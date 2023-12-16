use crate::admin::admin_server::DashboardServer;
use crate::api::{self, Api, ProxyServerConfig, QuicTunnelConfig};
use crate::http::http_proxy_handler::HttpProxyHandler;
use crate::proxy_handler::{OutboundType, ParseState, ProxyHandler};
use crate::proxy_rule_manager::MatchResult;
use crate::server_info_bridge::{
    ProxyTraffic, ServerInfo, ServerInfoBridge, ServerInfoType, ServerStats,
};
use crate::socks::socks_proxy_handler::SocksProxyHandler;
use crate::socks::SocksVersion;
use crate::{
    local_socket_addr_with_unspecified_port, utils, CommonQuicConfig, Config, Host, NetAddr,
    ProtoType, ProxyError, ProxyRuleManager, QuicClient, QuicClientConfig, QuicServer,
    QuicServerConfig,
};
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, error, info};
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rs_utilities::dns::{
    DNSQueryOrdering, DNSResolver, DNSResolverConfig, DNSResolverLookupIpStrategy, DNSResolverType,
};
use rs_utilities::log_and_bail;
use serde::Serialize;
use std::fmt::Display;
use std::net::SocketAddr;
use std::path::Path;
use std::str::{self, FromStr};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

const POST_TRAFFIC_DATA_INTERVAL_SECS: u64 = 10;
const TRAFFIC_DATA_QUEUE_SIZE: usize = 100;

#[derive(Clone, Serialize)]
pub enum ServerState {
    Idle = 0,
    Preparing,
    ResolvingDNS,
    Running,
    Terminated,
}

impl Display for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerState::Idle => write!(f, "Idle"),
            ServerState::Preparing => write!(f, "Preparing"),
            ServerState::ResolvingDNS => write!(f, "ResolvingDNS"),
            ServerState::Running => write!(f, "Running"),
            ServerState::Terminated => write!(f, "Terminated"),
        }
    }
}

struct ThreadSafeState {
    proxy_rule_manager: Option<ProxyRuleManager>,
    watcher: Option<Box<dyn Watcher + Send>>,
    scheduled_start: bool,
    on_info_report_enabled: bool,
    server_info_bridge: ServerInfoBridge,
    state: ServerState,
    quic_client: Option<Arc<QuicClient>>,
    dns_resolver: Option<Arc<DNSResolver>>,
    prefer_upstream: bool,
    // the following 3 fields are redundant, they exist in this struct because they can use updated
    upstream: Option<SocketAddr>,
    dot_server: Option<String>,
    name_servers: Option<String>,
    // stats
    total_rx_bytes: u64,
    total_tx_bytes: u64,
    total_connections: u32,
    ongoing_connections: u32,
}

impl ThreadSafeState {
    fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            proxy_rule_manager: None,
            watcher: None,
            scheduled_start: false,
            on_info_report_enabled: false,
            server_info_bridge: ServerInfoBridge::new(),
            state: ServerState::Idle,
            quic_client: None,
            dns_resolver: None,
            prefer_upstream: false,
            upstream: None,
            dot_server: None,
            name_servers: None,
            total_rx_bytes: 0,
            total_tx_bytes: 0,
            total_connections: 0,
            ongoing_connections: 0,
        }))
    }
}

macro_rules! inner_state {
    ($self:ident, $field:ident) => {
        (*$self.inner_state.lock().unwrap()).$field
    };
}

macro_rules! copy_inner_state {
    ($self:expr, $($field:ident),+ $(,)?) => {
        {
            let ref st = *$self.inner_state.lock().unwrap();
            ($(st.$field.clone(),)+)
        }
    };
}

pub struct Server {
    config: Config,
    common_quic_config: CommonQuicConfig,
    inner_state: Arc<Mutex<ThreadSafeState>>,
}

impl Server {
    pub fn new(config: Config, common_quic_config: CommonQuicConfig) -> Arc<Self> {
        Arc::new(Server {
            config,
            common_quic_config,
            inner_state: ThreadSafeState::new(),
        })
    }

    pub fn set_scheduled_start(self: &Arc<Self>) {
        inner_state!(self, scheduled_start) = true;
    }

    pub fn run(self: &mut Arc<Self>) -> Result<()> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(self.config.threads)
            .build()
            .unwrap()
            .block_on(async {
                self.run_internal()
                    .await
                    .context("")
                    .map_err(|_| std::process::exit(0))
            })
    }

    async fn run_internal(self: &mut Arc<Self>) -> Result<()> {
        self.set_and_post_server_state(ServerState::Preparing);

        // start the dashboard server
        let addr = local_socket_addr_with_unspecified_port(self.config.addr.is_ipv6());
        let dashboard_server = DashboardServer::new();
        let dashboard_listener = dashboard_server.bind(addr).await?;
        let dashboard_addr = dashboard_listener.local_addr().ok();
        dashboard_server
            .serve_async(dashboard_listener, self.clone())
            .await;

        let require_quic_server = self.config.is_layered_proto;
        let mut quic_client_join_handle = None;

        if let Some(upstream) = &self.config.upstream_addr {
            // connect to QUIC server if it is +quic protocols
            let require_quic_client = self.config.is_upstream_layered_proto;
            if require_quic_client {
                quic_client_join_handle = Some(
                    self.start_quic_client(upstream.clone(), self.common_quic_config.clone())
                        .await?,
                );
            } else {
                inner_state!(self, upstream) = upstream.to_socket_addr();
            }
        }

        let orig_server_addr = self.config.addr;
        let proxy_server_addr = if require_quic_server {
            local_socket_addr_with_unspecified_port(self.config.addr.is_ipv6())
        } else {
            orig_server_addr
        };

        // bind the proxy server first, it may be used as the upstream of the QUIC server
        let proxy_listener = self.bind(proxy_server_addr).await?;
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_server_handle = self.serve_async(proxy_listener, dashboard_addr);

        // join on the QUIC tunnel after the proxy server is started
        if let Some(quic_client_join_handle) = quic_client_join_handle {
            info!("join on the QUIC tunnel...",);
            quic_client_join_handle.await.ok();
            info!("QUIC tunnel quit");
        }

        if require_quic_server {
            let quic_server_config = QuicServerConfig {
                server_addr: orig_server_addr,
                upstream_addr: proxy_addr, // use proxy as the upstream of the QUIC tunnel
                common_cfg: self.common_quic_config.clone(),
            };
            let mut quic_server = QuicServer::new(quic_server_config);
            quic_server.bind().await?;
            quic_server.serve().await;
        }

        proxy_server_handle.await.context("failed on awating...")
    }

    async fn bind(self: &Arc<Self>, addr: SocketAddr) -> Result<TcpListener> {
        self.setup_proxy_rules_manager()?;

        let listener = TcpListener::bind(addr).await.map_err(|e| {
            error!("failed to bind proxy server on address: {addr}");
            e
        })?;

        let proxy_addr = listener.local_addr().unwrap();
        let server_type = self.server_type_as_string();

        info!("==========================================================");
        info!("proxy server bound to: {proxy_addr}, type: {server_type}");
        info!("==========================================================");

        self.post_server_info(ServerInfo::new(
            ServerInfoType::ProxyMessage,
            Box::new(format!(
                "Proxy server bound to: {proxy_addr}, type: {server_type}"
            )),
        ));

        Ok(listener)
    }

    async fn start_quic_client(
        &self,
        quic_server_addr: NetAddr,
        common_quic_config: CommonQuicConfig,
    ) -> Result<JoinHandle<()>> {
        // with +quic protocols, quic_client will be used to connect to the upstream
        let quic_client_config = QuicClientConfig {
            server_addr: quic_server_addr,
            local_access_server_addr: local_socket_addr_with_unspecified_port(
                self.config.addr.is_ipv6(),
            ),
            common_cfg: common_quic_config,
        };

        let mut client = QuicClient::new(quic_client_config);
        if inner_state!(self, on_info_report_enabled) {
            client.set_enable_on_info_report(true);
            let info_bridge = inner_state!(self, server_info_bridge).clone();
            client.set_on_info_listener(move |data: &str| {
                info_bridge.post_server_log(data);
            });
        }
        client.start_access_server().await?;

        let access_server_addr = client.access_server_addr();
        info!(
            "QUIC tunnel access server address: {:?}",
            access_server_addr
        );

        // will handover the handle to the caller, so we don't block here
        let join_handle = client.connect_and_serve_async();

        inner_state!(self, upstream) = access_server_addr;
        inner_state!(self, quic_client) = Some(Arc::new(client));

        Ok(join_handle)
    }

    fn serve_async(
        self: &Arc<Self>,
        proxy_listener: TcpListener,
        dashboard_addr: Option<SocketAddr>,
    ) -> JoinHandle<()> {
        let mut this = self.clone();
        tokio::spawn(async move { this.serve_internal(proxy_listener, dashboard_addr).await })
    }

    async fn serve_internal(
        self: &mut Arc<Self>,
        proxy_listener: TcpListener,
        dashboard_addr: Option<SocketAddr>,
    ) {
        self.set_and_post_server_state(ServerState::ResolvingDNS);

        let resolver = Self::create_dns_resolver(
            self.config.dot_server.as_str(),
            self.config.name_servers.as_str(),
        )
        .await;

        // always need a system resolver to resolve local domains
        let system_resolver = if resolver.resolver_type() == DNSResolverType::System {
            resolver.clone()
        } else {
            let dns_config = DNSResolverConfig {
                strategy: DNSResolverLookupIpStrategy::Ipv4thenIpv6,
                num_conccurent_reqs: 3,
                ordering: DNSQueryOrdering::QueryStatistics,
            };
            Arc::new(rs_utilities::dns::system_resolver(dns_config))
        };

        let resolver_type = resolver.resolver_type().to_string();
        inner_state!(self, dns_resolver) = Some(resolver);

        self.post_server_info(ServerInfo::new(
            ServerInfoType::ProxyDNSResolverType,
            Box::new(resolver_type),
        ));

        self.set_and_post_server_state(ServerState::Running);

        let (stats_sender, stats_receiver) = channel::<ServerStats>(TRAFFIC_DATA_QUEUE_SIZE);
        self.collect_and_report_server_stats(stats_receiver);

        info!(
            "proxy server started listening, addr: {}, type: {}",
            proxy_listener.local_addr().unwrap(),
            self.server_type_as_string()
        );

        let psp = Arc::new(ProxySupportParams {
            system_resolver,
            server_type: self.config.server_type.clone(),
            server_addr: self.config.addr.clone(),
            upstream_type: self.config.upstream_type.clone(),
            dashboard_addr,
            proxy_rule_manager: inner_state!(self, proxy_rule_manager).clone(),
            stats_sender,
        });

        loop {
            match proxy_listener.accept().await {
                Ok((inbound_stream, addr)) => {
                    let psp = psp.clone();
                    let (prefer_upstream, upstream, dns_resolver) =
                        copy_inner_state!(self, prefer_upstream, upstream, dns_resolver);
                    tokio::spawn(async move {
                        if let Some(ProtoType::Tcp) = psp.server_type {
                            if upstream.is_none() {
                                error!("tcp connection requires an upstream");
                                return;
                            }

                            match TcpStream::connect(upstream.unwrap()).await {
                                Ok(outbound_stream) => {
                                    Self::start_stream_transfer(
                                        inbound_stream,
                                        outbound_stream,
                                        &psp.stats_sender,
                                    )
                                    .await
                                    .ok();
                                }
                                Err(e) => {
                                    error!(
                                        "failed to connect to upstream: {}, err: {e}",
                                        upstream.unwrap()
                                    );
                                }
                            };

                            return;
                        }

                        Self::process_stream(
                            inbound_stream,
                            psp,
                            upstream,
                            prefer_upstream,
                            dns_resolver.unwrap(),
                        )
                        .await
                        .map_err(|e| match e {
                            ProxyError::BadRequest | ProxyError::BadGateway(_) => {
                                error!("{:?}", e);
                            }
                            _ => {}
                        })
                        .ok();

                        debug!("connection closed: {addr}");
                    });
                }

                Err(e) => {
                    error!("access server failed, err: {e}");
                }
            }
        }
    }

    async fn create_dns_resolver(dot_server: &str, name_servers: &str) -> Arc<DNSResolver> {
        Arc::new(
            rs_utilities::dns::resolver(
                dot_server,
                name_servers
                    .split(',')
                    .skip_while(|&x| x.is_empty())
                    .map(|e| e.trim().to_string())
                    .collect(),
            )
            .await,
        )
    }

    fn create_proxy_handler(
        server_type: &Option<ProtoType>,
        server_addr: SocketAddr,
        first_byte: u8,
    ) -> Box<dyn ProxyHandler + Send + Sync> {
        match server_type {
            Some(ProtoType::Socks5) => {
                Box::new(SocksProxyHandler::new(SocksVersion::V5, server_addr))
            }
            Some(ProtoType::Socks4) => {
                Box::new(SocksProxyHandler::new(SocksVersion::V4, server_addr))
            }
            Some(ProtoType::Http) => Box::new(HttpProxyHandler::new()),
            Some(ProtoType::Tcp) => unreachable!("not valid proxy type"),
            None => {
                match first_byte as char {
                    '\x05' => Box::new(SocksProxyHandler::new(SocksVersion::V5, server_addr)),
                    '\x04' => Box::new(SocksProxyHandler::new(SocksVersion::V4, server_addr)),
                    // default to HTTP
                    _ => Box::new(HttpProxyHandler::new()),
                }
            }
        }
    }

    pub fn has_scheduled_start(&self) -> bool {
        inner_state!(self, scheduled_start)
    }

    pub fn get_state(&self) -> ServerState {
        inner_state!(self, state).clone()
    }

    async fn process_stream(
        mut inbound_stream: TcpStream,
        params: Arc<ProxySupportParams>,
        upstream: Option<SocketAddr>,
        prefer_upstream: bool,
        resolver: Arc<DNSResolver>,
    ) -> Result<(), ProxyError> {
        // this buffer must be big enough to receive SOCKS request
        let mut buffer = [0u8; 512];
        let mut proxy_handler = None;
        loop {
            let nread = inbound_stream
                .read(&mut buffer)
                .await
                .context("failed to read from inbound_stream")
                .map_err(|_| ProxyError::BadRequest)?;

            if proxy_handler.is_none() {
                proxy_handler = Some(Self::create_proxy_handler(
                    &params.server_type,
                    params.server_addr,
                    buffer[0],
                ));
            }

            let proxy_handler = proxy_handler.as_mut().unwrap();

            let addr = match proxy_handler.parse(&buffer[..nread]) {
                ParseState::Pending => {
                    continue;
                }
                ParseState::ContinueWithReply(reply) => {
                    utils::write_to_stream(&mut inbound_stream, reply.as_ref()).await?;
                    continue;
                }
                ParseState::FailWithReply((reply, err)) => {
                    utils::write_to_stream(&mut inbound_stream, reply.as_ref()).await?;
                    return Err(err);
                }
                ParseState::ReceivedRequest(result) => result,
            };

            let mut outbound_type = OutboundType::Direct;
            let mut outbound_stream = None;

            if (addr.is_domain() && !addr.is_internal_domain())
                || (addr.is_ip() && !addr.is_internal_ip())
            {
                let match_result = if prefer_upstream {
                    MatchResult::Proxy
                } else {
                    match params.proxy_rule_manager.clone() {
                        Some(mut prm) if addr.is_domain() => {
                            prm.matches(addr.unwrap_domain(), addr.port)
                        }
                        _ => MatchResult::Direct,
                    }
                };

                match match_result {
                    MatchResult::Reject => {
                        let addr = addr.clone();
                        proxy_handler.reject(&mut inbound_stream).await?;
                        debug!("rejected: {addr}");
                        break;
                    }

                    MatchResult::Proxy if upstream.is_some() => {
                        outbound_type = match params.upstream_type.as_ref().unwrap() {
                            ProtoType::Http => OutboundType::HttpProxy,
                            ProtoType::Socks4 => OutboundType::SocksProxy(SocksVersion::V4),
                            ProtoType::Socks5 => OutboundType::SocksProxy(SocksVersion::V5),
                            ProtoType::Tcp => unreachable!("not valid proxy type"),
                        };

                        debug!(
                            "forward payload to next proxy({:?}), {addr} -> {:?}",
                            outbound_type, upstream
                        );

                        outbound_stream = match TcpStream::connect(upstream.unwrap()).await {
                            Ok(stream) => Some(stream),
                            Err(e) => {
                                error!(
                                    "failed to connect to upstream: {}, err: {e}",
                                    upstream.unwrap()
                                );
                                None
                            }
                        }
                    }

                    _ => {}
                }
            }

            if outbound_type == OutboundType::Direct {
                debug!("serve request directly: {addr}");
                outbound_stream = match &addr.host {
                    Host::Domain(domain) => {
                        let resolver = if addr.is_internal_domain() {
                            &params.system_resolver
                        } else {
                            &resolver
                        };

                        let ip_arr = resolver.lookup(domain.as_str()).await.map_err(|e| {
                            ProxyError::BadGateway(anyhow!("failed to resolve: {addr}, error: {e}"))
                        })?;

                        let mut outbound_stream = None;
                        for ip in ip_arr {
                            let resolved_ip = NetAddr::from_ip(ip, addr.port);
                            if resolved_ip.is_loopback()
                                && addr.port == inbound_stream.local_addr().unwrap().port()
                            {
                                outbound_stream = Self::connect_to_dashboard(
                                    params.dashboard_addr.clone(),
                                    &inbound_stream,
                                )
                                .await?;
                                break;
                            }

                            let stream =
                                Self::create_tcp_stream(SocketAddr::new(ip, addr.port)).await;
                            if stream.is_some() {
                                outbound_stream = stream;
                                break;
                            }
                        }

                        outbound_stream
                    }

                    Host::IP(ip) => {
                        let inbound_addr = inbound_stream.local_addr().unwrap();
                        if ip == &inbound_addr.ip() && addr.port == inbound_addr.port() {
                            Self::connect_to_dashboard(
                                params.dashboard_addr.clone(),
                                &inbound_stream,
                            )
                            .await?
                        } else {
                            Self::create_tcp_stream(addr.to_socket_addr().unwrap()).await
                        }
                    }
                };
            }

            match outbound_stream {
                Some(mut outbound_stream) => {
                    proxy_handler
                        .handle(outbound_type, &mut outbound_stream, &mut inbound_stream)
                        .await?;

                    Self::start_stream_transfer(
                        inbound_stream,
                        outbound_stream,
                        &params.stats_sender,
                    )
                    .await?;
                }

                None => {
                    proxy_handler
                        .handle_outbound_failure(&mut inbound_stream)
                        .await?;
                }
            }

            break;
        }
        Ok(())
    }

    async fn connect_to_dashboard(
        dashboard_addr: Option<SocketAddr>,
        inbound_stream: &TcpStream,
    ) -> Result<Option<TcpStream>, ProxyError> {
        match dashboard_addr {
            Some(addr) => {
                debug!("dashboard request: {}", inbound_stream.peer_addr().unwrap());
                Ok(Self::create_tcp_stream(addr.clone()).await)
            }
            None => {
                log::warn!(
                    "request routing to the proxy server itself is rejected: {}",
                    inbound_stream.peer_addr().unwrap()
                );
                return Err(ProxyError::BadRequest);
            }
        }
    }

    async fn create_tcp_stream(addr: SocketAddr) -> Option<TcpStream> {
        if addr.ip().is_unspecified() {
            error!("address is unspecified: {addr}");
            return None;
        }

        TcpStream::connect(addr)
            .await
            .map_err(|e| {
                error!("failed to connect to address: {addr}, err: {e}");
                e
            })
            .ok()
    }

    fn server_type_as_string(&self) -> String {
        match self.config.server_type {
            Some(ref server_type) => server_type.to_string(),
            None => "HTTP|SOCKS5|SOCKS4".to_string(),
        }
    }

    async fn start_stream_transfer(
        mut a_stream: TcpStream,
        mut b_stream: TcpStream,
        stats_sender: &Sender<ServerStats>,
    ) -> Result<ProxyTraffic, ProxyError> {
        stats_sender.send(ServerStats::NewConnection).await.ok();
        let result = match tokio::io::copy_bidirectional(&mut a_stream, &mut b_stream).await {
            Ok((tx_bytes, rx_bytes)) => {
                debug!(
                    "transfer, out:{tx_bytes}, in:{rx_bytes}, {:?} <-> {:?}",
                    a_stream.local_addr(),
                    b_stream.local_addr()
                );

                stats_sender
                    .send(ServerStats::Traffic(ProxyTraffic { tx_bytes, rx_bytes }))
                    .await
                    .ok();

                Ok(ProxyTraffic { rx_bytes, tx_bytes })
            }
            Err(e) => Err(ProxyError::Disconnected(anyhow!(e))),
        };

        stats_sender.send(ServerStats::CloseConnection).await.ok();
        result
    }

    fn collect_and_report_server_stats(&self, mut stats_receiver: Receiver<ServerStats>) {
        let inner_state = self.inner_state.clone();
        tokio::spawn(async move {
            let mut total_rx_bytes = 0;
            let mut total_tx_bytes = 0;
            let mut total_connections = 0;
            let mut ongoing_connections = 0;
            let mut last_elapsed_time = 0;
            let start_time = SystemTime::now();
            loop {
                match stats_receiver.recv().await {
                    Some(ServerStats::NewConnection) => {
                        ongoing_connections += 1;
                        total_connections += 1;
                    }

                    Some(ServerStats::CloseConnection) => {
                        ongoing_connections -= 1;
                    }

                    Some(ServerStats::Traffic(ProxyTraffic { rx_bytes, tx_bytes })) => {
                        total_rx_bytes += rx_bytes;
                        total_tx_bytes += tx_bytes;
                    }
                    None => break,
                }

                if let Ok(elpased) = start_time.elapsed() {
                    {
                        let mut st = inner_state.lock().unwrap();
                        st.total_rx_bytes = total_rx_bytes;
                        st.total_tx_bytes = total_tx_bytes;
                        st.total_connections = total_connections;
                        st.ongoing_connections = ongoing_connections;
                    }

                    // report traffic data every 10 seconds
                    let elapsed_time = elpased.as_secs();
                    if elapsed_time - last_elapsed_time > POST_TRAFFIC_DATA_INTERVAL_SECS {
                        last_elapsed_time = elapsed_time;
                        inner_state
                            .lock()
                            .unwrap()
                            .server_info_bridge
                            .post_server_info(&ServerInfo::new(
                                ServerInfoType::ProxyTraffic,
                                Box::new(ProxyTraffic {
                                    rx_bytes: total_rx_bytes,
                                    tx_bytes: total_tx_bytes,
                                }),
                            ));
                    }
                }
            }
            info!("quit collecting traffic data");
        });
    }

    fn setup_proxy_rules_manager(self: &Arc<Self>) -> Result<()> {
        let proxy_rules_file = &self.config.proxy_rules_file;
        if !proxy_rules_file.is_empty() && !Path::new(proxy_rules_file).is_file() {
            log_and_bail!("proxy rules file does not exist: {proxy_rules_file}");
        }

        if !proxy_rules_file.is_empty() {
            let mut prm = ProxyRuleManager::default();
            let count = prm.add_rules_by_file(proxy_rules_file);

            info!("{count} proxy rules added with file: {proxy_rules_file}");
            inner_state!(self, proxy_rule_manager) = Some(prm);

            if self.config.watch_proxy_rules_change {
                info!("will watch proxy rules change");
                self.watch_proxy_rules_file(proxy_rules_file.to_string())
                    .ok();
            }
        }

        Ok(())
    }

    fn watch_proxy_rules_file(self: &Arc<Self>, proxy_rules_file: String) -> Result<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                tx.send(res).ok();
            },
            notify::Config::default(),
        )?;

        watcher.watch(
            Path::new(proxy_rules_file.as_str()),
            RecursiveMode::NonRecursive,
        )?;

        inner_state!(self, watcher) = Some(Box::new(watcher));

        let mut prm = inner_state!(self, proxy_rule_manager).clone().unwrap();
        std::thread::spawn(move || {
            loop {
                match rx.recv() {
                    Ok(Ok(Event {
                        kind: EventKind::Modify(ModifyKind::Data(_)),
                        ..
                    })) => {
                        // TODO schedule timer task to refresh the rules at low frequency
                        prm.clear_all();
                        let count = prm.add_rules_by_file(proxy_rules_file.as_str());

                        info!(
                            "updated proxy rules from file: {proxy_rules_file}, rules updated: {count}"
                        );
                    }
                    Ok(Ok(_)) | Ok(Err(_)) => {
                        // do nothing
                    }
                    Err(_) => {
                        info!("quit loop for watching the proxy rules file");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    fn set_and_post_server_state(self: &Arc<Self>, state: ServerState) {
        info!("client state: {state}");
        inner_state!(self, state) = state.clone();
        self.post_server_info(ServerInfo::new(
            ServerInfoType::ProxyServerState,
            Box::new(state.to_string()),
        ));
    }

    fn post_server_info<T>(self: &Arc<Self>, server_info: ServerInfo<T>)
    where
        T: ?Sized + Serialize,
    {
        if inner_state!(self, on_info_report_enabled) {
            inner_state!(self, server_info_bridge).post_server_info(&server_info);
        }
    }

    pub fn set_on_info_listener(
        self: &Arc<Self>,
        callback: impl FnMut(&str) + 'static + Send + Sync,
    ) {
        inner_state!(self, server_info_bridge).set_listener(callback);
    }

    pub fn has_on_info_listener(self: &Arc<Self>) -> bool {
        inner_state!(self, server_info_bridge).has_listener()
    }

    pub fn set_enable_on_info_report(self: &Arc<Self>, enable: bool) {
        info!("set_enable_on_info_report, enable: {enable}");
        inner_state!(self, on_info_report_enabled) = enable
    }
}

#[async_trait::async_trait]
impl Api for Server {
    fn set_prefer_upstream(&self, flag: bool) {
        info!("set_prefer_upstream, prefer_upstream: {flag}");
        inner_state!(self, prefer_upstream) = flag
    }

    fn get_server_state(&self) -> api::ServerState {
        let tunnel_state = match inner_state!(self, quic_client).as_ref() {
            Some(qc) => qc.get_state().to_string(),
            None => "NotConnected".to_string(),
        };

        api::ServerState {
            prefer_upstream: inner_state!(self, prefer_upstream),
            tunnel_state,
        }
    }

    fn get_proxy_server_config(&self) -> ProxyServerConfig {
        let cfg = &self.config;

        let (dot_server, name_servers) = copy_inner_state!(self, dot_server, name_servers);

        if dot_server.is_some() || name_servers.is_some() {
            ProxyServerConfig {
                server_addr: cfg.server_addr_as_string(),
                dot_server: dot_server.unwrap_or("".to_string()),
                name_servers: name_servers.unwrap_or("".to_string()),
            }
        } else {
            ProxyServerConfig {
                server_addr: cfg.server_addr_as_string(),
                dot_server: cfg.dot_server.clone(),
                name_servers: cfg.name_servers.clone(),
            }
        }
    }

    fn get_quic_tunnel_config(&self) -> QuicTunnelConfig {
        let quic_server_addr = match inner_state!(self, quic_client) {
            Some(ref qc) => qc.get_server_addr(),
            None => "".to_string(),
        };

        let cfg = &self.common_quic_config;
        QuicTunnelConfig {
            upstream_addr: quic_server_addr,
            cert: cfg.cert.clone(),
            cipher: cfg.cipher.clone(),
            password: cfg.password.clone(),
            idle_timeout: cfg.max_idle_timeout_ms,
            retry_interval: cfg.retry_interval_ms,
        }
    }

    fn get_server_stats(&self) -> api::ServerStats {
        let (total_rx_bytes, total_tx_bytes, ongoing_connections, total_connections) = copy_inner_state!(
            self,
            total_rx_bytes,
            total_tx_bytes,
            ongoing_connections,
            total_connections
        );
        api::ServerStats {
            total_rx_bytes,
            total_tx_bytes,
            ongoing_connections,
            total_connections,
        }
    }

    async fn update_proxy_server_config(&self, config: ProxyServerConfig) -> Result<()> {
        inner_state!(self, dns_resolver) = Some(
            Self::create_dns_resolver(config.dot_server.as_str(), config.name_servers.as_str())
                .await,
        );

        info!(
            "dns resolver updated, dot_server: [{}], name_servers: [{}]",
            config.dot_server, config.name_servers
        );

        inner_state!(self, dot_server) = Some(config.dot_server);
        inner_state!(self, name_servers) = Some(config.name_servers);
        Ok(())
    }

    async fn update_quic_tunnel_config(&self, config: QuicTunnelConfig) -> Result<()> {
        if let Some(ref qc) = inner_state!(self, quic_client) {
            qc.stop().ok();
        }

        let mut base_common_quic_config = self.common_quic_config.clone();
        base_common_quic_config.cert = config.cert;
        base_common_quic_config.cipher = config.cipher;
        base_common_quic_config.password = config.password;
        base_common_quic_config.max_idle_timeout_ms = config.idle_timeout;
        base_common_quic_config.retry_interval_ms = config.retry_interval;
        let upstream_addr = NetAddr::from_str(config.upstream_addr.as_str())?;
        let quic_client_join_handle = self
            .start_quic_client(upstream_addr, base_common_quic_config)
            .await;

        tokio::spawn(async move { quic_client_join_handle.unwrap().await });

        Ok(())
    }
}

struct ProxySupportParams {
    system_resolver: Arc<DNSResolver>,
    server_type: Option<ProtoType>,
    server_addr: SocketAddr,
    upstream_type: Option<ProtoType>,
    dashboard_addr: Option<SocketAddr>,
    proxy_rule_manager: Option<ProxyRuleManager>,
    stats_sender: Sender<ServerStats>,
}
