use crate::api::Api;
use crate::http::http_proxy_handler::HttpProxyHandler;
use crate::proxy_handler::{OutboundType, ParseState, ProxyHandler};
use crate::server_info_bridge::{ProxyTraffic, ServerInfo, ServerInfoBridge, ServerInfoType};
use crate::socks::socks_proxy_handler::SocksProxyHandler;
use crate::socks::SocksVersion;
use crate::{
    utils, CommonQuicConfig, Config, Host, ProtoType, ProxyError, ProxyRuleManager, QuicClient,
    QuicClientConfig, QuicServer, QuicServerConfig,
};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::TryFutureExt;
use log::{debug, error, info};
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rs_utilities::dns::{DNSResolver, DNSResolverType};
use rs_utilities::log_and_bail;
use serde::Serialize;
use std::borrow::BorrowMut;
use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use tokio::sync::mpsc::{channel, Receiver, Sender};
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
    proxy_rule_manager: Option<Arc<RwLock<ProxyRuleManager>>>,
    watcher: Option<Box<dyn Watcher + Send>>,
    scheduled_start: bool,
    on_info_report_enabled: bool,
    prefer_upstream: bool,
    server_info_bridge: ServerInfoBridge,
    state: ServerState,
}

impl ThreadSafeState {
    fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            proxy_rule_manager: None,
            watcher: None,
            scheduled_start: false,
            on_info_report_enabled: false,
            prefer_upstream: false,
            server_info_bridge: ServerInfoBridge::new(),
            state: ServerState::Idle,
        }))
    }
}

macro_rules! inner_state {
    ($self:ident, $field:ident) => {
        (*$self.inner_state.lock().unwrap()).$field
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
                self.set_and_post_server_state(ServerState::Preparing);

                let require_quic_server = self.config.is_layered_proto;
                let require_quic_client = self.config.is_upstream_layered_proto;
                let mut quic_client = None;
                let proxy_upstream_addr;

                if require_quic_client {
                    // with +quic protocols, quic_client will be used to connect to the upstream
                    let quic_client_config = QuicClientConfig {
                        server_addr: self.config.upstream_addr.clone().unwrap(),
                        local_access_server_addr:
                            crate::local_ipv4_socket_addr_with_unspecified_port(),
                        common_cfg: self.common_quic_config.clone(),
                    };

                    let mut client = QuicClient::new(quic_client_config);
                    let proxy_server = self.clone();

                    client.set_enable_on_info_report(true);
                    client.set_on_info_listener(move |data: &str| {
                        proxy_server.post_server_log(data);
                    });

                    client.start_access_server().await?;
                    // make QUIC tunnel as the upstream of the proxy_server
                    proxy_upstream_addr = client.access_server_addr();
                    quic_client = Some(client);

                    #[cfg(target_os = "android")]
                    {
                        self.post_server_info(ServerInfo::new(
                            ServerInfoType::ProxyMessage,
                            Box::new(format!(
                                "Tunnel access server bound to: {}",
                                proxy_upstream_addr.unwrap()
                            )),
                        ));
                    }
                } else {
                    proxy_upstream_addr = match &self.config.upstream_addr {
                        Some(upstream) => upstream.to_socket_addr(),
                        None => None,
                    };
                }

                let orig_server_addr = self.config.addr;
                let proxy_server_addr = if require_quic_server {
                    crate::local_ipv4_socket_addr_with_unspecified_port()
                } else {
                    orig_server_addr
                };

                let proxy_listener = self.bind(proxy_server_addr).await?;
                let proxy_addr = proxy_listener.local_addr().unwrap();

                if require_quic_server || require_quic_client {
                    self.serve_async(proxy_listener, proxy_upstream_addr).await;

                    if let Some(mut qc) = quic_client {
                        qc.connect_and_serve().await;
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
                } else {
                    self.serve(proxy_listener, proxy_upstream_addr).await;
                }

                Ok::<(), anyhow::Error>(())
            })
    }

    async fn bind(self: &Arc<Self>, addr: SocketAddr) -> Result<TcpListener> {
        self.setup_proxy_rules_manager()?;

        let listener = TcpListener::bind(addr).await.map_err(|e| {
            error!("failed to bind proxy server on address: {}", addr);
            e
        })?;

        let proxy_addr = listener.local_addr().unwrap();
        let server_type = self.server_type_as_string();

        info!("==========================================================");
        info!(
            "proxy server bound to: {}, type: {}",
            proxy_addr, server_type
        );
        info!("==========================================================");

        self.post_server_info(ServerInfo::new(
            ServerInfoType::ProxyMessage,
            Box::new(format!(
                "Proxy server bound to: {}, type: {}",
                proxy_addr, server_type
            )),
        ));

        Ok(listener)
    }

    async fn serve_async(
        self: &Arc<Self>,
        proxy_listener: TcpListener,
        upstream_addr: Option<SocketAddr>,
    ) {
        let mut this = self.clone();
        tokio::spawn(async move { this.serve(proxy_listener, upstream_addr).await });
    }

    async fn serve(
        self: &mut Arc<Self>,
        proxy_listener: TcpListener,
        upstream_addr: Option<SocketAddr>,
    ) {
        self.set_and_post_server_state(ServerState::ResolvingDNS);

        let resolver = Arc::new(
            rs_utilities::dns::resolver(
                self.config.dot_server.as_str(),
                self.config
                    .name_servers
                    .split(',')
                    .skip_while(|&x| x.is_empty())
                    .map(|e| e.trim().to_string())
                    .collect(),
            )
            .await,
        );

        // always need a system resolver to resolve local domains
        let system_resolver = if resolver.resolver_type() == DNSResolverType::System {
            resolver.clone()
        } else {
            Arc::new(rs_utilities::dns::system_resolver(
                3,
                rs_utilities::dns::DNSQueryOrdering::UserProvidedOrder,
            ))
        };

        self.post_server_info(ServerInfo::new(
            ServerInfoType::ProxyDNSResolverType,
            Box::new(resolver.resolver_type().to_string()),
        ));

        self.set_and_post_server_state(ServerState::Running);

        let (traffic_data_sender, traffic_data_receiver) =
            channel::<ProxyTraffic>(TRAFFIC_DATA_QUEUE_SIZE);
        self.collect_and_report_traffic_data(traffic_data_receiver);

        info!(
            "proxy server started listening, addr: {}, type: {}",
            proxy_listener.local_addr().unwrap(),
            self.server_type_as_string()
        );

        let psp = Arc::new(ProxySupportParams {
            resolver,
            system_resolver,
            server_type: self.config.server_type.clone(),
            server_addr: self.config.addr.clone(),
            upstream_type: self.config.upstream_type.clone(),
            upstream_addr,
            proxy_rule_manager: inner_state!(self, proxy_rule_manager).clone(),
            traffic_data_sender,
            api: self.clone(),
        });

        loop {
            match proxy_listener.accept().await {
                Ok((inbound_stream, addr)) => {
                    let psp = psp.clone();
                    let prefer_upstream = inner_state!(self, prefer_upstream).clone();
                    tokio::spawn(async move {
                        Self::process_stream(inbound_stream, psp, prefer_upstream)
                            .await
                            .map_err(|e| match e {
                                ProxyError::BadRequest | ProxyError::BadGateway(_) => {
                                    error!("{:?}", e);
                                }
                                _ => {}
                            })
                            .ok();
                        debug!("connection closed: {}", addr);
                    });
                }

                Err(e) => {
                    error!("access server failed, err: {}", e);
                }
            }
        }
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
        prefer_upstream: bool,
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

            if params.upstream_addr.is_some()
                && ((addr.is_domain() && !addr.is_internal_domain())
                    || (addr.is_ip() && !addr.is_internal_ip()))
            {
                if prefer_upstream
                    || params.proxy_rule_manager.is_none()
                    || (addr.is_domain()
                        && Self::matches_proxy_rule(
                            params.proxy_rule_manager.as_ref().unwrap(),
                            addr.unwrap_domain(),
                            addr.port,
                        ))
                {
                    outbound_type = match params.upstream_type.as_ref().unwrap() {
                        ProtoType::Http => OutboundType::HttpProxy,
                        ProtoType::Socks4 => OutboundType::SocksProxy(SocksVersion::V4),
                        ProtoType::Socks5 => OutboundType::SocksProxy(SocksVersion::V5),
                    };

                    debug!(
                        "forward payload to next proxy({:?}), {} -> {:?}",
                        outbound_type, addr, params.upstream_addr
                    );

                    outbound_stream = match TcpStream::connect(params.upstream_addr.unwrap()).await
                    {
                        Ok(stream) => Some(stream),
                        Err(e) => {
                            error!(
                                "failed to connect to upstream: {}, err:{}",
                                params.upstream_addr.unwrap(),
                                e
                            );
                            None
                        }
                    }
                }
            }

            if outbound_type == OutboundType::Direct {
                debug!("serve request directly: {}", addr);
                outbound_stream = match &addr.host {
                    Host::Domain(domain) => {
                        let resolver = if addr.is_internal_domain() {
                            &params.system_resolver
                        } else {
                            &params.resolver
                        };

                        let ip_arr = resolver.lookup(domain.as_str()).await.map_err(|e| {
                            ProxyError::BadGateway(anyhow!(
                                "failed to resolve: {}, error: {}",
                                addr,
                                e
                            ))
                        })?;

                        let mut outbound_stream = None;
                        for ip in ip_arr {
                            let stream = Self::create_tcp_stream(ip, addr.port).await;
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
                            log::warn!(
                                "request routing to the proxy server itself is rejected: {}",
                                inbound_stream.peer_addr().unwrap()
                            );
                            return Err(ProxyError::BadRequest);
                        }
                        Self::create_tcp_stream(*ip, addr.port).await
                    }
                };
            }

            match outbound_stream {
                Some(ref mut outbound_stream) => {
                    proxy_handler
                        .handle(outbound_type, outbound_stream, &mut inbound_stream)
                        .await?;

                    Self::start_stream_transfer(
                        &mut inbound_stream,
                        outbound_stream,
                        &params.traffic_data_sender,
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

    async fn create_tcp_stream(ip: IpAddr, port: u16) -> Option<TcpStream> {
        if ip.is_unspecified() {
            return None;
        }

        TcpStream::connect(SocketAddr::new(ip, port))
            .await
            .map_err(|e| {
                error!("failed to connect to address: {}:{}, err:{}", ip, port, e);
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

    fn matches_proxy_rule(
        mut proxy_rule_manager: &Arc<RwLock<ProxyRuleManager>>,
        domain: &str,
        port: u16,
    ) -> bool {
        let result = proxy_rule_manager.read().unwrap().matches(domain, port);
        if result.needs_sort_rules {
            proxy_rule_manager
                .borrow_mut()
                .write()
                .unwrap()
                .sort_rules();
        }

        result.matched
    }

    async fn start_stream_transfer(
        a_stream: &mut TcpStream,
        b_stream: &mut TcpStream,
        traffic_data_sender: &Sender<ProxyTraffic>,
    ) -> Result<ProxyTraffic, ProxyError> {
        let (tx_bytes, rx_bytes) = tokio::io::copy_bidirectional(a_stream, b_stream)
            .map_err(|e| ProxyError::Disconnected(anyhow!(e)))
            .await?;

        debug!(
            "transfer, out:{}, in:{}, {:?} <-> {:?}",
            tx_bytes,
            rx_bytes,
            a_stream.local_addr(),
            b_stream.local_addr()
        );

        traffic_data_sender
            .send(ProxyTraffic { tx_bytes, rx_bytes })
            .await
            .ok();

        Ok(ProxyTraffic { rx_bytes, tx_bytes })
    }

    fn collect_and_report_traffic_data(&self, mut traffic_data_receiver: Receiver<ProxyTraffic>) {
        let inner_state = self.inner_state.clone();
        tokio::spawn(async move {
            let mut total_rx_bytes = 0;
            let mut total_tx_bytes = 0;
            let mut last_elapsed_time = 0;
            let start_time = SystemTime::now();
            while let Some(ProxyTraffic { rx_bytes, tx_bytes }) = traffic_data_receiver.recv().await
            {
                total_rx_bytes += rx_bytes;
                total_tx_bytes += tx_bytes;

                if let Ok(elpased) = start_time.elapsed() {
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
            log_and_bail!("proxy rules file does not exist: {}", proxy_rules_file);
        }

        if !proxy_rules_file.is_empty() {
            if self.config.upstream_addr.is_none() {
                log::warn!("no upstream specified, proxy rules ignored.");
                return Ok(());
            }

            let mut prm = ProxyRuleManager::default();
            let count = prm.add_rules_by_file(proxy_rules_file);

            info!(
                "{} proxy rules added with file: {}",
                count, proxy_rules_file
            );

            inner_state!(self, proxy_rule_manager) = Some(Arc::new(RwLock::new(prm)));

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

        let prm = inner_state!(self, proxy_rule_manager).clone().unwrap();
        std::thread::spawn(move || {
            loop {
                match rx.recv() {
                    Ok(Ok(Event {
                        kind: EventKind::Modify(ModifyKind::Data(_)),
                        ..
                    })) => {
                        // TODO schedule timer task to refresh the rules at low frequency
                        let mut prm = prm.write().unwrap();
                        prm.clear_all();
                        let count = prm.add_rules_by_file(proxy_rules_file.as_str());

                        info!(
                            "updated proxy rules from file: {}, rules updated: {}",
                            proxy_rules_file, count
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
        info!("client state: {}", state);
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

    fn post_server_log(self: &Arc<Self>, message: &str) {
        if inner_state!(self, on_info_report_enabled) {
            inner_state!(self, server_info_bridge).post_server_log(message)
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
        info!("set_enable_on_info_report, enable:{}", enable);
        inner_state!(self, on_info_report_enabled) = enable
    }
}

impl Api for Server {
    fn set_prefer_upstream(&self, flag: bool) {
        info!("set_prefer_upstream, prefer_upstream:{}", flag);
        inner_state!(self, prefer_upstream) = flag
    }

    fn is_prefer_upstream(&self) -> bool {
        inner_state!(self, prefer_upstream)
    }
}

struct ProxySupportParams {
    resolver: Arc<DNSResolver>,
    system_resolver: Arc<DNSResolver>,
    server_type: Option<ProtoType>,
    server_addr: SocketAddr,
    upstream_type: Option<ProtoType>,
    upstream_addr: Option<SocketAddr>,
    proxy_rule_manager: Option<Arc<RwLock<ProxyRuleManager>>>,
    traffic_data_sender: Sender<ProxyTraffic>,
    api: Arc<dyn Api>,
}
