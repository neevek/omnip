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
use crate::udp::udp_server::UdpServer;
use crate::{
    local_socket_addr, utils, CommonQuicConfig, Config, Host, NetAddr, ProtoType, ProxyError,
    ProxyRuleManager, QuicClient, QuicClientConfig, QuicServer, QuicServerConfig, BUFFER_POOL,
};
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, error, info, warn};
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
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::error::Elapsed;

use tokio::{
    io::AsyncReadExt,
    io::AsyncWriteExt,
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
    system_dns_resolver: Option<Arc<DNSResolver>>,
    dns_resolver: Option<Arc<DNSResolver>>,
    prefer_upstream: bool,
    // the following 3 fields are redundant, they exist in this struct because they can use updated
    tcp_upstream: Option<SocketAddr>,
    udp_upstream: Option<SocketAddr>,
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
            system_dns_resolver: None,
            dns_resolver: None,
            prefer_upstream: false,
            tcp_upstream: None,
            udp_upstream: None,
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
            let st = &(*$self.inner_state.lock().unwrap());
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
            .worker_threads(self.config.workers)
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
        let cfg = &self.config;
        info!(
            "tcp_nodelay:{}, workers:{}",
            cfg.tcp_nodelay, self.config.workers
        );
        self.set_and_post_server_state(ServerState::Preparing);

        // start the dashboard server
        let is_ipv6 = cfg.server_addr.net_addr.is_ipv6();
        let addr = local_socket_addr(is_ipv6);
        let dashboard_server = DashboardServer::new();
        let dashboard_listener = dashboard_server.bind(addr).await?;
        let dashboard_addr = dashboard_listener.local_addr().ok();
        dashboard_server
            .serve_async(dashboard_listener, self.clone())
            .await;

        let server_proto = cfg.server_addr.proto.clone();
        let is_tcp_or_udp_proto = server_proto
            .clone()
            .map_or(false, |p| p == ProtoType::Tcp || p == ProtoType::Udp);

        let mut quic_client_join_handle = None;
        if let Some(upstream_addr) = &cfg.upstream_addr {
            // connect to QUIC server if it is +quic protocols
            let require_quic_client = upstream_addr.is_quic_proto;
            if require_quic_client {
                // connecting to quic server, and it will set relevant upstream address
                let join_handle = self
                    .start_quic_client(
                        upstream_addr.net_addr.clone(),
                        self.common_quic_config.clone(),
                    )
                    .await?;

                if is_tcp_or_udp_proto {
                    info!(
                        "start serving {} through quic client",
                        server_proto.unwrap().format_as_string(false)
                    );
                    join_handle.await.ok();
                    // directly use the quic client's tcp server or udp server, and return early
                    return Ok(());
                }

                // self.tcp_upstream or self.udp_upstream is set accordingly when reaching here
                quic_client_join_handle = Some(join_handle);
            } else if upstream_addr.proto == Some(ProtoType::Udp) {
                // non-quic upstream can only use IP address instead of domain
                inner_state!(self, udp_upstream) = upstream_addr.net_addr.to_socket_addr();
            } else {
                // non-quic upstream can only use IP address instead of domain
                inner_state!(self, tcp_upstream) = upstream_addr.net_addr.to_socket_addr();
            }
        }

        let is_udp_proto = server_proto == Some(ProtoType::Udp);
        let orig_server_addr = cfg.server_addr.net_addr.to_socket_addr().unwrap();
        let require_quic_server = cfg.server_addr.is_quic_proto;

        // if is_udp_proto && !require_quic_server {
        //     self.bind_udp_server(orig_server_addr, true).await?;
        //     return Ok(());
        // }

        // if is_tcp_or_udp_proto {
        //     // we need to start the tcp or udp server
        //     if let Some(ProtoType::Udp) = cfg.server_addr.proto {
        //         if !require_quic_server {
        //             let udp_server = self.bind_udp_server(proxy_server_addr, true).await?;
        //         }
        //     } else {
        //     }
        // }

        // // let (require_tcp, require_udp) = self.is_tcp_or_udp_server_required();
        // let udp_server_addr = if let Some(ProtoType::Udp) = cfg.server_addr.proto {
        //     let udp_server = self.bind_udp_server(proxy_server_addr, true).await?;
        //     udp_server.local_addr().ok()
        // } else {
        //     inner_state!(self, udp_upstream)
        // };

        let (proxy_tcp_server_handle, quic_server_tcp_upstream, quic_server_udp_upstream) =
            if !is_udp_proto {
                let tcp_server_addr = if require_quic_server {
                    local_socket_addr(is_ipv6)
                } else {
                    orig_server_addr
                };

                // bind the proxy server first, it may be used as the upstream of the QUIC server
                let tcp_listener = self.bind_tcp_server(tcp_server_addr).await?;

                let tcp_upstream = if require_quic_server {
                    // the tcp server can be sitting in front of the quic client or
                    // back of the quic server, always use the tcp server as the upstream
                    // of the quic server
                    tcp_listener.local_addr().ok()
                } else {
                    None
                };

                let server_handle = self.serve(tcp_listener, dashboard_addr);
                (Some(server_handle), tcp_upstream, None)
            } else {
                if !require_quic_server {
                    self.bind_udp_server(orig_server_addr, true).await?;
                    return Ok(());
                }

                // for +quic udp server, udp_upstream is required, so we can use it directly
                (None, None, inner_state!(self, udp_upstream))
            };

        // join on the QUIC tunnel after the proxy server is started
        if let Some(quic_client_join_handle) = quic_client_join_handle {
            info!("join on the quic tunnel...",);
            quic_client_join_handle.await.ok();
            info!("quic tunnel quit");
        } else if require_quic_server {
            let quic_server_config = QuicServerConfig {
                server_addr: orig_server_addr,
                tcp_upstream: quic_server_tcp_upstream,
                udp_upstream: quic_server_udp_upstream,
                common_cfg: self.common_quic_config.clone(),
            };
            let mut quic_server = QuicServer::new(quic_server_config);
            quic_server.bind()?;
            quic_server.serve().await;
        }

        if let Some(proxy_tcp_server_handle) = proxy_tcp_server_handle {
            proxy_tcp_server_handle
                .await
                .context("failed on awating...")
        } else {
            Ok(())
        }
    }

    async fn bind_tcp_server(self: &Arc<Self>, addr: SocketAddr) -> Result<TcpListener> {
        self.setup_proxy_rules_manager()?;

        let listener = TcpListener::bind(addr).await.map_err(|e| {
            error!("failed to bind proxy server on address: {addr}");
            e
        })?;

        let tcp_server_addr = listener.local_addr().unwrap();
        let proto = self.proto_as_string();

        info!("==========================================================");
        info!("tcp server bound to: {tcp_server_addr}, type: {proto}");
        info!("==========================================================");

        self.post_server_info(ServerInfo::new(
            ServerInfoType::ProxyMessage,
            Box::new(format!(
                "tcp server bound to: {tcp_server_addr}, type: {proto}"
            )),
        ));

        Ok(listener)
    }

    async fn bind_udp_server(
        self: &Arc<Self>,
        addr: SocketAddr,
        use_sync: bool,
    ) -> Result<UdpServer> {
        let upstream_addr = inner_state!(self, udp_upstream).unwrap();
        let udp_server = UdpServer::bind_and_start(addr, upstream_addr, use_sync).await?;

        let udp_server_addr = udp_server.local_addr().unwrap();
        inner_state!(self, udp_upstream) = Some(udp_server_addr);
        let proto = self.proto_as_string();

        info!("==========================================================");
        info!("udp server bound to: {udp_server_addr}, type: {proto}");
        info!("==========================================================");

        self.post_server_info(ServerInfo::new(
            ServerInfoType::ProxyMessage,
            Box::new(format!(
                "udp server bound to: {udp_server_addr}, type: {proto}"
            )),
        ));

        Ok(udp_server)
    }

    async fn start_quic_client(
        &self,
        quic_server_addr: NetAddr,
        common_quic_config: CommonQuicConfig,
    ) -> Result<JoinHandle<()>> {
        // if we have to forward tcp/udp through quic tunnel, we can directly use the
        // quic client's tcp/udp entry without creating another layer of traffic relay
        let cfg = &self.config;
        let server_addr = &cfg.server_addr;
        let (tcp_server_addr, udp_server_addr) = if server_addr.proto == Some(ProtoType::Udp) {
            (None, server_addr.net_addr.to_socket_addr())
        } else if server_addr.proto == Some(ProtoType::Tcp) {
            (server_addr.net_addr.to_socket_addr(), None)
        } else {
            (
                Some(local_socket_addr(server_addr.net_addr.is_ipv6())),
                None,
            )
        };

        #[allow(warnings)]
        let dot_servers = cfg.dot_server.split(',').map(String::from).collect();
        let name_servers = cfg.name_servers.split(',').map(String::from).collect();

        // with +quic protocols, quic_client will be used to connect to the upstream
        let quic_client_config = QuicClientConfig {
            server_addr: quic_server_addr,
            local_tcp_server_addr: tcp_server_addr,
            local_udp_server_addr: udp_server_addr,
            common_cfg: common_quic_config,
            dot_servers,
            name_servers,
        };

        let mut client = QuicClient::new(quic_client_config);
        if inner_state!(self, on_info_report_enabled) {
            client.set_enable_on_info_report(true);
            let info_bridge = inner_state!(self, server_info_bridge).clone();
            client.set_on_info_listener(move |data: &str| {
                info_bridge.post_server_log(data);
            });
        }

        let (require_tcp, require_udp) = self.is_tcp_or_udp_server_required();

        if require_tcp {
            let tcp_server_addr = client.start_tcp_server().await?;
            inner_state!(self, tcp_upstream) = Some(tcp_server_addr);
            info!("started quic tcp server: {tcp_server_addr}");
        }

        if require_udp {
            let udp_server_addr = client.start_udp_server().await?;
            inner_state!(self, udp_upstream) = Some(udp_server_addr);
            info!("started quic udp server: {udp_server_addr}");
        }

        // will handover the handle to the caller, so we don't block here
        let join_handle = client.connect_and_serve_async();

        inner_state!(self, quic_client) = Some(Arc::new(client));

        Ok(join_handle)
    }

    fn is_tcp_or_udp_server_required(&self) -> (bool, bool) {
        self.config
            .server_addr
            .proto
            .as_ref()
            .map_or((true, false), |p| {
                (*p != ProtoType::Udp, *p == ProtoType::Udp)
            })
    }

    async fn init_resolver(self: &mut Arc<Self>) {
        self.set_and_post_server_state(ServerState::ResolvingDNS);

        let cfg = &self.config;
        let resolver =
            Self::create_dns_resolver(cfg.dot_server.as_str(), cfg.name_servers.as_str()).await;

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
        inner_state!(self, system_dns_resolver) = Some(system_resolver);

        self.post_server_info(ServerInfo::new(
            ServerInfoType::ProxyDNSResolverType,
            Box::new(resolver_type),
        ));
    }

    fn serve(
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
        self.init_resolver().await;
        self.set_and_post_server_state(ServerState::Running);

        let (stats_sender, stats_receiver) = channel::<ServerStats>(TRAFFIC_DATA_QUEUE_SIZE);
        self.collect_and_report_server_stats(stats_receiver);

        info!(
            "proxy server started listening, addr: {}, type: {}",
            proxy_listener.local_addr().unwrap(),
            self.proto_as_string()
        );

        let cfg = &self.config;
        let psp = Arc::new(ProxySupportParams {
            proto: cfg.server_addr.proto.clone(),
            server_addr: cfg.server_addr.net_addr.to_socket_addr().unwrap(),
            upstream_type: cfg.upstream_addr.as_ref().and_then(|u| u.proto.clone()),
            dashboard_addr,
            proxy_rule_manager: inner_state!(self, proxy_rule_manager).clone(),
            stats_sender,
            tcp_nodelay: cfg.tcp_nodelay,
        });

        // if let Some(p) = cfg.server_addr.proto {
        //     if p.is_udp_supported() {
        //         let addr = cfg.upstream_udp.unwrap_or(cfg.upstream_addr);
        //         let udp_server = UdpServer::bind_and_start(cfg.addr, upstream_addr, false).await;
        //     }
        // }

        loop {
            match proxy_listener.accept().await {
                Ok((inbound_stream, _addr)) => {
                    let psp = psp.clone();
                    let (prefer_upstream, upstream, dns_resolver, system_dns_resolver) = copy_inner_state!(
                        self,
                        prefer_upstream,
                        tcp_upstream,
                        dns_resolver,
                        system_dns_resolver
                    );
                    if psp.tcp_nodelay {
                        inbound_stream
                            .set_nodelay(true)
                            .map_err(|e| error!("failed to call set_nodelay: {e}"))
                            .ok();
                    }

                    tokio::spawn(async move {
                        if let Some(ProtoType::Tcp) = psp.proto {
                            if upstream.is_none() {
                                error!("tcp connection requires an upstream");
                                return;
                            }

                            if let Some(outbound_stream) =
                                Self::create_tcp_stream(upstream.unwrap(), psp.tcp_nodelay).await
                            {
                                Self::start_stream_transfer(
                                    inbound_stream,
                                    outbound_stream,
                                    &psp.stats_sender,
                                )
                                .await
                                .ok();
                            }
                        } else {
                            match Self::process_stream(
                                inbound_stream,
                                psp,
                                upstream,
                                prefer_upstream,
                                dns_resolver.unwrap(),
                                system_dns_resolver.unwrap(),
                            )
                            .await
                            {
                                Ok(()) => {}
                                Err(ProxyError::BadRequest) => {
                                    error!("BadRequest");
                                }
                                Err(ProxyError::BadGateway(e)) => {
                                    error!("BadGateway: {e:?}");
                                }
                                Err(ProxyError::Timeout) => {
                                    error!("Timeout");
                                }
                                Err(e) => {
                                    error!("generic error: {e:?}");
                                }
                            }
                        }
                    });
                }

                Err(e) => {
                    error!("access server will wait due to err: {e}");
                    tokio::time::sleep(Duration::from_secs(5)).await
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
        proto: &Option<ProtoType>,
        server_addr: SocketAddr,
        first_byte: u8,
    ) -> Box<dyn ProxyHandler + Send + Sync> {
        match proto {
            Some(ProtoType::Socks5) => {
                Box::new(SocksProxyHandler::new(SocksVersion::V5, server_addr))
            }
            Some(ProtoType::Socks4) => {
                Box::new(SocksProxyHandler::new(SocksVersion::V4, server_addr))
            }
            Some(ProtoType::Http) => Box::new(HttpProxyHandler::new()),
            Some(ProtoType::Tcp) | Some(ProtoType::Udp) => {
                unreachable!("not valid proxy type")
            }
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
        system_resolver: Arc<DNSResolver>,
    ) -> Result<(), ProxyError> {
        // this buffer must be big enough to receive SOCKS request
        let mut buffer = [0u8; 512];
        let mut proxy_handler = None;
        loop {
            let nread =
                tokio::time::timeout(Duration::from_secs(2), inbound_stream.read(&mut buffer))
                    .await
                    .map_err(|_: Elapsed| ProxyError::Timeout)?
                    .map_err(|_| ProxyError::BadRequest)?;

            if proxy_handler.is_none() {
                proxy_handler = Some(Self::create_proxy_handler(
                    &params.proto,
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
                let match_result = if prefer_upstream || params.proxy_rule_manager.is_none() {
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
                            ProtoType::Tcp | ProtoType::Udp => {
                                unreachable!("not valid proxy type")
                            }
                        };

                        debug!(
                            "forward to {outbound_type:?}, {addr} → {}",
                            upstream.unwrap()
                        );

                        outbound_stream =
                            Self::create_tcp_stream(upstream.unwrap(), params.tcp_nodelay).await;
                    }

                    _ => {}
                }
            }

            if outbound_type == OutboundType::Direct {
                debug!(
                    "serve request directly: {addr} from {}",
                    inbound_stream.peer_addr().unwrap()
                );
                outbound_stream = match &addr.host {
                    Host::Domain(domain) => {
                        let resolver = if addr.is_internal_domain() {
                            &system_resolver
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
                                    params.dashboard_addr,
                                    &inbound_stream,
                                    params.tcp_nodelay,
                                )
                                .await?;
                                break;
                            }

                            let stream = Self::create_tcp_stream(
                                SocketAddr::new(ip, addr.port),
                                params.tcp_nodelay,
                            )
                            .await;
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
                                params.dashboard_addr,
                                &inbound_stream,
                                params.tcp_nodelay,
                            )
                            .await?
                        } else {
                            Self::create_tcp_stream(
                                addr.to_socket_addr().unwrap(),
                                params.tcp_nodelay,
                            )
                            .await
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
                    warn!(
                        "failed to create outbound stream for: {addr} from {:?}",
                        inbound_stream.peer_addr()
                    );
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
        tcp_nodelay: bool,
    ) -> Result<Option<TcpStream>, ProxyError> {
        match dashboard_addr {
            Some(addr) => {
                debug!("dashboard request: {:?}", inbound_stream.peer_addr());
                Ok(Self::create_tcp_stream(addr, tcp_nodelay).await)
            }
            None => {
                log::warn!(
                    "request routing to the proxy server itself is rejected: {:?}",
                    inbound_stream.peer_addr()
                );
                Err(ProxyError::BadRequest)
            }
        }
    }

    async fn create_tcp_stream(addr: SocketAddr, nodelay: bool) -> Option<TcpStream> {
        if addr.ip().is_unspecified() {
            error!("address is unspecified: {addr}");
            return None;
        }

        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| {
                error!("failed to connect to address: {addr}, err: {e}");
                e
            })
            .ok()?;

        if nodelay {
            stream
                .set_nodelay(true)
                .map_err(|e| error!("failed to call set_nodelay: {e}"))
                .ok();
        }
        Some(stream)
    }

    fn proto_as_string(&self) -> String {
        match self.config.server_addr.proto {
            Some(ref proto) => proto.to_string(),
            None => "HTTP|SOCKS5|SOCKS4".to_string(),
        }
    }

    async fn start_stream_transfer(
        mut inbound_stream: TcpStream,
        mut outbound_stream: TcpStream,
        stats_sender: &Sender<ServerStats>,
    ) -> Result<ProxyTraffic, ProxyError> {
        stats_sender.send(ServerStats::NewConnection).await.ok();

        let in_addr = inbound_stream
            .peer_addr()
            .map_err(|_| ProxyError::InternalError)?;
        let out_addr = outbound_stream
            .peer_addr()
            .map_err(|_| ProxyError::InternalError)?;

        debug!("sess start: {in_addr:<20} ↔ {out_addr:<20}");

        const BUFFER_SIZE: usize = 8192;
        let mut inbound_buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);
        let mut outbound_buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);

        let (mut inbound_reader, mut inbound_writer) = inbound_stream.split();
        let (mut outbound_reader, mut outbound_writer) = outbound_stream.split();

        let mut tx_bytes = 0u64;
        let mut rx_bytes = 0u64;
        let mut inbound_stream_eos = false;
        let mut outbound_stream_eos = false;
        let mut loop_count = 0;

        loop {
            loop_count += 1;
            let result = if !inbound_stream_eos && !outbound_stream_eos {
                tokio::select! {
                    result = Self::transfer_data_with_timeout(
                        &mut inbound_reader,
                        &mut outbound_writer,
                        &mut inbound_buffer,
                        &mut tx_bytes,
                        &mut inbound_stream_eos) => result,
                    result = Self::transfer_data_with_timeout(
                        &mut outbound_reader,
                        &mut inbound_writer,
                        &mut outbound_buffer,
                        &mut rx_bytes,
                        &mut outbound_stream_eos) => result,
                }
            } else if !outbound_stream_eos {
                Self::transfer_data_with_timeout(
                    &mut outbound_reader,
                    &mut inbound_writer,
                    &mut outbound_buffer,
                    &mut rx_bytes,
                    &mut outbound_stream_eos,
                )
                .await
            } else {
                Self::transfer_data_with_timeout(
                    &mut inbound_reader,
                    &mut outbound_writer,
                    &mut inbound_buffer,
                    &mut tx_bytes,
                    &mut inbound_stream_eos,
                )
                .await
            };

            match result {
                Ok(0) => {
                    if inbound_stream_eos && outbound_stream_eos {
                        break;
                    }
                }
                Err(ProxyError::Timeout) => {
                    debug!("timeout   : {in_addr:<20} ↔ {out_addr:<20} | ⟳ {loop_count:<8}| ↑ {tx_bytes:<10} ↓ {rx_bytes:<10}");
                    break;
                }
                Err(_) => break,
                Ok(_) => {}
            }
        }
        debug!("sess end  : {in_addr:<20} ↔ {out_addr:<20} | ⟳ {loop_count:<8}| ↑ {tx_bytes:<10} ↓ {rx_bytes:<10}");

        stats_sender
            .send(ServerStats::Traffic(ProxyTraffic { tx_bytes, rx_bytes }))
            .await
            .ok();

        stats_sender.send(ServerStats::CloseConnection).await.ok();
        Ok(ProxyTraffic { rx_bytes, tx_bytes })
    }

    async fn transfer_data_with_timeout<R, W>(
        reader: &mut R,
        writer: &mut W,
        buffer: &mut [u8],
        out_bytes: &mut u64,
        eos_flag: &mut bool,
    ) -> Result<usize, ProxyError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        match tokio::time::timeout(Duration::from_secs(15), reader.read(buffer))
            .await
            .map_err(|_: Elapsed| ProxyError::Timeout)?
        {
            Ok(0) => {
                if !*eos_flag {
                    *eos_flag = true;
                    writer
                        .shutdown()
                        .await
                        .map_err(|_| ProxyError::InternalError)?;
                }
                Ok(0)
            }
            Ok(n) => {
                *out_bytes += n as u64;
                writer
                    .write_all(&buffer[..n])
                    .await
                    .map_err(|_| ProxyError::InternalError)?;
                Ok(n)
            }
            Err(_) => Err(ProxyError::InternalError), // Connection mostly reset by peer
        }
    }

    // async fn resolve_net_addr(&self, addr: &NetAddr) -> Result<SocketAddr> {
    //     if addr.is_ip() {
    //         return Ok(addr.to_socket_addr().unwrap());
    //     }
    //
    //     let resolver = if addr.is_internal_domain() {
    //         inner_state!(self, system_dns_resolver).clone()
    //     } else {
    //         inner_state!(self, dns_resolver).clone()
    //     };
    //
    //     let ip_arr = resolver.unwrap().lookup(addr.unwrap_domain()).await?;
    //     Ok(SocketAddr::new(*ip_arr.first().unwrap(), addr.port))
    // }

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
                server_addr: cfg.server_addr.to_string(),
                dot_server: dot_server.unwrap_or("".to_string()),
                name_servers: name_servers.unwrap_or("".to_string()),
            }
        } else {
            ProxyServerConfig {
                server_addr: cfg.server_addr.to_string(),
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
            qc.stop();
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
    proto: Option<ProtoType>,
    server_addr: SocketAddr,
    upstream_type: Option<ProtoType>,
    dashboard_addr: Option<SocketAddr>,
    proxy_rule_manager: Option<ProxyRuleManager>,
    stats_sender: Sender<ServerStats>,
    tcp_nodelay: bool,
}
