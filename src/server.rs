use crate::http::http_proxy_handler::HttpProxyHandler;
use crate::proxy_handler::{OutboundType, ParseState, ProxyHandler};
use crate::server_info_bridge::{ServerInfo, ServerInfoBridge, ServerInfoType, TrafficData};
use crate::socks::socks_proxy_handler::SocksProxyHandler;
use crate::socks::SocksVersion;
use crate::{utils, Config, Host, ProxyError, ProxyRuleManager, ServerType};
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
use std::sync::{Arc, RwLock};
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

pub struct Server {
    config: Config,
    tcp_listener: Option<TcpListener>,
    proxy_rule_manager: Option<Arc<RwLock<ProxyRuleManager>>>,
    resolver: Option<Arc<DNSResolver>>,
    system_resolver: Option<Arc<DNSResolver>>,
    watcher: Option<Box<dyn Watcher + Send>>,
    scheduled_start: bool,
    server_info_bridge: ServerInfoBridge,
    on_info_report_enabled: bool,
    state: ServerState,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Server {
            config,
            tcp_listener: None,
            proxy_rule_manager: None,
            resolver: None,
            system_resolver: None,
            watcher: None,
            scheduled_start: false,
            server_info_bridge: ServerInfoBridge::new(),
            on_info_report_enabled: false,
            state: ServerState::Idle,
        }
    }

    pub fn set_scheduled_start(&mut self) {
        self.scheduled_start = true;
    }

    pub fn init(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn start_and_block(&mut self) -> Result<()> {
        self.setup_proxy_rules_manager()?;

        if let Some(addr) = self.config.downstream_addr {
            info!("using outbound_stream: {}", addr);
        }

        let worker_threads = if self.config.threads > 0 {
            self.config.threads
        } else {
            num_cpus::get()
        };
        info!("will use {} worker threads", worker_threads);

        self.set_and_post_server_state(ServerState::Preparing);

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(worker_threads)
            .build()
            .unwrap()
            .block_on(async {
                self.bind().await.ok();
                self.serve().await;
            });

        self.set_and_post_server_state(ServerState::Terminated);

        Ok(())
    }

    pub async fn bind(&mut self) -> Result<SocketAddr> {
        let tcp_listener = TcpListener::bind(self.config.addr).await.map_err(|e| {
            error!(
                "failed to bind proxy server on address: {}",
                self.config.addr
            );
            e
        })?;
        let socket_addr = tcp_listener.local_addr().unwrap();
        info!(
            "proxy server is bound on address: {}, type: {}",
            socket_addr, self.config.server_type
        );
        self.tcp_listener = Some(tcp_listener);

        Ok(socket_addr)
    }

    pub async fn serve_async(mut self) {
        tokio::spawn(async move { self.serve().await });
    }

    pub async fn serve(&mut self) {
        if self.tcp_listener.is_none() {
            error!("bind the proxy server first");
            return;
        }

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
            ServerInfoType::DNSResolverType,
            Box::new(resolver.resolver_type().to_string()),
        ));

        self.resolver = Some(resolver);
        self.system_resolver = Some(system_resolver);

        self.set_and_post_server_state(ServerState::Running);

        let (traffic_data_sender, traffic_data_receiver) =
            channel::<TrafficData>(TRAFFIC_DATA_QUEUE_SIZE);
        self.collect_and_report_traffic_data(traffic_data_receiver);

        let listener = self.tcp_listener.as_ref().unwrap();

        info!(
            "proxy server started listening, addr: {}, type: {}",
            listener.local_addr().unwrap(),
            self.config.server_type
        );

        loop {
            match listener.accept().await {
                Ok((inbound_stream, _addr)) => {
                    let resolver = self.resolver.as_ref().unwrap().clone();
                    let system_resolver = self.system_resolver.as_ref().unwrap().clone();
                    let downstream_type = self.config.downstream_type.clone();
                    let downstream_addr = self.config.downstream_addr.clone();
                    let proxy_rule_manager = self.proxy_rule_manager.clone();
                    let traffic_data_sender = traffic_data_sender.clone();
                    let handler = self.create_proxy_handler();

                    tokio::spawn(async move {
                        Self::process_stream(
                            resolver,
                            system_resolver,
                            handler,
                            inbound_stream,
                            downstream_type,
                            downstream_addr,
                            proxy_rule_manager,
                            traffic_data_sender,
                        )
                        .await
                        .map_err(|e| match e {
                            ProxyError::BadRequest | ProxyError::BadGateway(_) => {
                                error!("{:?}", e);
                            }
                            _ => {}
                        })
                        .ok();
                    });
                }

                Err(e) => {
                    error!("access server failed, err: {}", e);
                }
            }
        }
    }

    fn create_proxy_handler(&self) -> Box<dyn ProxyHandler + Send + Sync> {
        match self.config.server_type {
            ServerType::Http => Box::new(HttpProxyHandler::new()),
            ServerType::Socks5 => {
                Box::new(SocksProxyHandler::new(SocksVersion::V5, self.config.addr))
            }
            ServerType::Socks4 => {
                Box::new(SocksProxyHandler::new(SocksVersion::V4, self.config.addr))
            }
        }
    }

    pub fn has_scheduled_start(&self) -> bool {
        self.scheduled_start
    }

    pub fn get_state(&self) -> ServerState {
        self.state.clone()
    }

    async fn process_stream(
        resolver: Arc<DNSResolver>,
        system_resolver: Arc<DNSResolver>,
        mut proxy_handler: Box<dyn ProxyHandler + Send + Sync>,
        mut inbound_stream: TcpStream,
        downstream_type: Option<ServerType>,
        downstream_addr: Option<SocketAddr>,
        proxy_rule_manager: Option<Arc<RwLock<ProxyRuleManager>>>,
        traffic_data_sender: Sender<TrafficData>,
    ) -> Result<(), ProxyError> {
        // this buffer must be big enough to receive SOCKS request
        let mut buffer = [0u8; 512];
        loop {
            let nread = inbound_stream
                .read(&mut buffer)
                .await
                .context("failed to read from inbound_stream")
                .map_err(|_| ProxyError::BadRequest)?;

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

            if addr.is_domain() && downstream_addr.is_some() {
                let domain = addr.unwrap_domain();
                if proxy_rule_manager.is_none()
                    || Self::matches_proxy_rule(proxy_rule_manager.unwrap(), domain, addr.port)
                {
                    outbound_type = match downstream_type.unwrap() {
                        ServerType::Http => OutboundType::HttpProxy,
                        ServerType::Socks4 => OutboundType::SocksProxy(SocksVersion::V4),
                        ServerType::Socks5 => OutboundType::SocksProxy(SocksVersion::V5),
                    };

                    debug!(
                        "forward payload to next proxy({:?}), {} -> {:?}",
                        outbound_type, addr, downstream_addr
                    );

                    outbound_stream = match TcpStream::connect(downstream_addr.unwrap()).await {
                        Ok(stream) => Some(stream),
                        Err(e) => {
                            error!(
                                "failed to connect to downstream: {}, err:{}",
                                downstream_addr.unwrap(),
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
                            &system_resolver
                        } else {
                            &resolver
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

                    Host::IP(ip) => Self::create_tcp_stream(*ip, addr.port).await,
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
                        &traffic_data_sender,
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

    fn matches_proxy_rule(
        mut proxy_rule_manager: Arc<RwLock<ProxyRuleManager>>,
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
        traffic_data_sender: &Sender<TrafficData>,
    ) -> Result<TrafficData, ProxyError> {
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
            .send(TrafficData { tx_bytes, rx_bytes })
            .await
            .ok();

        Ok(TrafficData { rx_bytes, tx_bytes })
    }

    fn collect_and_report_traffic_data(&self, mut traffic_data_receiver: Receiver<TrafficData>) {
        let server_info_bridge = self.server_info_bridge.clone();
        tokio::spawn(async move {
            let mut total_rx_bytes = 0;
            let mut total_tx_bytes = 0;
            let mut last_elapsed_time = 0;
            let start_time = SystemTime::now();
            while let Some(TrafficData { rx_bytes, tx_bytes }) = traffic_data_receiver.recv().await
            {
                total_rx_bytes += rx_bytes;
                total_tx_bytes += tx_bytes;

                if let Ok(elpased) = start_time.elapsed() {
                    // report traffic data every 10 seconds
                    let elapsed_time = elpased.as_secs();
                    if elapsed_time - last_elapsed_time > POST_TRAFFIC_DATA_INTERVAL_SECS {
                        last_elapsed_time = elapsed_time;
                        server_info_bridge.post_server_info(&ServerInfo::new(
                            ServerInfoType::Traffic,
                            Box::new(TrafficData {
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

    fn setup_proxy_rules_manager(&mut self) -> Result<()> {
        let proxy_rules_file = &self.config.proxy_rules_file;
        if !proxy_rules_file.is_empty() && !Path::new(proxy_rules_file).is_file() {
            log_and_bail!("proxy rules file does not exist: {}", proxy_rules_file);
        }

        if !proxy_rules_file.is_empty() {
            let mut prm = ProxyRuleManager::default();
            let count = prm.add_rules_by_file(proxy_rules_file);

            info!(
                "{} proxy rules added with file: {}",
                count, proxy_rules_file
            );

            self.proxy_rule_manager = Some(Arc::new(RwLock::new(prm)));

            if self.config.watch_proxy_rules_change {
                info!("will watch proxy rules change");
                self.watch_proxy_rules_file(proxy_rules_file.to_string())
                    .ok();
            }
        }

        Ok(())
    }

    fn watch_proxy_rules_file(&mut self, proxy_rules_file: String) -> Result<()> {
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

        self.watcher = Some(Box::new(watcher));

        let prm = self.proxy_rule_manager.clone().unwrap();
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

    fn set_and_post_server_state(&mut self, state: ServerState) {
        info!("client state: {}", state);
        self.state = state;
        self.post_server_info(ServerInfo::new(
            ServerInfoType::ServerState,
            Box::new(self.state.to_string()),
        ));
    }

    fn post_server_info<T>(&self, server_info: ServerInfo<T>)
    where
        T: ?Sized + Serialize,
    {
        if self.on_info_report_enabled {
            self.server_info_bridge.post_server_info(&server_info);
        }
    }

    pub fn set_on_info_listener(&mut self, callback: impl FnMut(&str) + 'static + Send + Sync) {
        self.server_info_bridge.set_listener(callback);
    }

    pub fn has_on_info_listener(&self) -> bool {
        self.server_info_bridge.has_listener()
    }

    pub fn set_enable_on_info_report(&mut self, enable: bool) {
        info!("set_enable_on_info_report, enable:{}", enable);
        self.on_info_report_enabled = enable
    }
}
