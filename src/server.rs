use crate::http_parser::HttpRequest;
use crate::server_info_bridge::{ServerInfo, ServerInfoBridge, ServerInfoType, TrafficData};
use crate::socks::socks_client::SocksClient;
use crate::socks::SocksVersion;
use crate::{
    http_parser, utils, BufferPool, Config, DownstreamType, Host, ProxyError, ProxyRuleManager,
};
use anyhow::{anyhow, bail, Context, Result};
use byte_pool::Block;
use futures_util::TryFutureExt;
use log::{debug, error, info};
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rs_utilities::dns::{DNSResolver, DNSResolverType};
use rs_utilities::log_and_bail;
use serde::Serialize;
use std::borrow::BorrowMut;
use std::cmp::min;
use std::fmt::Display;
use std::net::SocketAddr;
use std::path::Path;
use std::str;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

const HTTP_RESP_200: &[u8] = b"HTTP/1.1 200 OK\r\nServer: rsp\r\n\r\n";
const HTTP_RESP_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nServer: rsp\r\n\r\n";
const HTTP_RESP_413: &[u8] = b"HTTP/1.1 413 Payload Too Large\r\nServer: rsp\r\n\r\n";
const HTTP_RESP_400: &[u8] = b"HTTP/1.1 300 Bad Request\r\nServer: rsp\r\n\r\n";
const MAX_CLIENT_HEADER_SIZE: usize = 1024 * 8;
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
    buffer_pool: BufferPool,
    proxy_rule_manager: Option<Arc<RwLock<ProxyRuleManager>>>,
    resolver: Option<Arc<DNSResolver>>,
    system_resolver: Option<Arc<DNSResolver>>,
    watcher: Option<Box<dyn Watcher>>,
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
            buffer_pool: crate::new_buffer_pool(),
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

    pub fn start_and_block(&mut self) -> Result<()> {
        self.setup_proxy_rules_manager()?;

        if let Some(addr) = self.config.downstream_addr {
            info!("using downstream: {}", addr);
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
                self.serve().await.ok();
            });

        self.set_and_post_server_state(ServerState::Terminated);

        Ok(())
    }

    pub async fn bind(&mut self) -> Result<()> {
        let tcp_listener = TcpListener::bind(self.config.addr).await.context(format!(
            "failed to bind server on address: {}",
            self.config.addr
        ))?;

        info!("server bound to {}", self.config.addr);
        self.tcp_listener = Some(tcp_listener);

        Ok(())
    }

    pub async fn serve(&mut self) -> Result<()> {
        if self.tcp_listener.is_none() {
            log_and_bail!("bind the server first");
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

        info!("started listening, addr: {}", self.config.addr);

        self.set_and_post_server_state(ServerState::Running);

        let (traffic_data_sender, traffic_data_receiver) =
            channel::<TrafficData>(TRAFFIC_DATA_QUEUE_SIZE);
        self.collect_and_report_traffic_data(traffic_data_receiver);

        let listener = self.tcp_listener.as_ref().unwrap();
        loop {
            match listener.accept().await {
                Ok((upstream, _addr)) => {
                    let resolver = self.resolver.as_ref().unwrap().clone();
                    let system_resolver = self.system_resolver.as_ref().unwrap().clone();
                    let buffer_pool = self.buffer_pool.clone();
                    let downstream_type = self.config.downstream_type.clone();
                    let downstream_addr = self.config.downstream_addr.clone();
                    let proxy_rule_manager = self.proxy_rule_manager.clone();
                    let traffic_data_sender = traffic_data_sender.clone();
                    tokio::spawn(async move {
                        Self::process_stream(
                            resolver,
                            system_resolver,
                            buffer_pool,
                            upstream,
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

    pub fn has_scheduled_start(&self) -> bool {
        self.scheduled_start
    }

    pub fn get_state(&self) -> ServerState {
        self.state.clone()
    }

    async fn process_stream(
        resolver: Arc<DNSResolver>,
        system_resolver: Arc<DNSResolver>,
        buffer_pool: BufferPool,
        mut upstream: TcpStream,
        downstream_type: Option<DownstreamType>,
        downstream_addr: Option<SocketAddr>,
        proxy_rule_manager: Option<Arc<RwLock<ProxyRuleManager>>>,
        traffic_data_sender: Sender<TrafficData>,
    ) -> Result<(), ProxyError> {
        let mut buf = buffer_pool.alloc(MAX_CLIENT_HEADER_SIZE);
        let mut total_read = 0;
        loop {
            let nread = upstream
                .read(&mut buf[total_read..])
                .await
                .context("failed to read from upstream")
                .map_err(|_| ProxyError::BadRequest)?;

            total_read += nread;

            let http_request = http_parser::parse(&buf[..total_read]);
            if http_request.is_none() {
                if nread == 0 {
                    utils::write_to_stream(&mut upstream, HTTP_RESP_400).await?;
                    error!("failed to read request: total_read:{}", total_read);
                    return Err(ProxyError::BadRequest);
                }

                if total_read == buf.len() {
                    utils::write_to_stream(&mut upstream, HTTP_RESP_413).await?;
                    error!("invalid request, total_read:{}", total_read);
                    return Err(ProxyError::PayloadTooLarge);
                }

                if buf[..min(16, total_read)].iter().any(|w| w >= &0x80) {
                    error!("invalid request, total_read:{}", total_read);
                    return Err(ProxyError::BadRequest);
                }

                // read more
                continue;
            }

            let http_request = http_request.unwrap();
            let addr = http_request
                .get_request_addr()
                .context("failed to parse request")
                .map_err(|_| ProxyError::BadRequest)?;

            if addr.is_domain() && downstream_addr.is_some() {
                let downstream_addr = downstream_addr.unwrap();
                let domain = addr.unwrap_domain();
                if proxy_rule_manager.is_none()
                    || Self::matches_proxy_rule(proxy_rule_manager.unwrap(), domain, addr.port)
                {
                    debug!(
                        "forward payload to downstream, {} -> {:?}",
                        addr, downstream_addr
                    );

                    let downstream_type = downstream_type.unwrap();
                    let downstream = if downstream_type == DownstreamType::HTTP {
                        TcpStream::connect(downstream_addr)
                            .await
                            .map_err(|_| ProxyError::ConnectionRefused)?
                    } else {
                        let socks_version = if downstream_type == DownstreamType::SOCKS
                            || downstream_type == DownstreamType::SOCKS5
                        {
                            SocksVersion::V5
                        } else {
                            SocksVersion::V4
                        };
                        SocksClient::initiate_connection(socks_version, &downstream_addr, addr)
                            .await?
                    };

                    Self::prepare_for_streamming(
                        http_request,
                        upstream,
                        downstream,
                        traffic_data_sender,
                        buf,
                        total_read,
                    )
                    .await?;

                    return Ok(());
                }
            }

            let addrs: Vec<SocketAddr> = if let Host::Domain(domain) = &addr.host {
                let resolver = if addr.is_internal_domain() {
                    system_resolver
                } else {
                    resolver
                };

                resolver
                    .lookup(domain.as_str())
                    .await
                    .map_err(|e| {
                        ProxyError::BadGateway(anyhow!("failed to resolve: {}, error: {}", addr, e))
                    })?
                    .iter()
                    .map(|&e| SocketAddr::new(e, addr.port))
                    .collect()
            } else {
                if let Host::IP(ip) = addr.host {
                    vec![SocketAddr::new(ip, addr.port)]
                } else {
                    vec![]
                }
            };

            debug!("serve request directly: {}", addr);

            for addr in addrs {
                if let Ok(downstream) = TcpStream::connect(addr).await {
                    Self::prepare_for_streamming(
                        http_request,
                        upstream,
                        downstream,
                        traffic_data_sender,
                        buf,
                        total_read,
                    )
                    .await?;

                    return Ok(());
                }
            }

            utils::write_to_stream(&mut upstream, HTTP_RESP_502).await?;
            return Err(ProxyError::BadGateway(anyhow!(
                "cannot connect to {}",
                addr
            )));
        }
    }

    async fn prepare_for_streamming<'a>(
        http_request: HttpRequest,
        mut upstream: TcpStream,
        mut downstream: TcpStream,
        traffic_data_sender: Sender<TrafficData>,
        buf: Block<'a>,
        total_read: usize,
    ) -> Result<(), ProxyError> {
        let mut payload_start_index: usize = 0;
        if http_request.is_connect_request() {
            payload_start_index = http_request.header_len;
            utils::write_to_stream(&mut upstream, HTTP_RESP_200).await?;
        }

        if payload_start_index < total_read {
            let header = str::from_utf8(&buf[payload_start_index..total_read])
                .context("failed to convert header as UTF-8 string")
                .map_err(|_| ProxyError::BadRequest)?
                .replace("Proxy-Connection", "Connection")
                .replace("proxy-connection", "Connection");

            utils::write_to_stream(&mut downstream, header.as_bytes()).await?;

            if http_request.header_len < total_read {
                utils::write_to_stream(&mut downstream, &buf[http_request.header_len..total_read])
                    .await?;
            }
        }

        traffic_data_sender
            .send(TrafficData {
                tx_bytes: total_read as u64,
                rx_bytes: 0,
            })
            .await
            .ok();

        Self::start_stream_transfer(&mut upstream, &mut downstream, &traffic_data_sender).await?;

        Ok(())
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
            tx_bytes,
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
