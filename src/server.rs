use crate::server_info_bridge::{ServerInfo, ServerInfoBridge, ServerInfoType};
use crate::{http_parser, BufferPool, Config, NetAddr, ProxyRuleManager};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::TryFutureExt;
use log::{debug, error, info};
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rs_utilities::dns::DNSResolver;
use rs_utilities::log_and_bail;
use serde::Serialize;
use std::borrow::BorrowMut;
use std::cmp::min;
use std::net::SocketAddr;
use std::path::Path;
use std::str;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex, RwLock};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const HTTP_RESP_200: &[u8] = b"HTTP/1.1 200 OK\r\nServer: rsp\r\n\r\n";
const HTTP_RESP_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nServer: rsp\r\n\r\n";
const HTTP_RESP_413: &[u8] = b"HTTP/1.1 413 Payload Too Large\r\nServer: rsp\r\n\r\n";
const HTTP_RESP_400: &[u8] = b"HTTP/1.1 300 Bad Request\r\nServer: rsp\r\n\r\n";
const MAX_CLIENT_HEADER_SIZE: usize = 1024 * 8;

#[derive(Debug)]
pub enum ProxyError {
    BadRequest,
    PayloadTooLarge,
    BadGateway(anyhow::Error),
    Disconnected(anyhow::Error),
}

pub struct Server {
    config: Config,
    tcp_listener: Option<TcpListener>,
    buffer_pool: BufferPool,
    proxy_rule_manager: Option<Arc<RwLock<ProxyRuleManager>>>,
    resolver: Option<Arc<DNSResolver>>,
    watcher: Option<Box<dyn Watcher>>,
    scheduled_start: bool,
    is_running: Mutex<bool>,
    server_info_bridge: ServerInfoBridge,
    on_info_report_enabled: bool,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Server {
            config,
            tcp_listener: None,
            buffer_pool: crate::new_buffer_pool(),
            proxy_rule_manager: None,
            resolver: None,
            watcher: None,
            scheduled_start: false,
            is_running: Mutex::new(false),
            server_info_bridge: ServerInfoBridge::new(),
            on_info_report_enabled: false,
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

        *self.is_running.lock().unwrap() = true;

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(worker_threads)
            .build()
            .unwrap()
            .block_on(async {
                self.bind().await.ok();
                self.serve().await.ok();
            });

        *self.is_running.lock().unwrap() = false;

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

        self.post_server_info(ServerInfo::new(
            ServerInfoType::ServerState,
            Box::new("Resoving DNS"),
        ));

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

        self.post_server_info(ServerInfo::new(
            ServerInfoType::DNSResolverType,
            Box::new(resolver.resolver_type().to_string()),
        ));

        self.resolver = Some(resolver);

        info!("started listening, addr: {}", self.config.addr);

        self.post_server_info(ServerInfo::new(
            ServerInfoType::ServerState,
            Box::new("Running"),
        ));

        let listener = self.tcp_listener.as_ref().unwrap();
        loop {
            match listener.accept().await {
                Ok((upstream, _addr)) => {
                    if !*self.is_running.lock().unwrap() {
                        info!("proxy server quit");
                        break;
                    }

                    let resolver = self.resolver.as_ref().unwrap().clone();
                    let buffer_pool = self.buffer_pool.clone();
                    let downstream_addr = self.config.downstream_addr;
                    let proxy_rule_manager = self.proxy_rule_manager.clone();
                    tokio::spawn(async move {
                        Self::process_stream(
                            resolver,
                            buffer_pool,
                            upstream,
                            downstream_addr,
                            proxy_rule_manager,
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

        Ok(())
    }

    pub fn has_scheduled_start(&self) -> bool {
        self.scheduled_start
    }

    pub fn is_running(&self) -> bool {
        *self.is_running.lock().unwrap()
    }

    pub async fn process_stream(
        resolver: Arc<DNSResolver>,
        buffer_pool: BufferPool,
        mut upstream: TcpStream,
        downstream_addr: Option<SocketAddr>,
        proxy_rule_manager: Option<Arc<RwLock<ProxyRuleManager>>>,
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
                    Self::write_to_stream(&mut upstream, HTTP_RESP_400).await?;
                    error!("failed to read request: total_read:{}", total_read);
                    return Err(ProxyError::BadRequest);
                }

                if total_read == buf.len() {
                    Self::write_to_stream(&mut upstream, HTTP_RESP_413).await?;
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

            if let Some(downstream_addr) = downstream_addr {
                if proxy_rule_manager.is_none()
                    || Self::matches_proxy_rule(proxy_rule_manager.unwrap(), &addr)
                {
                    debug!(
                        "forward payload to downstream, {} -> {:?}",
                        addr, downstream_addr
                    );
                    if let Ok(mut downstream) = TcpStream::connect(downstream_addr).await {
                        Self::write_to_stream(&mut downstream, &buf[..total_read]).await?;
                        Self::start_stream_transfer(&mut downstream, &mut upstream)
                            .await
                            .ok();
                    }
                    return Ok(());
                }
            }

            let addrs: Vec<SocketAddr> = resolver
                .lookup(&addr.host)
                .await
                .map_err(|e| {
                    ProxyError::BadGateway(anyhow!(
                        "failed to resolve: {}, error: {}",
                        addr.host,
                        e
                    ))
                })?
                .iter()
                .map(|&e| SocketAddr::new(e, addr.port))
                .collect();

            debug!("serve request directly: {}", addr);

            for addr in addrs {
                if let Ok(mut downstream) = TcpStream::connect(addr).await {
                    let mut payload_start_index: usize = 0;
                    if http_request.is_connect_request() {
                        payload_start_index = http_request.header_len;
                        Self::write_to_stream(&mut upstream, HTTP_RESP_200).await?;
                    }

                    if payload_start_index < total_read {
                        let header = str::from_utf8(&buf[payload_start_index..total_read])
                            .context("failed to convert header as UTF-8 string")
                            .map_err(|_| ProxyError::BadRequest)?
                            .replace("Proxy-Connection", "Connection")
                            .replace("proxy-connection", "Connection");

                        Self::write_to_stream(&mut downstream, header.as_bytes()).await?;

                        if http_request.header_len < total_read {
                            Self::write_to_stream(
                                &mut downstream,
                                &buf[http_request.header_len..total_read],
                            )
                            .await?;
                        }
                    }

                    return Self::start_stream_transfer(&mut downstream, &mut upstream).await;
                }
            }

            Self::write_to_stream(&mut upstream, HTTP_RESP_502).await?;
            return Err(ProxyError::BadGateway(anyhow!(
                "cannot connect to {}",
                addr
            )));
        }
    }

    fn matches_proxy_rule(
        mut proxy_rule_manager: Arc<RwLock<ProxyRuleManager>>,
        addr: &NetAddr,
    ) -> bool {
        let result = proxy_rule_manager
            .read()
            .unwrap()
            .matches(addr.host.as_str(), addr.port);

        if result.needs_sort_rules {
            proxy_rule_manager
                .borrow_mut()
                .write()
                .unwrap()
                .sort_rules();
        }

        result.matched
    }

    async fn write_to_stream(stream: &mut TcpStream, buf: &[u8]) -> Result<(), ProxyError> {
        stream
            .write(buf)
            .await
            .context(format!(
                "failed to write to stream, addr: {:?}",
                stream.peer_addr()
            ))
            .map_err(ProxyError::Disconnected)?;
        Ok(())
    }

    async fn start_stream_transfer(
        a_stream: &mut TcpStream,
        b_stream: &mut TcpStream,
    ) -> Result<(), ProxyError> {
        loop {
            // copy data until error
            let (a_bytes, b_bytes) = tokio::io::copy_bidirectional(a_stream, b_stream)
                .map_err(|e| ProxyError::Disconnected(anyhow!(e)))
                .await?;
            debug!(
                "transfer, in:{}, out:{}, {:?} <-> {:?}",
                a_bytes,
                b_bytes,
                a_stream.local_addr(),
                b_stream.local_addr()
            );
            if a_bytes == 0 && b_bytes == 0 {
                break;
            }
        }
        Ok(())
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
            self.watch_proxy_rules_file(proxy_rules_file.to_string())
                .ok();
        }

        Ok(())
    }

    fn watch_proxy_rules_file(&mut self, proxy_rules_file: String) -> Result<()> {
        let (tx, rx) = channel();
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

    fn post_server_info<T>(&mut self, server_info: ServerInfo<T>)
    where
        T: ?Sized + Serialize,
    {
        if self.on_info_report_enabled {
            self.server_info_bridge.post_server_info(&server_info);
        }
    }

    pub fn set_on_info_listener(&mut self, callback: impl FnMut(&str) + 'static) {
        self.server_info_bridge.set_listener(callback);
    }

    pub fn has_on_info_listener(&self) -> bool {
        self.server_info_bridge.has_listener()
    }

    pub fn set_enable_on_info_report(&mut self, enable: bool) {
        self.on_info_report_enabled = enable
    }
}
