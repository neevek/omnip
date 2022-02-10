use crate::{http_parser, BufferPool};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::TryFutureExt;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::str;
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::{
    io::AsyncReadExt,
    net::lookup_host,
    net::{TcpListener, TcpStream},
};

const HTTP_RESP_200: &[u8] = b"HTTP/1.1 200 OK\r\nServer: rsp\r\n\r\n";
const HTTP_RESP_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nServer: rsp\r\n\r\n";
const HTTP_RESP_413: &[u8] = b"HTTP/1.1 413 Payload Too Large\r\nServer: rsp\r\n\r\n";
const HTTP_RESP_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\nServer: rsp\r\n\r\n";
const MAX_PENDING_REQUEST_BYTES: usize = 1024 * 128;

#[derive(Debug)]
pub enum ProxyError {
    BadRequest,
    PayloadTooLarge,
    BadGateway,
    Disconnected(anyhow::Error),
}

pub struct Server {
    addr: SocketAddr,
    tcp_listener: Option<TcpListener>,
    buffer_pool: BufferPool,
    is_running: Mutex<bool>,
}

impl Server {
    pub fn new(addr: SocketAddr) -> Self {
        Server {
            addr,
            tcp_listener: None,
            buffer_pool: crate::new_buffer_pool(),
            is_running: Mutex::new(false),
        }
    }

    pub async fn bind(&mut self) -> Result<()> {
        let tcp_listener = TcpListener::bind(self.addr)
            .await
            .context(format!("failed to bind server on address: {}", self.addr))?;

        info!("server bound to {}", self.addr);
        self.tcp_listener = Some(tcp_listener);

        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.tcp_listener.is_none() {
            bail!("bind the server first");
        }

        *self.is_running.lock().unwrap() = true;

        info!("started listening, addr: {}", self.addr);

        let listener = self.tcp_listener.as_ref().unwrap();
        loop {
            match listener.accept().await {
                Ok((tcp_stream, addr)) => {
                    if !*self.is_running.lock().unwrap() {
                        info!("proxy server quit");
                        break;
                    }

                    debug!("received connection, addr: {}", addr);
                    let buffer_pool = self.buffer_pool.clone();
                    tokio::spawn(async move {
                        Self::process_stream(buffer_pool, tcp_stream)
                            .await
                            .map_err(|e| match e {
                                ProxyError::BadRequest | ProxyError::BadGateway => {
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

    pub async fn process_stream(
        buffer_pool: BufferPool,
        mut upstream: TcpStream,
    ) -> Result<(), ProxyError> {
        let mut buf = buffer_pool.alloc(MAX_PENDING_REQUEST_BYTES);
        let mut total_read = 0 as usize;
        let mut is_request_valid = false;
        let mut has_sent_resp = false;
        loop {
            total_read = total_read
                + upstream
                    .read(&mut buf[total_read..])
                    .await
                    .context("failed to read from upstream")
                    .map_err(|_| ProxyError::BadRequest)?;

            if let Ok(s) = str::from_utf8(&buf[..total_read]) {
                if let Some(http_request) = http_parser::parse(s) {
                    let addr = http_request
                        .get_request_addr()
                        .context("failed to parse request")
                        .map_err(|_| ProxyError::BadRequest)?;

                    is_request_valid = true;

                    let addrs = lookup_host(&addr)
                        .await
                        .context(format!("failed to resolve DNS for addr: {}", addr))
                        .map_err(|_| ProxyError::BadGateway)?;

                    for addr in addrs {
                        if let Ok(mut downstream) = TcpStream::connect(addr).await {
                            upstream
                                .write(HTTP_RESP_200)
                                .await
                                .context(format!(
                                    "failed to write to upstream, addr: {:?}",
                                    upstream.local_addr()
                                ))
                                .map_err(|e| ProxyError::Disconnected(e))?;

                            has_sent_resp = true;

                            let mut remaining_buf_start_index: usize = 0;
                            if http_request.is_connect_request() {
                                remaining_buf_start_index = http_request.header_len;
                            }
                            if remaining_buf_start_index < total_read {
                                downstream
                                    .write(&buf[remaining_buf_start_index..total_read])
                                    .await
                                    .context(format!(
                                        "failed to write to downstream, addr: {}",
                                        addr
                                    ))
                                    .map_err(|e| ProxyError::Disconnected(e))?;
                            }

                            loop {
                                let (down_bytes, up_bytes) =
                                    tokio::io::copy_bidirectional(&mut downstream, &mut upstream)
                                        .map_err(|e| ProxyError::Disconnected(anyhow!(e)))
                                        .await?;

                                if down_bytes == 0 && up_bytes == 0 {
                                    break;
                                }
                            }

                            break;
                        }
                    }
                    break;
                }
            }

            if total_read >= MAX_PENDING_REQUEST_BYTES {
                upstream
                    .write(HTTP_RESP_413)
                    .await
                    .context(format!(
                        "request payload too large, addr: {:?}",
                        upstream.peer_addr()
                    ))
                    .map_err(|_| ProxyError::PayloadTooLarge)?;

                break;
            }
        }

        if !is_request_valid {
            error!("invalid request from: {:?}", upstream.local_addr());
            upstream
                .write(HTTP_RESP_400)
                .await
                .context(format!("invalid request, addr: {:?}", upstream.peer_addr()))
                .map_err(|_| ProxyError::BadRequest)?;
        } else if !has_sent_resp {
            upstream
                .write(HTTP_RESP_502)
                .await
                .context(format!(
                    "failed to connect to downstream for upstream: {:?}",
                    upstream.peer_addr()
                ))
                .map_err(|_| ProxyError::BadGateway)?;
        }

        Ok(())
    }
}
