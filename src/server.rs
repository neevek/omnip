use crate::{http_parser, BufferPool};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::TryFutureExt;
use log::{debug, error, info};
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
//const HTTP_RESP_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\nServer: rsp\r\n\r\n";
const MAX_PENDING_REQUEST_BYTES: usize = 1024 * 128;

#[derive(Debug)]
pub enum ProxyError {
    BadRequest,
    PayloadTooLarge,
    BadGateway(anyhow::Error),
    Disconnected(anyhow::Error),
}

pub struct Server {
    addr: SocketAddr,
    tcp_listener: Option<TcpListener>,
    buffer_pool: BufferPool,
    is_running: Mutex<bool>,
    downstream_addr: Option<SocketAddr>,
}

impl Server {
    pub fn new(addr: SocketAddr, downstream_addr: Option<SocketAddr>) -> Self {
        Server {
            addr,
            tcp_listener: None,
            buffer_pool: crate::new_buffer_pool(),
            is_running: Mutex::new(false),
            downstream_addr,
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
                Ok((upstream, addr)) => {
                    if !*self.is_running.lock().unwrap() {
                        info!("proxy server quit");
                        break;
                    }

                    debug!("received connection, addr: {}", addr);
                    let buffer_pool = self.buffer_pool.clone();
                    let downstream_addr = self.downstream_addr.clone();
                    tokio::spawn(async move {
                        Self::process_stream(buffer_pool, upstream, downstream_addr)
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
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn process_stream(
        buffer_pool: BufferPool,
        mut upstream: TcpStream,
        downstream_addr: Option<SocketAddr>,
    ) -> Result<(), ProxyError> {
        let mut buf = buffer_pool.alloc(MAX_PENDING_REQUEST_BYTES);
        let mut total_read = 0 as usize;
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

                    if let Some(downstream_addr) = downstream_addr {
                        if let Ok(mut downstream) = TcpStream::connect(downstream_addr).await {
                            Self::write_to_stream(&mut downstream, &buf[..total_read]).await?;
                            Self::start_stream_transfer(&mut downstream, &mut upstream)
                                .await
                                .ok();
                        }
                        return Ok(());
                    }

                    let addrs = lookup_host(addr.as_string())
                        .await
                        .context(format!("failed to resolve DNS for addr: {}", addr))
                        .map_err(|e| ProxyError::BadGateway(e))?;

                    for addr in addrs {
                        if let Ok(mut downstream) = TcpStream::connect(addr).await {
                            let mut remaining_buf_start_index: usize = 0;
                            if http_request.is_connect_request() {
                                remaining_buf_start_index = http_request.header_len;
                                Self::write_to_stream(&mut upstream, HTTP_RESP_200).await?;
                            }

                            if remaining_buf_start_index < total_read {
                                let header =
                                    str::from_utf8(&buf[remaining_buf_start_index..total_read])
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

                            Self::start_stream_transfer(&mut downstream, &mut upstream).await?;
                        }
                    }

                    Self::write_to_stream(&mut upstream, HTTP_RESP_502).await?;
                    return Err(ProxyError::BadGateway(anyhow!(
                        "cannot connect to {}",
                        addr
                    )));
                }
            }

            if total_read >= MAX_PENDING_REQUEST_BYTES {
                Self::write_to_stream(&mut upstream, HTTP_RESP_413).await?;
                return Err(ProxyError::PayloadTooLarge);
            }
        }
    }

    async fn write_to_stream(stream: &mut TcpStream, buf: &[u8]) -> Result<(), ProxyError> {
        stream
            .write(buf)
            .await
            .context(format!(
                "failed to write to stream, addr: {:?}",
                stream.peer_addr()
            ))
            .map_err(|e| ProxyError::Disconnected(e))?;
        Ok(())
    }

    async fn start_stream_transfer(
        a_stream: &mut TcpStream,
        b_stream: &mut TcpStream,
    ) -> Result<(), ProxyError> {
        loop {
            // copy data until error
            tokio::io::copy_bidirectional(a_stream, b_stream)
                .map_err(|e| ProxyError::Disconnected(anyhow!(e)))
                .await?;
        }
    }
}
