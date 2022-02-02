use crate::BufferPool;
use anyhow::{bail, Context, Result};
use log::{debug, error, info};
use std::net::SocketAddr;
use std::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};

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

        self.tcp_listener = Some(tcp_listener);

        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.tcp_listener.is_none() {
            bail!("bind the server first");
        }

        *self.is_running.lock().unwrap() = true;

        let listener = self.tcp_listener.as_ref().unwrap();
        loop {
            match listener.accept().await {
                Ok((tcp_stream, addr)) => {
                    if !*self.is_running.lock().unwrap() {
                        info!("proxy server quit");
                        break;
                    }

                    debug!("received new local connection, addr: {}", addr);
                    self.process_stream(tcp_stream).await.ok();
                }

                Err(e) => {
                    error!("access server failed, err: {}", e);
                }
            }
        }

        Ok(())
    }

    pub async fn process_stream(&self, tcp_stream: TcpStream) -> Result<()> {
        Ok(())
    }
}
