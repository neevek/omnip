use crate::{unspecified_socket_addr, BUFFER_POOL};
use anyhow::{Context, Result};
use dashmap::DashMap;
use log::{debug, error, warn};
use std::sync::Mutex;
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;

pub const UDP_PACKET_SIZE: usize = 1500;

pub struct UdpServer {
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Clone)]
struct State {
    serv_sock: Arc<UdpSocket>,
    sock_map: DashMap<SocketAddr, Arc<UdpSocket>>,
}

impl UdpServer {
    pub async fn bind_and_start(
        server_addr: SocketAddr,
        upstream_addr: SocketAddr,
        use_sync: bool,
        udp_timeout_ms: u64,
    ) -> Result<Self> {
        let serv_sock = Arc::new(UdpSocket::bind(server_addr).await?);

        let state = Arc::new(Mutex::new(State {
            serv_sock: serv_sock.clone(),
            sock_map: DashMap::new(),
        }));
        let state_clone = state.clone();

        let task = || async move {
            loop {
                let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
                let state = state.clone();
                match serv_sock.recv_from(&mut buf).await {
                    Ok((size, addr)) => {
                        tokio::spawn(async move {
                            let state = state.lock().unwrap().clone();
                            let sock =
                                Self::open_udp_socket(&state, addr, upstream_addr, udp_timeout_ms)
                                    .await?;
                            sock.send(&buf[..size]).await.ok();
                            Ok::<(), anyhow::Error>(())
                        });
                    }
                    Err(e) => {
                        error!("failed to read from local udp socket, err: {e}");
                    }
                }
            }
        };

        if use_sync {
            task().await;
        } else {
            tokio::spawn(task());
        }

        Ok(Self { state: state_clone })
    }

    async fn open_udp_socket(
        state: &State,
        inbound_addr: SocketAddr,
        outbound_addr: SocketAddr,
        udp_timeout_ms: u64,
    ) -> Result<Arc<UdpSocket>> {
        if let Some(s) = state.sock_map.get(&inbound_addr) {
            return Ok((*s).clone());
        }

        let sock_map = state.sock_map.clone();
        let serv_sock = state.serv_sock.clone();

        let local_addr = unspecified_socket_addr(outbound_addr.is_ipv6());
        let udp_socket = Arc::new(UdpSocket::bind(local_addr).await?);
        udp_socket.connect(outbound_addr).await?;
        let udp_socket_clone = udp_socket.clone();
        sock_map.insert(inbound_addr, udp_socket.clone());

        tokio::spawn(async move {
            debug!(
                "start udp session: {inbound_addr}, sockets: {}",
                sock_map.len()
            );
            loop {
                let mut buf = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
                match tokio::time::timeout(
                    Duration::from_millis(udp_timeout_ms),
                    udp_socket.recv(&mut buf),
                )
                .await
                {
                    Ok(Ok(size)) => {
                        unsafe {
                            buf.set_len(size);
                        }
                        serv_sock.send_to(&buf[..size], inbound_addr).await.ok();
                    }
                    e => {
                        match e {
                            Ok(Err(e)) => {
                                warn!("failed read from udp socket, err: {e}");
                            }
                            Err(_) => {
                                // timedout
                            }
                            _ => unreachable!(""),
                        }
                        break;
                    }
                }
            }

            sock_map.remove(&inbound_addr);
            debug!(
                "drop udp session({inbound_addr}), sockets: {}",
                sock_map.len()
            );
        });

        Ok(udp_socket_clone)
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.state
            .lock()
            .unwrap()
            .serv_sock
            .local_addr()
            .context("")
    }
}
