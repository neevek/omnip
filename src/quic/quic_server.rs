use anyhow::Result;
use log::error;
use std::{net::SocketAddr, sync::Arc};

use crate::QuicServerConfig;

pub struct QuicServer {
    server: Arc<rstun::Server>,
}

impl QuicServer {
    pub fn new(quic_server_config: QuicServerConfig) -> Self {
        let config = rstun::ServerConfig {
            addr: quic_server_config.server_addr.to_string(),
            password: quic_server_config.common_cfg.password.to_string(),
            cert_path: quic_server_config.common_cfg.cert.to_string(),
            key_path: quic_server_config.common_cfg.key.to_string(),
            max_idle_timeout_ms: quic_server_config.common_cfg.max_idle_timeout_ms,
            tcp_upstreams: vec![quic_server_config.upstream_addr],
            udp_upstreams: vec![],
            dashboard_server: "".to_string(),
            dashboard_server_credential: "".to_string(),
        };
        QuicServer {
            server: rstun::Server::new(config),
        }
    }

    pub fn bind(&mut self) -> Result<SocketAddr> {
        self.server.bind()
    }

    pub async fn serve(&self) {
        self.server
            .serve()
            .await
            .map_err(|e| error!("tunnel server failed: {}", e))
            .ok();
    }
}
