use anyhow::Result;
use log::error;
use std::{net::SocketAddr, sync::Arc};

use crate::QuicServerConfig;

pub struct QuicServer {
    server: Arc<rstun::Server>,
}

impl QuicServer {
    pub fn new(quic_server_config: QuicServerConfig) -> Self {
        let mut config = rstun::ServerConfig::default();
        config.addr = quic_server_config.server_addr.to_string();
        config.password = quic_server_config.common_cfg.password.to_string();
        config.cert_path = quic_server_config.common_cfg.cert.to_string();
        config.key_path = quic_server_config.common_cfg.key.to_string();
        config.max_idle_timeout_ms = quic_server_config.common_cfg.max_idle_timeout_ms;
        config.upstreams = vec![quic_server_config.upstream_addr];
        let server = rstun::Server::new(config);
        QuicServer { server }
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
