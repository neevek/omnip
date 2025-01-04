use crate::QuicServerConfig;
use anyhow::Result;
use log::error;
use std::net::SocketAddr;

pub struct QuicServer {
    server: rstun::Server,
}

impl QuicServer {
    pub fn new(quic_server_config: QuicServerConfig) -> Self {
        log::info!(
            "quic server, tcp_upstream:{:?}, udp_upstream:{:?}",
            quic_server_config.tcp_upstream,
            quic_server_config.udp_upstream
        );

        let config = rstun::ServerConfig {
            addr: quic_server_config.server_addr.to_string(),
            password: quic_server_config.common_cfg.password.to_string(),
            cert_path: quic_server_config.common_cfg.cert.to_string(),
            key_path: quic_server_config.common_cfg.key.to_string(),
            quic_timeout_ms: quic_server_config.common_cfg.quic_timeout_ms,
            tcp_timeout_ms: quic_server_config.common_cfg.tcp_timeout_ms,
            udp_timeout_ms: quic_server_config.common_cfg.udp_timeout_ms,
            default_tcp_upstream: quic_server_config.tcp_upstream,
            default_udp_upstream: quic_server_config.udp_upstream,
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
            .map_err(|e| error!("tunnel server failed: {e}"))
            .ok();
    }
}
