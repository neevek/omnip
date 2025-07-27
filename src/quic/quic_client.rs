use crate::QuicClientConfig;
use anyhow::Result;
use rstun::{TunnelConfig, TunnelMode, Upstream, UpstreamType};
use std::net::SocketAddr;

pub struct QuicClient {
    client: rstun::Client,
    server_addr: String,
}

impl QuicClient {
    pub fn new(quic_client_config: QuicClientConfig) -> Self {
        let mut config = rstun::ClientConfig::default();
        Self::set_config(&mut config, &quic_client_config);
        let server_addr = config.server_addr.clone();
        QuicClient {
            client: rstun::Client::new(config),
            server_addr,
        }
    }

    pub async fn start_tcp_server(&mut self, addr: SocketAddr) -> Result<SocketAddr> {
        Ok(self.client.start_tcp_server(addr).await?.addr())
    }

    pub async fn start_udp_server(&mut self, addr: SocketAddr) -> Result<SocketAddr> {
        Ok(self.client.start_udp_server(addr).await?.addr())
    }

    pub fn connect_and_serve_async(&mut self) {
        self.client.connect_and_serve_async()
    }

    pub fn set_on_info_listener(&mut self, callback: impl FnMut(&str) + 'static + Send + Sync) {
        self.client.set_on_info_listener(callback);
    }

    pub fn set_enable_on_info_report(&mut self, enable: bool) {
        self.client.set_enable_on_info_report(enable);
    }

    pub fn stop(&self) {
        self.client.stop()
    }

    pub fn get_server_addr(&self) -> String {
        self.server_addr.clone()
    }

    pub fn get_state(&self) -> rstun::ClientState {
        self.client.get_state()
    }

    fn set_config(config: &mut rstun::ClientConfig, quic_client_config: &QuicClientConfig) {
        let mut tunnels = Vec::new();
        if quic_client_config.local_tcp_server_addr.is_some() {
            tunnels.push(TunnelConfig {
                mode: TunnelMode::Out,
                local_server_addr: quic_client_config.local_tcp_server_addr,
                upstream: Upstream {
                    upstream_addr: None,
                    upstream_type: UpstreamType::Tcp,
                },
            });
        }

        if quic_client_config.local_udp_server_addr.is_some() {
            tunnels.push(TunnelConfig {
                mode: TunnelMode::Out,
                local_server_addr: quic_client_config.local_udp_server_addr,
                upstream: Upstream {
                    upstream_addr: None,
                    upstream_type: UpstreamType::Udp,
                },
            });
        }

        config.tunnels = tunnels;
        config.server_addr = quic_client_config.server_addr.to_string();
        config.password = quic_client_config.common_cfg.password.clone();
        config.cert_path = quic_client_config.common_cfg.cert.clone();
        config.cipher = quic_client_config.common_cfg.cipher.clone();
        config.quic_timeout_ms = quic_client_config.common_cfg.quic_timeout_ms;
        config.tcp_timeout_ms = quic_client_config.common_cfg.tcp_timeout_ms;
        config.udp_timeout_ms = quic_client_config.common_cfg.udp_timeout_ms;
        config.wait_before_retry_ms = quic_client_config.common_cfg.retry_interval_ms;
        config.hop_interval_ms = quic_client_config.common_cfg.hop_interval_ms;
        config.workers = quic_client_config.common_cfg.workers;
        config.dot_servers = quic_client_config.dot_servers.clone();
        config.dns_servers = quic_client_config.name_servers.clone();
    }
}
