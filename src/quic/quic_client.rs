use anyhow::Result;
use std::net::SocketAddr;

use crate::QuicClientConfig;

pub struct QuicClient {
    client: rstun::Client,
    access_server_addr: Option<SocketAddr>,
}

impl QuicClient {
    pub fn new(quic_client_config: QuicClientConfig) -> Self {
        let mut config = rstun::ClientConfig::default();
        config.server_addr = quic_client_config.server_addr.to_string();
        config.cert_path = quic_client_config.cert;
        config.cipher = quic_client_config.cipher;
        config.max_idle_timeout_ms = quic_client_config.max_idle_timeout_ms;
        config.keep_alive_interval_ms = config.max_idle_timeout_ms / 2;
        config.connect_max_retry = 0;
        config.wait_before_retry_ms = 5000;
        config.mode = rstun::TUNNEL_MODE_OUT;
        config.local_access_server_addr = Some(quic_client_config.local_access_server_addr);
        config.login_msg = Some(rstun::TunnelMessage::ReqOutLogin(rstun::LoginInfo {
            password: quic_client_config.password,
            access_server_addr: None,
        }));

        QuicClient {
            client: rstun::Client::new(config),
            access_server_addr: None,
        }
    }

    pub async fn start_access_server(&mut self) -> Result<()> {
        self.access_server_addr = Some(self.client.start_access_server().await?);
        Ok(())
    }

    pub async fn connect_and_serve(&mut self) {
        self.client.connect_and_serve().await;
    }

    pub fn access_server_addr(&self) -> Option<SocketAddr> {
        self.access_server_addr
    }
}
