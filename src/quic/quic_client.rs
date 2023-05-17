use anyhow::Result;
use std::{net::SocketAddr, sync::Arc};
use tokio::task::JoinHandle;

use crate::QuicClientConfig;

pub struct QuicClient {
    client: Arc<rstun::Client>,
    server_addr: String,
    access_server_addr: Option<SocketAddr>,
}

impl QuicClient {
    pub fn new(quic_client_config: QuicClientConfig) -> Self {
        let mut config = rstun::ClientConfig::default();
        Self::set_config(&mut config, &quic_client_config);
        let server_addr = config.server_addr.clone();
        QuicClient {
            client: rstun::Client::new(config.clone()),
            server_addr,
            access_server_addr: None,
        }
    }

    pub async fn start_access_server(&mut self) -> Result<()> {
        self.access_server_addr = Some(self.client.start_access_server().await?);
        Ok(())
    }

    pub fn connect_and_serve_async(&self) -> JoinHandle<()> {
        self.client.connect_and_serve_async()
    }

    pub fn set_on_info_listener(&mut self, callback: impl FnMut(&str) + 'static + Send + Sync) {
        self.client.set_on_info_listener(callback);
    }

    pub fn set_enable_on_info_report(&mut self, enable: bool) {
        self.client.set_enable_on_info_report(enable);
    }

    pub fn stop(&self) -> Result<()> {
        self.client.stop()
    }

    pub fn get_server_addr(&self) -> String {
        self.server_addr.clone()
    }

    pub fn access_server_addr(&self) -> Option<SocketAddr> {
        self.access_server_addr
    }

    pub fn get_state(&self) -> rstun::ClientState {
        self.client.get_state()
    }

    fn set_config(config: &mut rstun::ClientConfig, quic_client_config: &QuicClientConfig) {
        config.server_addr = quic_client_config.server_addr.to_string();
        config.cert_path = quic_client_config.common_cfg.cert.clone();
        config.cipher = quic_client_config.common_cfg.cipher.clone();
        config.max_idle_timeout_ms = quic_client_config.common_cfg.max_idle_timeout_ms;
        config.keep_alive_interval_ms = quic_client_config.common_cfg.max_idle_timeout_ms / 2;
        config.threads = quic_client_config.common_cfg.threads;
        config.wait_before_retry_ms = quic_client_config.common_cfg.retry_interval_ms;
        config.connect_max_retry = 0;
        config.mode = rstun::TUNNEL_MODE_OUT;
        config.local_access_server_addr = Some(quic_client_config.local_access_server_addr);
        config.login_msg = Some(rstun::TunnelMessage::ReqOutLogin(rstun::LoginInfo {
            password: quic_client_config.common_cfg.password.clone(),
            access_server_addr: None,
        }))
    }
}
