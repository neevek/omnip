use anyhow::Result;
use std::{net::SocketAddr, sync::Arc};
use tokio::task::JoinHandle;

use crate::QuicClientConfig;

pub struct QuicClient {
    client: Arc<rstun::Client>,
    access_server_addr: Option<SocketAddr>,
    config: rstun::ClientConfig,
    quic_client_config: QuicClientConfig,
}

impl QuicClient {
    pub fn new(quic_client_config: QuicClientConfig) -> Self {
        let mut config = rstun::ClientConfig::default();
        let config_copy = config.clone();
        let quic_client_config_copy = quic_client_config.clone();
        Self::set_config(&mut config, quic_client_config);
        QuicClient {
            client: rstun::Client::new(config),
            access_server_addr: None,
            config: config_copy,
            quic_client_config: quic_client_config_copy,
        }
    }

    pub async fn start_access_server(&mut self) -> Result<()> {
        self.access_server_addr = Some(self.client.start_access_server().await?);
        Ok(())
    }

    pub async fn connect_and_serve_async(&self) -> JoinHandle<()> {
        self.client.connect_and_serve_async().await
    }

    pub fn set_on_info_listener(&mut self, callback: impl FnMut(&str) + 'static + Send + Sync) {
        self.client.set_on_info_listener(callback);
    }

    pub fn set_enable_on_info_report(&mut self, enable: bool) {
        self.client.set_enable_on_info_report(enable);
    }

    pub fn update_config(&mut self, quic_client_config: QuicClientConfig) {
        Self::set_config(&mut self.config, quic_client_config);
    }

    pub fn get_config(&self) -> QuicClientConfig {
        self.quic_client_config.clone()
    }

    pub async fn stop_and_reconnect(&mut self) {
        self.client.stop_and_reconnect().await
    }

    pub fn access_server_addr(&self) -> Option<SocketAddr> {
        self.access_server_addr
    }

    pub fn get_state(&self) -> rstun::ClientState {
        self.client.get_state()
    }

    fn set_config(config: &mut rstun::ClientConfig, quic_client_config: QuicClientConfig) {
        config.server_addr = quic_client_config.server_addr.to_string();
        config.cert_path = quic_client_config.common_cfg.cert;
        config.cipher = quic_client_config.common_cfg.cipher;
        config.max_idle_timeout_ms = quic_client_config.common_cfg.max_idle_timeout_ms;
        config.keep_alive_interval_ms = quic_client_config.common_cfg.max_idle_timeout_ms / 2;
        config.threads = quic_client_config.common_cfg.threads;
        config.wait_before_retry_ms = quic_client_config.common_cfg.retry_interval_ms;
        config.connect_max_retry = 0;
        config.mode = rstun::TUNNEL_MODE_OUT;
        config.local_access_server_addr = Some(quic_client_config.local_access_server_addr);
        config.login_msg = Some(rstun::TunnelMessage::ReqOutLogin(rstun::LoginInfo {
            password: quic_client_config.common_cfg.password,
            access_server_addr: None,
        }));
    }
}
