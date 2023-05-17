use anyhow::Result;
use serde::{Deserialize, Serialize};

#[async_trait::async_trait]
pub trait Api: Send + Sync {
    fn set_prefer_upstream(&self, flag: bool);
    fn get_server_state(&self) -> ServerState;
    fn get_proxy_server_config(&self) -> ProxyServerConfig;
    fn get_quic_tunnel_config(&self) -> QuicTunnelConfig;
    fn get_server_stats(&self) -> ServerStats;
    async fn update_proxy_server_config(&self, config: ProxyServerConfig) -> Result<()>;
    async fn update_quic_tunnel_config(&self, config: QuicTunnelConfig) -> Result<()>;
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ProxyServerConfig {
    pub server_addr: String,
    pub dot_server: String,
    pub name_servers: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct QuicTunnelConfig {
    pub upstream_addr: String,
    pub cert: String,
    pub cipher: String,
    pub password: String,
    pub idle_timeout: u64,
    pub retry_interval: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerState {
    pub prefer_upstream: bool,
    pub tunnel_state: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerStats {
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub total_connections: u32,
    pub ongoing_connections: u32,
}
