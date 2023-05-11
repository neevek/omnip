use anyhow::Result;
use serde::{Deserialize, Serialize};

pub trait Api: Send + Sync {
    fn set_prefer_upstream(&self, flag: bool);
    fn get_server_config(&self) -> ServerConfig;
    fn get_server_state(&self) -> ServerState;
    fn apply_changes(&self, config: ServerConfig) -> Result<()>;
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ServerConfig {
    pub server_addr: String,
    pub dot_server: String,
    pub name_servers: String,
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
