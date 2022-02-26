mod http_parser;
mod proxy_rule_manager;
mod server;

use byte_pool::BytePool;
pub use proxy_rule_manager::ProxyRuleManager;
pub use server::Server;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::sync::Arc;

type BufferPool = Arc<BytePool<Vec<u8>>>;

fn new_buffer_pool() -> BufferPool {
    Arc::new(BytePool::<Vec<u8>>::new())
}

#[derive(Default, Debug)]
pub struct NetAddr {
    pub host: String, // domain or ip
    pub port: u16,
}

impl NetAddr {
    fn as_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl std::fmt::Display for NetAddr {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        formatter.write_fmt(format_args!("{}:{}", self.host, self.port))
    }
}

#[derive(Debug)]
pub struct Config {
    pub addr: SocketAddr,
    pub downstream_addr: Option<SocketAddr>,
    pub proxy_rules_file: String,
}
