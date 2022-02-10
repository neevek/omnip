use byte_pool::BytePool;
use std::sync::Arc;
mod server;
pub use server::Server;
mod session;
pub use session::Session;
pub mod http_parser;

type BufferPool = Arc<BytePool<Vec<u8>>>;

fn new_buffer_pool() -> BufferPool {
    Arc::new(BytePool::<Vec<u8>>::new())
}

#[derive(Default, Debug)]
pub struct NetAddr {
    pub host: String, // domain or ip
    pub port: u16,
}

#[derive(Default, Debug)]
pub struct Config {
    pub loglevel: String,
}
