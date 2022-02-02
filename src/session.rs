use crate::BufferPool;
use anyhow::{bail, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Session {
    upstream: TcpStream,
    downstream: Option<SocketAddr>,
}

impl Session {
    fn new(upstream: TcpStream, downstream: Option<SocketAddr>) -> Self {
        Session {
            upstream,
            downstream,
        }
    }

    pub async fn start(&mut self, upstream: TcpStream, buffer_pool: BufferPool) -> Result<()> {
        let (mut tcp_read, mut tcp_write) = upstream.into_split();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 1024];

            loop {
                let len = buffer.len();
                let len_read = tcp_read.read(&mut buffer[len..]).await?;
                if false {
                    break;
                }
                //if len_read > 0 {
                //quic_send.write_all(&buffer[..len_read]).await?;
                //Ok(ReadResult::Succeeded)
                //} else {
                //quic_send.finish().await?;
                //Ok(ReadResult::EOF)
                //}
            }

            Result::<()>::Ok(())
        });
        Ok(())
    }
}
