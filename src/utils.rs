use anyhow::Context;
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};

use crate::ProxyError;

pub async fn write_to_stream(stream: &mut TcpStream, buf: &[u8]) -> Result<(), ProxyError> {
    stream
        .write(buf)
        .await
        .context(format!(
            "failed to write to stream, addr: {:?}",
            stream.peer_addr()
        ))
        .map_err(ProxyError::Disconnected)?;
    Ok(())
}

pub async fn read_from_stream(stream: &mut TcpStream, buf: &mut [u8]) -> Result<usize, ProxyError> {
    let size = stream
        .read(buf)
        .await
        .context(format!(
            "failed to read from stream, addr: {:?}",
            stream.peer_addr()
        ))
        .map_err(ProxyError::Disconnected)?;
    Ok(size)
}
