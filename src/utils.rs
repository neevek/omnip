use crate::ProxyError;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};

pub async fn write_to_stream(stream: &mut TcpStream, buf: &[u8]) -> Result<(), ProxyError> {
    stream
        .write(buf)
        .await
        .context(format!(
            "failed to write to stream, addr: {:?}",
            get_peer_addr(stream)
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
            get_peer_addr(stream)
        ))
        .map_err(ProxyError::Disconnected)?;
    Ok(size)
}

pub fn get_peer_addr(st: &TcpStream) -> Result<SocketAddr, ProxyError> {
    st.peer_addr().map_err(|e| {
        log::error!("unexpected error: {e}");
        ProxyError::GetPeerAddrFailed
    })
}
