use crate::ProxyError;
use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};

const UNSPECIFIED_V4: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

pub async fn write_to_stream(stream: &mut TcpStream, buf: &[u8]) -> Result<(), ProxyError> {
    stream
        .write(buf)
        .await
        .context(format!(
            "failed to write to stream, addr: {:?}",
            get_peer_addr_for_debug_build(stream)
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
            get_peer_addr_for_debug_build(stream)
        ))
        .map_err(ProxyError::Disconnected)?;
    Ok(size)
}

pub fn get_peer_addr_for_debug_build(st: &TcpStream) -> Result<SocketAddr, ProxyError> {
    if cfg!(debug_assertions) {
        Ok(st.peer_addr().map_err(|e| {
            log::error!("unexpected error: {e}");
            ProxyError::GetPeerAddrFailed
        })?)
    } else {
        Ok(UNSPECIFIED_V4)
    }
}
