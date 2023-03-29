use std::net::TcpStream;

use rs_utilities::ByteBuffer;

use crate::ProxyError;

use super::{SocksError, SocksVersion};

#[derive(PartialEq, Debug)]
pub(crate) enum State {
    IdentifyMethod,
    WaitForConnect,
    NegotiationCompleted,
    ErrorOccurred(SocksError),
}

pub(crate) struct SockServer {
    socks_version: SocksVersion,
    state: State,
    buffer: ByteBuffer<512>,
}

impl SockServer {
    pub fn new(socks_version: SocksVersion) -> Self {
        SockServer {
            socks_version: socks_version.clone(),
            state: if socks_version == SocksVersion::V5 {
                State::IdentifyMethod
            } else {
                State::WaitForConnect
            },
            buffer: ByteBuffer::new(),
        }
    }

    pub async fn authenticate_connection(
        socks_version: SocksVersion,
        inbound_stream: &mut TcpStream,
    ) -> Result<TcpStream, ProxyError> {
        // let mut stream = TcpStream::connect(socks_server_addr).await.map_err(|e| {
        //     error!("failed to connect: {}", e);
        //     ProxyError::ConnectionRefused
        // })?;

        Ok(stream)
    }
}
