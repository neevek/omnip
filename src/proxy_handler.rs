use crate::{socks::SocksVersion, NetAddr, ProxyError};
use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum OutboundType {
    HttpProxy,
    SocksProxy(SocksVersion),
    Direct,
}

pub enum ParseState<'a> {
    Pending,
    ContinueWithReply(Vec<u8>),
    FailWithReply((Vec<u8>, ProxyError)),
    ReceivedRequest(&'a NetAddr),
}

#[async_trait]
pub(crate) trait ProxyHandler {
    fn parse(&mut self, data: &[u8]) -> ParseState;

    async fn handle(
        &self,
        outbound_type: OutboundType,
        outbound_stream: &mut TcpStream,
        inbound_stream: &mut TcpStream,
    ) -> Result<(), ProxyError>;

    async fn handle_outbound_failure(
        &self,
        inbound_stream: &mut TcpStream,
    ) -> Result<(), ProxyError>;
}
