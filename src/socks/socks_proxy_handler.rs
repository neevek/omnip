use super::{socks_reply, socks_req::SocksReq, SocksVersion};
use crate::{
    http::http_req::HttpReq,
    proxy_handler::{OutboundType, ParseState, ProxyHandler},
    utils, NetAddr, ProxyError,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::{debug, error};
use std::{
    cmp::min,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::net::TcpStream;

#[derive(PartialEq, Debug)]
pub(crate) enum InternalParseState {
    SelectMethod,
    SelectedMethod,
    Connected,
}

pub struct SocksProxyHandler {
    socks_version: SocksVersion,
    bnd_addr: SocketAddr,
    state: InternalParseState,
    target_addr: Option<NetAddr>,
}

impl SocksProxyHandler {
    pub fn new(socks_version: SocksVersion, bnd_addr: SocketAddr) -> Self {
        SocksProxyHandler {
            socks_version,
            bnd_addr,
            state: match socks_version {
                SocksVersion::V5 => InternalParseState::SelectMethod,
                // for SOCKS4, there's no method selection step, so initial step is SelectedMethod
                SocksVersion::V4 => InternalParseState::SelectedMethod,
            },
            target_addr: None,
        }
    }

    fn fail_with_resp(&self) -> ParseState {
        ParseState::FailWithReply((
            socks_reply(self.socks_version, self.bnd_addr, true),
            ProxyError::BadRequest,
        ))
    }

    async fn reply_connected(
        &self,
        inbound_stream: &mut TcpStream,
        connected: bool,
    ) -> Result<(), ProxyError> {
        utils::write_to_stream(
            inbound_stream,
            &socks_reply(self.socks_version, self.bnd_addr, !connected),
        )
        .await
    }

    /// see https://www.openssh.com/txt/socks4a.protocol
    fn parse_socks4a_domain(data: &[u8]) -> Option<String> {
        let data = &data[8..];
        let userid_end = data.iter().position(|&b| b == 0u8)?;
        if userid_end + 1 < data.len() {
            let data = &data[(userid_end + 1)..];
            let domain_end = data.iter().position(|&b| b == 0u8)?;
            Some(std::str::from_utf8(&data[..domain_end]).ok()?.to_string())
        } else {
            error!("failed to parse domain name for socks4a connection");
            None
        }
    }

    fn extract_target_addr(&self) -> Result<&NetAddr, ProxyError> {
        match self.target_addr {
            Some(ref target_addr) => Ok(target_addr),
            None => Err(ProxyError::BadGateway(anyhow!(
                "failed to parse SOCKS request, no target address"
            ))),
        }
    }
}

#[async_trait]
impl ProxyHandler for SocksProxyHandler {
    fn parse(&mut self, data: &[u8]) -> ParseState {
        if self.state == InternalParseState::Connected {
            error!("invalid state, never call parse again!");
            return self.fail_with_resp();
        }

        if data.len() == 0 {
            return self.fail_with_resp();
        }

        let data_len = data.len();
        if self.state == InternalParseState::SelectMethod {
            if data_len < 3 || (data[1] + 2) as usize != data_len {
                error!("unexpected socks request length: {}", data_len);
                return self.fail_with_resp();
            }

            if !data[2..].iter().any(|method| *method == 0x00) {
                error!("only \"No Authentication\" is supported for SOCKS5");
                return self.fail_with_resp();
            }

            self.state = InternalParseState::SelectedMethod;
            return ParseState::ContinueWithReply("\x05\x00".into());
        }

        if self.state == InternalParseState::SelectedMethod {
            if self.socks_version == SocksVersion::V4 {
                if data_len < 8 {
                    return self.fail_with_resp();
                }
                // supports CONNECT only
                if !data.starts_with("\x04\x01".as_bytes()) {
                    debug!("error request: {:x?}", &data[..min(10, data_len)]);
                    return self.fail_with_resp();
                }

                if &data[4..8] == "\x00\x00\x00\x01".as_bytes() {
                    self.target_addr = Some(match Self::parse_socks4a_domain(data) {
                        Some(domain) => NetAddr::new_width_domain(
                            domain,
                            (data[2] as u16) << 8 | data[3] as u16,
                        ),
                        None => return self.fail_with_resp(),
                    });
                } else {
                    self.target_addr = Some(NetAddr::new_with_ip(
                        IpAddr::V4(Ipv4Addr::new(data[4], data[5], data[6], data[7])),
                        (data[2] as u16) << 8 | data[3] as u16,
                    ));
                }

                self.state = InternalParseState::Connected;
                return ParseState::ReceivedRequest(self.target_addr.as_ref().unwrap());
            }

            // Socks5
            // at least 5 data is need to identify a valid Socks5 CONNECT fail_with_response
            if data_len <= 4 {
                return self.fail_with_resp();
            }

            if !data.starts_with("\x05\x01\x00".as_bytes()) {
                debug!("error request: {:x?}", &data[..min(10, data_len)]);
                return self.fail_with_resp();
            }

            let target_addr = match data[3] {
                1u8 => {
                    // <4-byte header> + <4-byte IP> + <2-byte port>
                    if data_len == 4 + 4 + 2 {
                        Some(NetAddr::new_with_ip(
                            IpAddr::V4(Ipv4Addr::new(data[4], data[5], data[6], data[7])),
                            (data[8] as u16) << 8 | data[9] as u16,
                        ))
                    } else {
                        None
                    }
                }
                3u8 => {
                    // // domain name
                    // // <4-byte header> + <1-byte domain length> + <N-byte domain> + <2-byte port>
                    let domain_len = data[4] as usize;
                    if domain_len > 0 && data_len == 4 + 1 + domain_len + 2 {
                        let domain_start = 5;
                        if let Ok(domain) =
                            std::str::from_utf8(&data[domain_start..(domain_start + domain_len)])
                        {
                            let port_index = domain_start + domain_len;
                            Some(NetAddr::new(
                                domain,
                                (data[port_index] as u16) << 8 | data[port_index + 1] as u16,
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                4u8 => {
                    // // ipv6
                    // // <4-byte header> + <16-byte IP> + <2-byte port>
                    if data_len == 4 + 16 + 2 {
                        Some(NetAddr::new_with_ip(
                            IpAddr::V6(Ipv6Addr::new(
                                (data[4] as u16) << 8 | data[5] as u16,
                                (data[6] as u16) << 8 | data[7] as u16,
                                (data[8] as u16) << 8 | data[9] as u16,
                                (data[10] as u16) << 8 | data[11] as u16,
                                (data[12] as u16) << 8 | data[13] as u16,
                                (data[14] as u16) << 8 | data[15] as u16,
                                (data[16] as u16) << 8 | data[17] as u16,
                                (data[18] as u16) << 8 | data[19] as u16,
                            )),
                            (data[20] as u16) << 8 | data[21] as u16,
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if !target_addr.is_some() {
                error!("unexpected socks5 request");
                return self.fail_with_resp();
            }

            self.target_addr = target_addr;
            self.state = InternalParseState::Connected;
            return ParseState::ReceivedRequest(self.target_addr.as_ref().unwrap());
        }

        ParseState::Pending
    }

    async fn handle(
        &self,
        outbound_type: OutboundType,
        outbound_stream: &mut TcpStream,
        inbound_stream: &mut TcpStream,
    ) -> Result<(), ProxyError> {
        match outbound_type {
            OutboundType::Direct => self.reply_connected(inbound_stream, true).await,

            OutboundType::HttpProxy => {
                HttpReq::handshake(outbound_stream, self.extract_target_addr()?).await?;
                self.reply_connected(inbound_stream, true).await
            }

            OutboundType::SocksProxy(ver) => {
                SocksReq::handshake(ver, outbound_stream, self.extract_target_addr()?).await?;
                self.reply_connected(inbound_stream, true).await
            }
        }
    }

    async fn handle_outbound_failure(
        &self,
        inbound_stream: &mut TcpStream,
    ) -> Result<(), ProxyError> {
        self.reply_connected(inbound_stream, false).await
    }
}
