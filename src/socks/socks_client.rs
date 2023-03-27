use anyhow::Result;
use log::error;
use rs_utilities::ByteBuffer;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;

use crate::{utils, NetAddr, ProxyError};

use super::{
    socks_resp_parser::{self, SocksRespParser},
    SocksVersion,
};

pub struct SocksClient {}

impl SocksClient {
    pub async fn build_socks_connection(
        socks_version: SocksVersion,
        socks_server_addr: &SocketAddr,
        dst_addr: NetAddr,
    ) -> Result<TcpStream, ProxyError> {
        let mut stream = TcpStream::connect(socks_server_addr).await.map_err(|e| {
            error!("failed to connect: {}", e);
            ProxyError::ConnectionRefused
        })?;

        let ip = dst_addr.host.parse::<IpAddr>();
        let mut resp_parser = SocksRespParser::new(socks_version);
        let mut buf = [0u8; 512];
        loop {
            match *resp_parser.state() {
                socks_resp_parser::State::IdentifyMethod => {
                    utils::write_to_stream(&mut stream, "\x05\x01\x00".as_ref()).await?;
                }

                socks_resp_parser::State::Connect => {
                    let mut connect_command = ByteBuffer::<512>::new();
                    if *resp_parser.socks_version() == SocksVersion::V5 {
                        connect_command.append("\x05\x01\x00".as_ref());
                        if let Ok(ip) = ip {
                            match ip {
                                IpAddr::V4(ipv4) => {
                                    connect_command.append_byte('\x01' as u8);
                                    connect_command.append(&ipv4.octets());
                                    connect_command.append(&dst_addr.port.to_be_bytes());
                                }
                                IpAddr::V6(ipv6) => {
                                    connect_command.append_byte('\x04' as u8);
                                    connect_command.append(&ipv6.octets());
                                    connect_command.append(&dst_addr.port.to_be_bytes());
                                }
                            }
                        } else {
                            // domain name
                            let domain_name = dst_addr.host.as_bytes();
                            connect_command.append_byte('\x03' as u8);
                            connect_command.append_byte(domain_name.len() as u8);
                            connect_command.append(domain_name);
                            connect_command.append(&dst_addr.port.to_be_bytes());
                        }
                    } else {
                        connect_command.append("\x04\x01".as_ref());
                        if let Ok(ip) = ip {
                            match ip {
                                IpAddr::V4(ipv4) => {
                                    connect_command.append(&dst_addr.port.to_be_bytes());
                                    connect_command.append(&ipv4.octets());
                                }
                                IpAddr::V6(_) => {
                                    return Err(ProxyError::IPv6NotSupported);
                                }
                            }
                        } else {
                            return Err(ProxyError::DomainNameNotSupported);
                        }
                    }

                    utils::write_to_stream(&mut stream, connect_command.as_bytes()).await?;
                }
                _ => {}
            }

            let read_len = utils::read_from_stream(&mut stream, &mut buf).await?;
            if !resp_parser.advance(&buf[..read_len]) {
                error!("connect failed: {:?}", resp_parser.state());
                return Err(ProxyError::InternalError);
            }

            if resp_parser.state() == &socks_resp_parser::State::NegotiationCompleted {
                break;
            }
        }

        Ok(stream)
    }
}
