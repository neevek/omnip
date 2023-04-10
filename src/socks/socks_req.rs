use anyhow::Result;
use log::error;
use rs_utilities::ByteBuffer;
use std::net::IpAddr;
use tokio::net::TcpStream;

use crate::{utils, Host, NetAddr, ProxyError};

use super::{
    socks_resp_parser::{SocksRespParser, State},
    SocksVersion,
};

pub struct SocksReq {}

impl SocksReq {
    pub async fn handshake(
        socks_version: SocksVersion,
        outbound_stream: &mut TcpStream,
        dst_addr: &NetAddr,
    ) -> Result<(), ProxyError> {
        let mut resp_parser = SocksRespParser::new(socks_version);
        let mut buf = [0u8; 512];
        loop {
            match *resp_parser.state() {
                State::SelectMethod => {
                    utils::write_to_stream(outbound_stream, "\x05\x01\x00".as_ref()).await?;
                }

                State::Connect => {
                    let mut connect_command = ByteBuffer::<512>::new();
                    match *resp_parser.socks_version() {
                        SocksVersion::V5 => {
                            connect_command.append("\x05\x01\x00".as_ref());
                            match dst_addr.host {
                                Host::IP(ip) => match ip {
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
                                },
                                Host::Domain(ref domain) => {
                                    // domain name
                                    let domain_name = domain.as_bytes();
                                    connect_command.append_byte('\x03' as u8);
                                    connect_command.append_byte(domain_name.len() as u8);
                                    connect_command.append(domain_name);
                                    connect_command.append(&dst_addr.port.to_be_bytes());
                                }
                            }
                        }

                        SocksVersion::V4 => {
                            connect_command.append("\x04\x01".as_ref());
                            match dst_addr.host {
                                Host::IP(IpAddr::V4(ipv4)) => {
                                    connect_command.append(&dst_addr.port.to_be_bytes());
                                    connect_command.append(&ipv4.octets());
                                }
                                // see https://www.openssh.com/txt/socks4a.protocol
                                Host::IP(IpAddr::V6(ipv6)) => {
                                    let ipv6_str = ipv6.to_string();
                                    connect_command.append(&dst_addr.port.to_be_bytes());
                                    connect_command.append("\x00\x00\x00\x01\x00".as_bytes());
                                    connect_command.append(ipv6_str.as_bytes());
                                    connect_command.append_byte(0u8);
                                }
                                Host::Domain(ref domain) => {
                                    connect_command.append(&dst_addr.port.to_be_bytes());
                                    connect_command.append("\x00\x00\x00\x01\x00".as_bytes());
                                    connect_command.append(domain.as_bytes());
                                    connect_command.append_byte(0u8);
                                }
                            }
                        }
                    }

                    utils::write_to_stream(outbound_stream, connect_command.as_bytes()).await?;
                }
                _ => {}
            }

            let read_len = utils::read_from_stream(outbound_stream, &mut buf).await?;
            if !resp_parser.advance(&buf[..read_len]) {
                error!("connect failed: {:?}", resp_parser.state());
                return Err(ProxyError::InternalError);
            }

            if resp_parser.state() == &State::NegotiationCompleted {
                break;
            }
        }

        Ok(())
    }
}
