use anyhow::Result;
use log::error;
use rs_utilities::Utils;
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

        Self::start_negotiation(socks_version, &mut stream, dst_addr).await?;
        Ok(stream)
    }

    async fn start_negotiation(
        socks_version: SocksVersion,
        stream: &mut TcpStream,
        dst_addr: NetAddr,
    ) -> Result<(), ProxyError> {
        let ip = dst_addr.host.parse::<IpAddr>();
        let mut resp_parser = SocksRespParser::new(socks_version);
        let mut buf = [0u8; 512];
        loop {
            match *resp_parser.state() {
                socks_resp_parser::State::IdentifyMethod => {
                    utils::write_to_stream(stream, "\x05\x01\x00".as_ref()).await?;
                }

                socks_resp_parser::State::Connect => {
                    let mut connect_command = [0u8; 512]; // <4-byte header> + <16-byte IPv6> + <2-byte port>
                    let connect_command_len;
                    if *resp_parser.socks_version() == SocksVersion::V5 {
                        Utils::copy_slice(&mut connect_command, "\x05\x01\x00".as_ref());
                        if let Ok(ip) = ip {
                            match ip {
                                IpAddr::V4(ipv4) => {
                                    connect_command[3] = 1u8;
                                    Utils::copy_slice(&mut connect_command[4..], &ipv4.octets());
                                    Utils::copy_slice(
                                        &mut connect_command[8..],
                                        &dst_addr.port.to_be_bytes(),
                                    );
                                    connect_command_len = 10;
                                }
                                IpAddr::V6(ipv6) => {
                                    connect_command[3] = 4u8;
                                    Utils::copy_slice(&mut connect_command[4..], &ipv6.octets());
                                    Utils::copy_slice(
                                        &mut connect_command[20..],
                                        &dst_addr.port.to_be_bytes(),
                                    );
                                    connect_command_len = 22;
                                }
                            }
                        } else {
                            // domain name
                            connect_command[3] = 3u8;
                            connect_command[4] = dst_addr.host.len() as u8;
                            Utils::copy_slice(&mut connect_command[5..], dst_addr.host.as_bytes());
                            Utils::copy_slice(
                                &mut connect_command[(5 + dst_addr.host.len())..],
                                &dst_addr.port.to_be_bytes(),
                            );
                            connect_command_len = 5 + dst_addr.host.len() + 2;
                        }
                    } else {
                        Utils::copy_slice(&mut connect_command, "\x04\x01".as_ref());
                        if let Ok(ip) = ip {
                            match ip {
                                IpAddr::V4(ipv4) => {
                                    Utils::copy_slice(
                                        &mut connect_command[2..],
                                        &dst_addr.port.to_be_bytes(),
                                    );
                                    Utils::copy_slice(&mut connect_command[4..], &ipv4.octets());
                                    connect_command_len = 8;
                                }
                                IpAddr::V6(_) => {
                                    return Err(ProxyError::IPv6NotSupported);
                                }
                            }
                        } else {
                            return Err(ProxyError::DomainNameNotSupported);
                        }
                    }

                    utils::write_to_stream(stream, connect_command[..connect_command_len].as_ref())
                        .await?;
                }
                _ => {}
            }

            let read_len = utils::read_from_stream(stream, &mut buf).await?;
            if !resp_parser.advance(&buf[..read_len]) {
                error!("connect failed: {:?}", resp_parser.state());
                return Err(ProxyError::InternalError);
            }

            if resp_parser.state() == &socks_resp_parser::State::NegotiationCompleted {
                break;
            }
        }

        Ok(())
    }
}
