use std::{
    cmp::min,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use log::{debug, error};

use crate::NetAddr;

use super::{SocksError, SocksVersion};

#[derive(PartialEq, Debug)]
pub(crate) enum State {
    IdentifyMethod,
    WaitForConnect,
    NegotiationCompleted,
    ErrorOccurred(SocksError),
}

pub(crate) struct SocksReqParser<'a> {
    socks_version: SocksVersion,
    server_addr: &'a SocketAddr,
    state: State,
    net_addr: Option<NetAddr>,
}

impl<'a> SocksReqParser<'a> {
    pub fn new(socks_version: SocksVersion, server_addr: &'a SocketAddr) -> Self {
        SocksReqParser {
            socks_version: socks_version.clone(),
            server_addr,
            state: if socks_version == SocksVersion::V5 {
                State::IdentifyMethod
            } else {
                State::WaitForConnect
            },
            net_addr: None,
        }
    }

    pub fn advance(&mut self, buf: &[u8]) -> bool {
        if let State::ErrorOccurred(_) = self.state {
            return false;
        }

        let buf_len = buf.len();
        if self.state == State::IdentifyMethod {
            if buf_len != 3 {
                error!(
                    "unexpected socks request length: {}, only \"No Authentication\" (\\x05\\x01\\x00) is supported.",
                    buf_len
                );
                return self.fail_with_general_error();
            }

            if self.socks_version == SocksVersion::V5 {
                // supports CONNECT only
                if buf != "\x05\x01\x00".as_bytes() {
                    error!("method not supported: {}", buf[1]);
                    return self.fail_with_general_error();
                }
                self.state = State::WaitForConnect;
                return true;
            }
        }

        if self.state == State::WaitForConnect {
            if self.socks_version == SocksVersion::V4 {
                if buf_len < 8 {
                    return self.fail_with_general_error();
                }
                // supports CONNECT only
                if !buf.starts_with("\x04\x01".as_bytes()) {
                    debug!("error request: {:x?}", &buf[..min(10, buf_len)]);
                    return self.fail_with_general_error();
                }

                self.net_addr = Some(NetAddr::new_with_ip(
                    IpAddr::V4(Ipv4Addr {
                        octets: buf[4..7].try_into().unwrap(),
                    }),
                    (buf[2] << 8 | buf[3]) as u16,
                ));

                if buf_len > 8 {
                    debug!(
                        "userid of the CONNECT requiest is ignored: {:x?}",
                        [buf_len..min(buf_len - 9, 10)]
                    );
                }

                self.state = State::NegotiationCompleted;
                return true;
            }

            // Socks5
            // at least 5 buf is need to identify a valid Socks5 CONNECT response
            if buf_len <= 4 {
                return self.fail_with_general_error();
            }

            if !buf.starts_with("\x05\x01\x00".as_bytes()) {
                debug!("error request: {:x?}", &buf[..min(10, buf_len)]);
                return self.fail_with_general_error();
            }

            self.net_addr = match buf[3] {
                1u8 => {
                    // <4-byte header> + <4-byte IP> + <2-byte port>
                    if buf_len == 4 + 4 + 2 {
                        Some(NetAddr::new_with_ip(
                            IpAddr::V4(Ipv4Addr {
                                octets: buf[4..7].try_into().unwrap(),
                            }),
                            (buf[8] << 8 | buf[9]) as u16,
                        ))
                    } else {
                        None
                    }
                }
                3u8 => {
                    // // domain name
                    // // <4-byte header> + <1-byte domain length> + <N-byte domain> + <2-byte port>
                    let domain_len = buf[4] as usize;
                    if domain_len > 0 && buf_len == 4 + 1 + domain_len + 2 {
                        if let Ok(domain) = std::str::from_utf8(&buf[5..domain_len]) {
                            let port_index = 5 + domain_len;
                            Some(NetAddr::new(
                                domain,
                                (buf[port_index] << 8 | buf[port_index + 1]) as u16,
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
                    if buf_len == 4 + 16 + 2 {
                        Some(NetAddr::new_with_ip(
                            IpAddr::V6(Ipv6Addr {
                                octets: buf[4..19].try_into().unwrap(),
                            }),
                            (buf[20] << 8 | buf[21]) as u16,
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if self.net_addr.is_some() {
                self.state = State::NegotiationCompleted;
            } else {
                error!("unexpected socks5 request");
                return self.fail_with_general_error();
            }

            return self.net_addr.is_some();
        }

        true
    }

    fn fail_with_general_error(&self) -> bool {
        self.state = State::ErrorOccurred(SocksError::GeneralError);
        false
    }
}
