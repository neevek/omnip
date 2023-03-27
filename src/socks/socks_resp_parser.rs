use std::cmp::min;

use log::{debug, error};
use rs_utilities::ByteBuffer;

use super::{SocksError, SocksVersion};

#[derive(PartialEq, Debug)]
pub(crate) enum State {
    IdentifyMethod,
    IdentifyingMethod,
    Connect,
    Connecting,
    NegotiationCompleted,
    ErrorOccurred(SocksError),
}

pub(crate) struct SocksRespParser {
    socks_version: SocksVersion,
    state: State,
    buffer: ByteBuffer<512>,
}

impl SocksRespParser {
    pub fn new(socks_version: SocksVersion) -> Self {
        SocksRespParser {
            socks_version: socks_version.clone(),
            state: if socks_version == SocksVersion::V5 {
                State::IdentifyMethod
            } else {
                State::Connect
            },
            buffer: ByteBuffer::new(),
        }
    }

    pub fn socks_version(&self) -> &SocksVersion {
        &self.socks_version
    }

    pub fn advance(&mut self, buf: &[u8]) -> bool {
        if let State::ErrorOccurred(_) = self.state {
            return false;
        }

        if self.buffer.remaining() < buf.len() || !self.buffer.append(buf) {
            error!("unexpected large buffer: {}", self.buffer.len() + buf.len());
            return self.fail_with_general_error();
        }

        if self.state == State::IdentifyMethod {
            self.state = State::IdentifyingMethod;
            if self.buffer.len() != 2 {
                error!("unexpected socks response length: {}", self.buffer.len());
                return self.fail_with_general_error();
            }

            let bytes = self.buffer.as_bytes();
            if self.socks_version == SocksVersion::V5 {
                if bytes != "\x05\x00".as_bytes() {
                    error!("unexpected socks5 response code: {}", bytes[1]);
                    return self.fail_with_general_error();
                }
                self.state = State::Connect;
                self.buffer.clear();
                return true;
            }
        }

        if self.state == State::Connect {
            self.state = State::Connecting;
            let bytes = self.buffer.as_bytes();
            let resp_size = bytes.len();

            // exact 8 bytes for a Socks4 CONNECT response
            if self.socks_version == SocksVersion::V4 {
                if resp_size != 8 {
                    error!("unexpected socks4 response length: {}", resp_size);
                    return self.fail_with_general_error();
                }

                if !bytes.starts_with("\x00\x5a".as_bytes()) {
                    error!("unexpected socks4 response code: {}", bytes[1]);
                    return self.fail_with_general_error();
                }

                // the DSTPORT and DSTIP fields will be silently ignored

                self.state = State::NegotiationCompleted;
                return true;
            }

            // Socks5
            // at least 5 bytes is need to identify a valid Socks5 CONNECT response
            if resp_size > 4 {
                if !bytes.starts_with("\x05\x00\x00".as_bytes()) {
                    self.state = match bytes[1] {
                        1u8 => State::ErrorOccurred(SocksError::GeneralError),
                        2u8 => State::ErrorOccurred(SocksError::V5ConnectionNotAllowed),
                        3u8 => State::ErrorOccurred(SocksError::V5NetworkUnreachable),
                        4u8 => State::ErrorOccurred(SocksError::V5HostUnreachable),
                        5u8 => State::ErrorOccurred(SocksError::V5ConnectionRefused),
                        6u8 => State::ErrorOccurred(SocksError::V5TTLExpired),
                        7u8 => State::ErrorOccurred(SocksError::V5CommandNotSupported),
                        8u8 => State::ErrorOccurred(SocksError::V5AddressTypeNotSupported),
                        _ => State::ErrorOccurred(SocksError::V5Unassigned),
                    };
                    debug!("error response: {:x?}", &bytes[..min(10, resp_size)]);
                    return self.fail_with_general_error();
                }

                // The BND.ADDR field indicates the IP address of the network interface
                // on the SOCKS server that was used to establish the outbound connection
                // to the destination host. This does not affect the connection between
                // the SOCKS client and the SOCKS server itself. The connection between
                // the SOCKS client and the SOCKS server remains the same.
                // The purpose of the BND.ADDR field is to allow the client to know the
                // specific network path that was used to establish the connection to the
                // destination host. This information may be useful for troubleshooting
                // or network analysis purposes.
                //
                // So we will simply drain and ignore the rest of this the Socks5 response
                // so that we have a clean connection for later streaming

                let completed = match bytes[3] {
                    1u8 => {
                        // <4-byte header> + <4-byte IP> + <2-byte port>
                        resp_size == 4 + 4 + 2
                    }
                    3u8 => {
                        // domain name
                        let domain_name_len = bytes[4];
                        // <4-byte header> + <1-byte domain length> + <N-byte domain> + <2-byte port>
                        resp_size == (4 + 1 + domain_name_len + 2) as usize
                    }
                    4u8 => {
                        // ipv6
                        // <4-byte header> + <16-byte IP> + <2-byte port>
                        resp_size == 4 + 16 + 2
                    }
                    _ => false,
                };

                if completed {
                    self.state = State::NegotiationCompleted;
                } else {
                    error!("unexpected socks5 response");
                    self.state = State::ErrorOccurred(SocksError::GeneralError);
                }

                return completed;
            }
        }

        true
    }

    fn fail_with_general_error(&mut self) -> bool {
        self.state = State::ErrorOccurred(SocksError::GeneralError);
        false
    }

    pub fn state(&self) -> &State {
        &self.state
    }
}
