use log::{error, warn};
use rs_utilities::ByteBuffer;

use super::SocksVersion;

#[derive(PartialEq, Debug)]
pub(crate) enum SocksError {
    GeneralError,
    V5ConnectionNotAllowed,
    V5NetworkUnreachable,
    V5HostUnreachable,
    V5ConnectionRefused,
    V5TTLExpired,
    V5CommandNotSupported,
    V5AddressTypeNotSupported,
    V5Unassigned,
}

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
    total_bytes: usize,
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
            total_bytes: 0,
        }
    }

    pub fn socks_version(&self) -> &SocksVersion {
        &self.socks_version
    }

    pub fn advance(&mut self, buf: &[u8]) -> bool {
        if let State::ErrorOccurred(_) = self.state {
            return false;
        }

        self.total_bytes += buf.len();
        if self.buffer.remaining() < buf.len() || !self.buffer.append(buf) {
            error!("response too large: {}", self.buffer.len() + buf.len());
            self.state = State::ErrorOccurred(SocksError::GeneralError);
            return false;
        }

        if self.state == State::IdentifyMethod {
            self.state = State::IdentifyingMethod;
            if self.buffer.len() < 2 {
                // wait for more bytes to come
                return true;
            }

            let bytes = &self.buffer.as_bytes();
            if self.socks_version == SocksVersion::V5 {
                if !bytes.starts_with("\x05\x00".as_bytes()) {
                    self.state = State::ErrorOccurred(SocksError::GeneralError);
                    return false;
                }
                self.state = State::Connect;
                self.buffer.clear();
                return true;
            }
        }

        if self.state == State::Connect {
            self.state = State::Connecting;
            let bytes = &self.buffer.as_bytes();
            let resp_size = bytes.len();

            // exact 8 bytes for a Socks4 CONNECT response
            if self.socks_version == SocksVersion::V4 {
                if resp_size < 8 {
                    // wait for more bytes to come
                    return true;
                }

                if !bytes.starts_with("\x00\x5a".as_bytes()) {
                    self.state = State::ErrorOccurred(SocksError::GeneralError);
                    return false;
                }

                if resp_size > 8 {
                    warn!("Socks4 CONNECT response is not exact 8 bytes!");
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
                    return false;
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
                        resp_size >= 4 + 4 + 2
                    }
                    3u8 => {
                        // domain name
                        let domain_name_len = bytes[4];
                        // <4-byte header> + <1-byte domain length> + <N-byte domain> + <2-byte port>
                        resp_size >= (4 + 1 + domain_name_len + 2) as usize
                    }
                    4u8 => {
                        // ipv6
                        // <4-byte header> + <16-byte IP> + <2-byte port>
                        resp_size >= 4 + 16 + 2
                    }
                    _ => {
                        self.state = State::ErrorOccurred(SocksError::GeneralError);
                        return false;
                    }
                };

                if completed {
                    self.state = State::NegotiationCompleted;
                } else {
                    // wait for more input
                }

                return true;
            }
        }

        true
    }

    pub fn state(&self) -> &State {
        &self.state
    }
}
