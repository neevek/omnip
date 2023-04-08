use log::error;
use rs_utilities::ByteBuffer;
use std::net::{IpAddr, SocketAddr};
pub(crate) mod socks_proxy_handler;
pub(crate) mod socks_req;
mod socks_resp_parser;

pub type RespData = Vec<u8>;

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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SocksVersion {
    V4,
    V5,
}

#[allow(unused)]
pub(crate) enum SocksMethod {
    // I choose not to suport GSSAPI and basic Username/Password authentications.
    // For being secure, other protocols are supposed to be used instead of SocksV4/5.
    NoAuthentication,
    NoAcceptableMethods,
}

#[allow(unused)]
pub(crate) enum RequestType {
    Connect,
    Bind,
    UDPAssociate,
}

#[allow(unused)]
pub(crate) enum AddressType {
    Unknown,
    IPv4,
    DomainName,
    IPv6,
}

fn socks_reply(socks_version: SocksVersion, bnd_addr: SocketAddr, is_fail: bool) -> RespData {
    // <4-byte header> + <16-byte IP> + <2-byte port>
    const MAX_RESPONSE_LENGTH: usize = 22;
    let mut resp = ByteBuffer::<MAX_RESPONSE_LENGTH>::new();
    match socks_version {
        SocksVersion::V4 => {
            if is_fail {
                resp.append("\x00\x5b".as_bytes());
            } else {
                resp.append("\x00\x5a".as_bytes());
            }
            resp.append(bnd_addr.port().to_be_bytes().as_ref());

            match bnd_addr.ip() {
                IpAddr::V4(ip) => {
                    resp.append(ip.octets().as_ref());
                }
                IpAddr::V6(ip) => {
                    error!("SOCKS4 doesn't support IPv6: {}", ip);
                    resp.append("\x00\x00\x00\x00".as_bytes());
                }
            }
        }
        SocksVersion::V5 => {
            if is_fail {
                resp.append("\x05\x01\x00".as_bytes());
            } else {
                resp.append("\x05\x00\x00".as_bytes());
            }

            match bnd_addr.ip() {
                IpAddr::V4(ip) => {
                    resp.append_byte(0x01);
                    resp.append(ip.octets().as_ref());
                }
                IpAddr::V6(ip) => {
                    resp.append_byte(0x04);
                    resp.append(ip.octets().as_ref());
                }
            }

            resp.append(bnd_addr.port().to_be_bytes().as_ref());
        }
    }

    resp.as_bytes().into()
}
