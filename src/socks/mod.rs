pub(crate) mod socks_client;
// mod socks_req_parser;
mod socks_resp_parser;
// pub(crate) mod socks_server;

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

#[derive(PartialEq, Clone, Copy)]
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
