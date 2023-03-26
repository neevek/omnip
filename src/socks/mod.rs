pub(crate) mod socks_client;
mod socks_resp_parser;

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
