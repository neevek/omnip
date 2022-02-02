use std::net::SocketAddr;

use rsproxy::*;
use url::{ParseError, Url};

fn main() {
    let s = "GET http://demo.com/file.html HTTP/1.1\r\nkey:value\r\nkey2:value2\r\n\r\n";

    let r = http_parser::parse(s).unwrap();
    let sa = r.get_socket_addr().unwrap();
}
