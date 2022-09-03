use crate::NetAddr;
use log::{debug, error};
use std::collections::HashMap;
use url::Url;

pub struct HttpRequest {
    method: String,
    url: String,
    _version: String,
    headers: HashMap<String, String>,
    pub header_len: usize,
}

impl HttpRequest {
    pub fn is_connect_request(&self) -> bool {
        self.method.starts_with("CONNECT")
    }

    pub fn get_request_addr(&self) -> Option<NetAddr> {
        //let host;
        let mut addr = None;
        if self.is_connect_request() {
            // url is the address, host:port is assumed
            addr = Some(self.url.as_str());
        } else if let Some(host) = self.headers.get("host") {
            // host is the address, host:port is assumed
            addr = Some(host);
        }

        if let Some(addr) = addr {
            let start_pos = if let Some(ipv6_end_bracket_pos) = addr.rfind("]") {
                ipv6_end_bracket_pos + 1
            } else {
                0
            };

            let host;
            let mut port = None;
            if let Some(pos) = addr[start_pos..].find(":") {
                host = addr[..pos].to_string();
                port = addr[(pos + 1)..].parse().ok();
            } else {
                host = addr.to_string();
            }

            if let None = port {
                port = if self.url.starts_with("https") {
                    Some(443)
                } else {
                    Some(80)
                }
            }

            return Some(NetAddr {
                host,
                port: port.unwrap(),
            });
        }

        debug!("will parse url first: {}", self.url);
        let url = Url::parse(&self.url);
        if let Some(url) = url.ok() {
            if url.scheme().starts_with("http") {
                let host = url.host_str()?.to_string();
                let mut port = url.port().unwrap_or(0);
                if port == 0 {
                    port = if url.scheme().starts_with("https") {
                        443
                    } else {
                        80
                    }
                }

                return Some(NetAddr { host, port });
            }
        }

        error!("invalid request");
        None
    }
}

pub fn parse(buffer: &[u8]) -> Option<HttpRequest> {
    let request_text = find_http_request_text(buffer)?;
    let request_text = std::str::from_utf8(&request_text).ok()?;

    let parts: Vec<&str> = request_text.split("\r\n").collect();
    if parts.is_empty() {
        return None;
    }

    let mut method = "";
    let mut url = "";
    let mut version = "";
    let mut headers = HashMap::<String, String>::new();
    for (index, part) in parts.iter().enumerate() {
        if index == 0 {
            let parts: Vec<&str> = part.split(" ").collect();
            if parts.len() != 3 {
                error!("invalid http request");
                return None;
            }

            method = parts[0];
            url = parts[1];
            version = parts[2];
        } else {
            if let Some(colon_pos) = part.find(":") {
                let k = part[0..colon_pos].trim().to_lowercase();
                let v = part[(colon_pos + 1)..].trim().to_string();
                headers.insert(k, v);
            }
        }
    }

    return Some(HttpRequest {
        method: method.to_string(),
        url: url.to_string(),
        _version: version.to_string(),
        headers,
        header_len: request_text.len(),
    });
}

fn find_http_request_text(buffer: &[u8]) -> Option<&[u8]> {
    let len = buffer.len();
    if len > 4 {
        let start_index = len - 4;
        if &buffer[start_index..len] == b"\r\n\r\n" {
            return Some(&buffer[..len]);
        }

        if let Some(start_index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            return Some(&buffer[..(start_index + 4)]);
        }
    }

    None
}
