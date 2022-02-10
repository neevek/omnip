use log::{debug, error};
use std::collections::HashMap;
use url::Url;

pub struct HttpRequest {
    method: String,
    url: String,
    version: String,
    headers: HashMap<String, String>,
    pub header_len: usize,
}

impl HttpRequest {
    pub fn is_connect_request(&self) -> bool {
        self.method.starts_with("CONNECT")
    }

    pub fn get_request_addr(&self) -> Option<String> {
        if self.is_connect_request() {
            // url is the address, host:port is assumed
            return Some(self.url.clone());
        }

        debug!("will parse url first: {}", self.url);
        let url = Url::parse(&self.url);
        if let Some(url) = url.ok() {
            if url.scheme().starts_with("http") {
                let addr: String;
                if let Some(port) = url.port() {
                    addr = format!("{}:{}", url.host_str()?, port).to_string();
                } else {
                    addr = format!(
                        "{}:{}",
                        url.host_str()?,
                        if url.scheme().starts_with("https") {
                            443
                        } else {
                            80
                        }
                    )
                    .to_string();
                }

                return Some(addr);
            }
        }

        if let Some(host) = self.headers.get("host") {
            let start_pos = if let Some(ipv6_end_bracket_pos) = host.rfind("]") {
                ipv6_end_bracket_pos
            } else {
                0
            };

            if host[start_pos..].find(":").is_some() {
                return Some(host.to_string());
            }
        }
        error!("invalid request");
        None
    }
}

pub fn parse(buffer: &str) -> Option<HttpRequest> {
    let request_text = find_http_request_text(buffer)?;

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
        version: version.to_string(),
        headers,
        header_len: buffer.len() + 4, // 4 for the trailing \r\n\r\n
    });
}

fn find_http_request_text(buffer: &str) -> Option<&str> {
    let len = buffer.len();
    if len < 4 {
        return None;
    }

    let mut chars = buffer.chars();
    if chars.nth(len - 1) == Some('\n')
        && chars.nth(len - 2) == Some('\r')
        && chars.nth(len - 3) == Some('\n')
        && chars.nth(len - 4) == Some('\r')
    {
        return Some(&buffer[..len]);
    }

    if let Some(len) = buffer.find("\r\n\r\n") {
        return Some(&buffer[..len]);
    }

    None
}
