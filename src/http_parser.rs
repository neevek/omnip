use log::error;
use std::{collections::HashMap, net::SocketAddr};
use url::Url;

pub struct HttpRequest {
    method: String,
    url: String,
    version: String,
    headers: HashMap<String, String>,
}

impl HttpRequest {
    pub fn is_connect_request(&self) -> bool {
        self.method.starts_with("CONNECT")
    }

    pub fn get_socket_addr(&self) -> Option<SocketAddr> {
        let mut host = None;
        if let Some(h) = self.headers.get("host") {
            host = Some(h.to_string());
        }

        if host.is_none() {
            let url = Url::parse(&self.url).ok()?;
            if let Some(port) = url.port() {
                host = Some(format!("{}:{}", url.host_str()?, port));
            } else {
                host = Some(url.host_str()?.to_string());
            }
        } else {
            let start_pos = if let Some(ipv6_end_bracket_pos) = host.as_ref()?.rfind("]") {
                ipv6_end_bracket_pos
            } else {
                0
            };

            if host.as_ref()?[start_pos..].find(":").is_none() {
                host = Some(format!(
                    "{}:{}",
                    host?,
                    if self.url.to_lowercase().starts_with("http://") {
                        80
                    } else {
                        443
                    }
                ));
            }
        }

        // TODO we cannot return SocketAddr here, host may be a domain, which we need to resolve first
        host?.parse().ok()
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
            if part.is_empty() {
                continue;
            }

            let header_key_value: Vec<&str> = part.split(":").collect();
            if header_key_value.len() == 2 {
                headers.insert(
                    header_key_value[1].to_lowercase().to_string(),
                    header_key_value[1].to_string(),
                );
            }
        }
    }

    return Some(HttpRequest {
        method: method.to_string(),
        url: url.to_string(),
        version: version.to_string(),
        headers,
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
