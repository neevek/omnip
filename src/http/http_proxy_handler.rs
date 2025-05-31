use crate::{
    proxy_handler::{OutboundType, ParseState, ProxyHandler},
    socks::socks_req::SocksReq,
    utils, NetAddr, PooledBuffer, ProxyError, BUFFER_POOL,
};
use anyhow::Context;
use async_trait::async_trait;
use log::{debug, error};
use rs_utilities::unwrap_or_return;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use url::Url;

use super::{INITIAL_HTTP_HEADER_SIZE, MAX_HTTP_HEADER_SIZE};

const HTTP_RESP_200: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";
const HTTP_RESP_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\r\n";
const HTTP_RESP_413: &[u8] = b"HTTP/1.1 413 Payload Too Large\r\n\r\n";
const HTTP_RESP_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";

pub struct HttpProxyHandler<'a> {
    http_request: Option<HttpRequest<'a>>,
    buffer: Option<PooledBuffer<'a>>,
    parse_done: bool,
}

impl HttpProxyHandler<'_> {
    pub fn new() -> Self {
        HttpProxyHandler {
            http_request: None,
            buffer: None,
            parse_done: false,
        }
    }

    async fn exchange_http_payloads(
        http_request: &HttpRequest<'_>,
        outbound_stream: &mut TcpStream,
        inbound_stream: &mut TcpStream,
    ) -> Result<(), ProxyError> {
        if http_request.is_connect_request() {
            utils::write_to_stream(inbound_stream, HTTP_RESP_200).await?;
        } else {
            let header = std::str::from_utf8(http_request.header())
                .context("failed to convert header as UTF-8 string")
                .map_err(|_| ProxyError::BadRequest)?
                .replace("Proxy-Connection", "Connection")
                .replace("proxy-connection", "Connection");
            utils::write_to_stream(outbound_stream, header.as_bytes()).await?;
        }

        let body = http_request.body();
        if !body.is_empty() {
            utils::write_to_stream(outbound_stream, body).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl ProxyHandler for HttpProxyHandler<'_> {
    fn parse(&mut self, data: &[u8]) -> ParseState {
        if self.parse_done {
            error!("invalid state, never call parse again!");
            return ParseState::FailWithReply((HTTP_RESP_400.into(), ProxyError::BadRequest));
        }

        if data.is_empty() {
            return ParseState::FailWithReply((HTTP_RESP_400.into(), ProxyError::BadRequest));
        }

        if self.buffer.is_none() {
            self.buffer = Some(BUFFER_POOL.alloc(INITIAL_HTTP_HEADER_SIZE));
        }

        let buffer = self.buffer.as_mut().unwrap();
        if buffer.len() + data.len() > MAX_HTTP_HEADER_SIZE {
            return ParseState::FailWithReply((HTTP_RESP_413.into(), ProxyError::PayloadTooLarge));
        }

        buffer.extend_from_slice(data);

        let request_text = unwrap_or_return!(find_http_request_text(buffer), ParseState::Pending);
        let request_text = unwrap_or_return!(
            std::str::from_utf8(request_text).ok(),
            ParseState::FailWithReply((HTTP_RESP_400.into(), ProxyError::BadRequest))
        );

        let parts: Vec<&str> = request_text.split("\r\n").collect();
        if parts.is_empty() {
            return ParseState::FailWithReply((HTTP_RESP_400.into(), ProxyError::BadRequest));
        }

        let request_text_len = request_text.len();
        let mut method = "";
        let mut url = "";
        let mut version = "";
        let mut headers = vec![];
        for (index, part) in parts.iter().enumerate() {
            if index == 0 {
                let parts: Vec<&str> = part.split(' ').collect();
                if parts.len() != 3 {
                    error!("invalid http request");
                    return ParseState::FailWithReply((
                        HTTP_RESP_400.into(),
                        ProxyError::BadRequest,
                    ));
                }

                method = parts[0];
                url = parts[1];
                version = parts[2];
            } else if let Some(colon_pos) = part.find(':') {
                let k = part[0..colon_pos].trim().to_lowercase();
                let v = part[(colon_pos + 1)..].trim().to_string();
                headers.push((k, v));
            }
        }

        let method = method.to_string();
        let url = url.to_string();
        let version = version.to_string();
        let buffer = self.buffer.take().unwrap();

        self.parse_done = true;
        self.http_request =
            HttpRequest::build(method, url, version, headers, request_text_len, buffer);

        match self.http_request {
            Some(ref http_request) => ParseState::ReceivedRequest(&http_request.outbound_addr),
            None => ParseState::FailWithReply((HTTP_RESP_400.into(), ProxyError::BadRequest)),
        }
    }

    async fn handle(
        &self,
        outbound_type: OutboundType,
        outbound_stream: &mut TcpStream,
        inbound_stream: &mut TcpStream,
    ) -> Result<(), ProxyError> {
        let http_request = unwrap_or_return!(&self.http_request, Err(ProxyError::BadRequest));
        match outbound_type {
            OutboundType::Direct => {
                Self::exchange_http_payloads(http_request, outbound_stream, inbound_stream).await
            }

            OutboundType::HttpProxy => {
                // simply forward the complete http proxy request
                utils::write_to_stream(outbound_stream, http_request.payload()).await
            }

            OutboundType::SocksProxy(ver) => {
                SocksReq::handshake(ver, outbound_stream, &http_request.outbound_addr).await?;
                Self::exchange_http_payloads(http_request, outbound_stream, inbound_stream).await
            }
        }
    }

    async fn handle_outbound_failure(
        &self,
        inbound_stream: &mut TcpStream,
    ) -> Result<(), ProxyError> {
        utils::write_to_stream(inbound_stream, HTTP_RESP_502).await
    }

    async fn reject(&self, inbound_stream: &mut TcpStream) -> Result<(), ProxyError> {
        let http_request = unwrap_or_return!(&self.http_request, Err(ProxyError::BadRequest));
        if http_request.is_connect_request() {
            // we will still politely return OK to the client, and drop the connection
            utils::write_to_stream(inbound_stream, HTTP_RESP_200).await?;
            inbound_stream
                .flush()
                .await
                .context("stream is disconnected while flushing")
                .map_err(ProxyError::Disconnected)
        } else {
            Ok(())
        }
    }
}

fn find_http_request_text(data: &[u8]) -> Option<&[u8]> {
    let len = data.len();
    if len > 4 {
        let start_index = len - 4;
        if &data[start_index..len] == b"\r\n\r\n" {
            return Some(&data[..len]);
        }

        if let Some(start_index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            return Some(&data[..(start_index + 4)]);
        }
    }

    None
}

#[derive(Debug)]
pub(crate) struct HttpRequest<'a> {
    pub method: String,
    _url: String,
    _version: String,
    _headers: Vec<(String, String)>,
    pub header_len: usize,
    pub buffer: PooledBuffer<'a>,
    pub outbound_addr: NetAddr,
    pub header_start_pos: usize,
}

impl<'a> HttpRequest<'a> {
    pub fn build(
        method: String,
        url: String,
        version: String,
        headers: Vec<(String, String)>,
        header_len: usize,
        mut buffer: PooledBuffer<'a>,
    ) -> Option<Self> {
        let (outbound_addr, header_start_pos) = Self::derive_outbound_addr_and_header_start_pos(
            &method,
            &url,
            &headers,
            header_len,
            &mut buffer,
        )?;

        Some(Self {
            method,
            _url: url,
            _version: version,
            _headers: headers,
            header_len,
            buffer,
            outbound_addr,
            header_start_pos,
        })
    }

    fn derive_outbound_addr_and_header_start_pos(
        method: &str,
        url: &str,
        headers: &Vec<(String, String)>,
        header_len: usize,
        buffer: &mut PooledBuffer<'a>,
    ) -> Option<(NetAddr, usize)> {
        let mut addr = None;
        let is_connect_request = method.starts_with("CONNECT");
        let mut has_host = false;
        if is_connect_request {
            // url is the address, host:port is assumed
            addr = Some(url);
        } else if let Some(host) = Self::find_host(headers) {
            // host is the address, host:port is assumed
            addr = Some(host);
            has_host = true;
        }

        // strip the scheme://host part of the url, for example:
        // GET http://example.com/test/index.html
        // to
        // GET /test/index.html
        let mut start_pos = 0;
        if has_host && url.starts_with("http") {
            let method_len = method.len();
            let skip_len = if url.starts_with("https") {
                method_len + 9 // 9 for the string " https://"
            } else {
                method_len + 8 // 8 for the string " http://"
            };

            let header_text = &mut buffer[..header_len];
            if let Some(mut slash_pos) = header_text
                .iter()
                .skip(skip_len)
                .position(|&c| c == b'/' || c == b' ')
            {
                slash_pos += skip_len;
                if header_text[slash_pos] == b'/' {
                    start_pos = slash_pos - method_len - 1; // - 1 for the space after METHOD
                    header_text[start_pos..(start_pos + method_len)]
                        .copy_from_slice(method.as_bytes());
                    header_text[slash_pos - 1] = b' ';
                }
            }
        }

        if let Some(addr) = addr {
            let ipv6_end_bracket_pos = addr.rfind(']').unwrap_or(0);
            let mut port = None;
            let mut host_start_pos = 0;
            let mut host_end_pos;
            if let Some(pos) = addr[ipv6_end_bracket_pos..].find(':') {
                port = addr[(pos + 1)..].parse().ok();
                host_end_pos = pos;
            } else {
                host_end_pos = addr.len();
            }

            if ipv6_end_bracket_pos > 0 {
                // exclude the square brackets
                host_start_pos = 1;
                host_end_pos = ipv6_end_bracket_pos;
            }
            let host = &addr[host_start_pos..host_end_pos];

            if port.is_none() {
                port = if url.starts_with("https") {
                    Some(443)
                } else {
                    Some(80)
                }
            }

            return Some((NetAddr::new(host, port.unwrap()), start_pos));
        }

        debug!("will parse url first: {}", url);
        let url = Url::parse(url);
        if let Ok(url) = url {
            if url.scheme().starts_with("http") {
                let mut host = url.host_str()?;
                if host.is_empty() {
                    error!("invalid request: {}", url);
                    return None;
                }
                if host.as_bytes().first().unwrap_or(&b' ') == &b'[' {
                    host = &host[1..(host.len() - 1)];
                }
                let mut port = url.port().unwrap_or(0);
                if port == 0 {
                    port = if url.scheme().starts_with("https") {
                        443
                    } else {
                        80
                    }
                }

                return Some((NetAddr::new(host, port), start_pos));
            }
        }

        error!("invalid request");
        None
    }

    fn find_host(headers: &Vec<(String, String)>) -> Option<&str> {
        for (k, v) in headers {
            if k == "Host" || k == "host" {
                return Some(v);
            }
        }
        None
    }

    pub fn is_connect_request(&self) -> bool {
        self.method.starts_with("CONNECT")
    }

    /// return the complete HTTP header text, including the trailing \r\n\r\n
    pub fn header(&self) -> &[u8] {
        &self.buffer[self.header_start_pos..self.header_len]
    }

    /// return the HTTP body
    pub fn body(&self) -> &[u8] {
        &self.buffer[self.header_len..]
    }

    /// return the entire request payload
    pub fn payload(&self) -> &[u8] {
        &self.buffer[self.header_start_pos..]
    }
}
