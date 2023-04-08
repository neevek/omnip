use crate::{http::INITIAL_HTTP_HEADER_SIZE, utils, Host, NetAddr, ProxyError, BUFFER_POOL};
use anyhow::anyhow;
use anyhow::Result;
use tokio::net::TcpStream;

pub struct HttpReq {}

impl HttpReq {
    pub async fn handshake<'a>(
        outbound_stream: &mut TcpStream,
        dst_addr: &NetAddr,
    ) -> Result<Vec<u8>, ProxyError> {
        let str_addr = match &dst_addr.host {
            Host::IP(ip) => ip.to_string(),
            Host::Domain(domain) => domain.to_string(),
        };

        let mut buffer = BUFFER_POOL.alloc(INITIAL_HTTP_HEADER_SIZE);
        buffer.extend_from_slice("CONNECT ".as_bytes());
        buffer.extend_from_slice(str_addr.as_bytes());
        buffer.push(':' as u8);
        buffer.extend_from_slice(dst_addr.port.to_string().as_bytes());
        buffer.extend_from_slice(" HTTP/1.1\r\n\r\n".as_bytes());

        utils::write_to_stream(outbound_stream, buffer.as_ref()).await?;

        buffer.clear();

        let partially_read_body_start_index;
        loop {
            let mut tmp_buffer = [0u8; 256];
            let len = utils::read_from_stream(outbound_stream, &mut tmp_buffer).await?;
            buffer.extend_from_slice(&tmp_buffer[..len]);
            let len = buffer.len();
            if len > 4 {
                let start_index = len - 4;
                if &buffer[start_index..len] == b"\r\n\r\n" {
                    partially_read_body_start_index = Some(len);
                    break;
                }

                if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                    partially_read_body_start_index = Some(index + 4);
                    break;
                }
            }
        }

        match partially_read_body_start_index {
            Some(index) => {
                if buffer[..].starts_with("HTTP/1.1 200 OK".as_bytes()) {
                    if index <= buffer.len() {
                        return Ok(Vec::with_capacity(0));
                    } else {
                        return Ok(buffer[index..].into());
                    }
                }
            }
            None => {}
        }

        Err(ProxyError::BadGateway(anyhow!(
            "no valid response from proxy server"
        )))
    }
}
