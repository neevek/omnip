use crate::Api;
use anyhow::Result;
use http::response;
use http_body::Full;
use hyper::{body::Body, body::Bytes, server::conn::Http, service::Service, Request, Response};
use lazy_static::lazy_static;
use log::{debug, error, info};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::{net::SocketAddr, pin::Pin};
use tokio::net::TcpListener;

const WEB_SOURCE_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rsproxy-web.blob"));

lazy_static! {
    static ref WEB_SOURCE_CODE_MAPPING: HashMap<&'static str, WebSourceCodeItem> = {
        const WEB_SOURCE_CODE_INDEX: &str =
            include_str!(concat!(env!("OUT_DIR"), "/rsproxy-web.idx"));

        let mut map = HashMap::new();
        for line in WEB_SOURCE_CODE_INDEX.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();

            let item = WebSourceCodeItem {
                filename: fields[0],
                offset: fields[1].parse().unwrap(),
                len: fields[2].parse().unwrap(),
            };

            debug!("web source: {}", item.filename);

            map.insert(item.filename, item);
        }
        map
    };
}

struct WebSourceCodeItem {
    filename: &'static str,
    offset: usize,
    len: usize,
}

pub struct DashboardServer {}

impl DashboardServer {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn bind(&self, addr: SocketAddr) -> Result<TcpListener> {
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            error!("failed to bind dashboard server on address: {}", addr);
            e
        })?;

        let addr = listener.local_addr().unwrap();
        info!("==========================================================");
        info!("dashboard server bound to: {}", addr);
        info!("==========================================================");
        Ok(listener)
    }

    pub async fn serve_async(&self, listener: TcpListener, api: Arc<dyn Api>) {
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let api = api.clone();
                        tokio::task::spawn(async move {
                            if let Err(err) = Http::new()
                                .serve_connection(stream, DashboardService::new(api))
                                .await
                            {
                                println!("Failed to serve connection: {:?}", err);
                            }
                        });
                    }

                    Err(e) => error!("access server failed, err: {}", e),
                }
            }
        });
    }
}

struct DashboardService {
    _api: Arc<dyn Api>,
}

impl DashboardService {
    pub fn new(api: Arc<dyn Api>) -> Self {
        DashboardService { _api: api }
    }
}

impl Service<Request<Body>> for DashboardService {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&mut self, req: Request<Body>) -> Self::Future {

        fn static_html_resp<F: Fn(response::Builder) -> response::Builder>(
            content: &'static str,
            status: u16,
            cb_with_response_builder: F,
        ) -> Result<Response<Full<Bytes>>, hyper::Error> {
            let builder = Response::builder().status(status);
            let builder = cb_with_response_builder(builder).header("Content-Type", "text/html");
            Ok(builder.body(Full::new(Bytes::from(content))).unwrap())
        }

        // let path = if ["/", "/web", "/web/"].iter().any(|&p| p == path) {
        //     "/web/302.html"
        // } else {
        //     path
        // };

        let path = req.uri().path();
        if path.starts_with("/web/") {
            let subpath = &path[5..];
            if let Some(file) = WEB_SOURCE_CODE_MAPPING.get(subpath) {
                let mime = match mime_guess::from_path(file.filename).first() {
                    Some(t) => t.to_string(),
                    None => "application/octet-stream".to_string(),
                };

                let res = Ok(Response::builder()
                    .status(200)
                    .header("Content-Type", mime)
                    .body(Full::new(Bytes::from(
                        &WEB_SOURCE_CODE[file.offset..(file.offset + file.len)],
                    )))
                    .unwrap());
                return Box::pin(async { res });
            }
        } else {
        }

        let res = match req.uri().path() {
            "/" | "/web" | "/web/" => {
                let content = include_str!("../html/302.html");
                static_html_resp(content, 302, |builder| {
                    builder.header("Location", "/web/index.html")
                })
            }
            _ => {
                let content = include_str!("../html/404.html");
                static_html_resp(content, 404, |builder| builder)
            }
        };

        Box::pin(async { res })
    }

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
