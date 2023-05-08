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

static WEB_SOURCE_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rsproxy-web.blob"));
const WEB_PREFIX: &'static str = "/web";

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

type RequestHandler = fn(&DashboardService, req: &Request<Body>) -> Response<Full<Bytes>>;
type RequestHandlersMap = HashMap::<&'static str, RequestHandler>;

struct DashboardService {
    _api: Arc<dyn Api>,
    req_handlers_map: RequestHandlersMap,
}

impl DashboardService {
    pub fn new(api: Arc<dyn Api>) -> Self {
        let mut req_handlers_map = HashMap::<&'static str, RequestHandler>::new();
        req_handlers_map.insert("/api/hello", DashboardService::hello);
        DashboardService { _api: api, req_handlers_map }
    }

    fn handle_request(&self, req: &Request<Body>) -> Option<Response<Full<Bytes>>> {
        let path = req.uri().path();
        match self.req_handlers_map.get(path) {
            Some(handler) => Some(handler(&self, req)),
            None => None
        }
    }

    pub fn hello(&self, _req: &Request<Body>) -> Response<Full<Bytes>> {
        let builder = Response::builder().status(200).header("Content-Type", "application/json");
        builder.body(Full::new(Bytes::from(r#"{"key": "value"}"#))).unwrap()
    }
}

impl Service<Request<Body>> for DashboardService {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        fn static_html_resp(
            builder: response::Builder,
            WebSourceCodeItem { filename: _, offset, len }: &WebSourceCodeItem,
        ) -> Response<Full<Bytes>> {
            let content = &WEB_SOURCE_CODE[*offset..(offset + len)];
            builder.body(Full::new(Bytes::from(content))).unwrap()
        }

        let path = req.uri().path();
        let path = if ["/", "/web/", WEB_PREFIX].iter().any(|&p| p == path) {
            "/index.html"
        } else {
            if path.len() > 4 { &path[4..] } else { path }
        };

        let res = match WEB_SOURCE_CODE_MAPPING.get(path) {
            Some(item) => {
                let mime = match mime_guess::from_path(item.filename).first() {
                    Some(t) => t.to_string(),
                    None => "application/octet-stream".to_string(),
                };

                let builder = Response::builder().status(200).header("Content-Type", mime);
                static_html_resp(builder, item)
            }
            None =>  {
                match self.handle_request(&req) {
                    Some(res) => res,
                    None => {
                        let builder = Response::builder().status(404).header("Content-Type", "text/html");
                        let item = WEB_SOURCE_CODE_MAPPING.get("/404.html").unwrap();
                        static_html_resp(builder, item)
                    }
                }
            }
        };

        Box::pin(async { Ok(res) })
    }

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
