use super::{JsonRequest, JsonResponse};
use crate::api::ServerConfig;
use crate::Api;
use anyhow::Result;
use http::request::Parts;
use http::response;
use hyper::body;
use hyper::{body::Body, body::Bytes, server::conn::Http, service::Service, Request, Response};
use lazy_static::lazy_static;
use log::{debug, error, info};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::{net::SocketAddr, pin::Pin};
use tokio::net::TcpListener;

static STATIC_RESOURCE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rsproxy-web.blob"));
const WEB_PREFIX: &'static str = "/web";
const HEADER_KEY_CONTENT_TYPE: &'static str = "Content-Type";
const CONTENT_TYPE_JSON: &'static str = "application/json";

static HTTP_CODE_OK: u16 = 200;

static SERVICE_ERR_CODE_INVALID_PAYLOAD: u16 = 100;
static SERVICE_ERR_CODE_INVALID_RESPONSE: u16 = 101;
static SERVICE_ERR_CODE_METHOD_NOT_SUPPORTED: u16 = 102;

type RequestHandler = fn(api: Arc<dyn Api>, head: Parts, body: Bytes) -> Result<Body, JsonResponse>;
type RequestHandlersMap = HashMap<&'static str, RequestHandler>;
type StaticResourceMap = HashMap<&'static str, StaticResourceItem>;

lazy_static! {
    static ref STATIC_RESOURCE_ITEM_MAPPING: StaticResourceMap = {
        const WEB_SOURCE_CODE_INDEX: &str =
            include_str!(concat!(env!("OUT_DIR"), "/rsproxy-web.idx"));

        let mut map = HashMap::new();
        for line in WEB_SOURCE_CODE_INDEX.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();

            let item = StaticResourceItem {
                filename: fields[0],
                offset: fields[1].parse().unwrap(),
                len: fields[2].parse().unwrap(),
            };

            debug!("web source: {}", item.filename);

            map.insert(item.filename, item);
        }
        map
    };
    static ref REQUEST_HANDLERS_MAP: RequestHandlersMap = {
        let mut map = HashMap::<&'static str, RequestHandler>::new();
        map.insert("/api/server_state", DashboardService::server_state);
        map.insert("/api/server_config", DashboardService::server_config);
        map.insert("/api/prefer_upstream", DashboardService::prefer_upstream);
        map.insert("/api/apply_changes", DashboardService::apply_changes);
        map
    };
}

struct StaticResourceItem {
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
        info!("dashboard server bound to: {}", addr);
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
    api: Arc<dyn Api>,
}

impl DashboardService {
    pub fn new(api: Arc<dyn Api>) -> Self {
        DashboardService { api }
    }

    async fn handle_request(api: Arc<dyn Api>, req: Request<Body>) -> Option<Response<Body>> {
        let path = req.uri().path();
        match REQUEST_HANDLERS_MAP.get(path) {
            Some(handler) => {
                let (parts, req_body) = req.into_parts();
                let bytes = body::to_bytes(req_body).await.ok()?;
                let resp_body = match handler(api.clone(), parts, bytes) {
                    Ok(resp) => resp,
                    Err(e) => Self::convert_resp_to_body(e).unwrap(),
                };

                Some(
                    Response::builder()
                        .status(HTTP_CODE_OK)
                        .header(HEADER_KEY_CONTENT_TYPE, CONTENT_TYPE_JSON)
                        .body(resp_body)
                        .unwrap(),
                )
            }

            None => None,
        }
    }

    fn not_supported() -> JsonResponse {
        JsonResponse::fail(
            SERVICE_ERR_CODE_METHOD_NOT_SUPPORTED,
            "Method not supported".to_string(),
        )
    }

    fn convert_req_to_json<T: DeserializeOwned>(
        bytes: Bytes,
    ) -> Result<JsonRequest<T>, JsonResponse> {
        serde_json::from_slice::<JsonRequest<T>>(&bytes)
            .map_err(|e| JsonResponse::fail(SERVICE_ERR_CODE_INVALID_PAYLOAD, e.to_string()))
    }

    fn convert_resp_to_body<T: Serialize>(resp: JsonResponse<T>) -> Result<Body, JsonResponse> {
        let bytes = serde_json::to_vec(&resp)
            .map_err(|e| JsonResponse::fail(SERVICE_ERR_CODE_INVALID_RESPONSE, e.to_string()))?;
        Ok(Body::from(bytes))
    }

    fn server_state(api: Arc<dyn Api>, head: Parts, _: Bytes) -> Result<Body, JsonResponse> {
        let body = match head.method {
            http::Method::GET => Self::convert_resp_to_body(
                JsonResponse::<crate::api::ServerState>::succeed(Some(api.get_server_state())),
            )?,
            _ => return Err(Self::not_supported()),
        };

        Ok(body)
    }

    fn server_config(api: Arc<dyn Api>, head: Parts, _: Bytes) -> Result<Body, JsonResponse> {
        let body = match head.method {
            http::Method::GET => {
                Self::convert_resp_to_body(JsonResponse::<crate::api::ServerConfig>::succeed(
                    Some(api.get_server_config()),
                ))?
            }
            _ => return Err(Self::not_supported()),
        };

        Ok(body)
    }

    fn prefer_upstream(api: Arc<dyn Api>, head: Parts, body: Bytes) -> Result<Body, JsonResponse> {
        let body = match head.method {
            http::Method::POST => {
                let req = Self::convert_req_to_json::<bool>(body)?;
                api.set_prefer_upstream(req.data.unwrap());
                Self::convert_resp_to_body(<JsonResponse>::succeed(None))?
            }
            _ => return Err(Self::not_supported()),
        };

        Ok(body)
    }

    fn apply_changes(api: Arc<dyn Api>, head: Parts, body: Bytes) -> Result<Body, JsonResponse> {
        let body = match head.method {
            http::Method::POST => {
                let config = Self::convert_req_to_json::<ServerConfig>(body)?;
                match api.apply_changes(config.data.unwrap()) {
                    Ok(res) => {
                        // TODO handle result
                        Self::convert_resp_to_body(<JsonResponse>::succeed(None))?
                    }
                    _ => Self::convert_resp_to_body(<JsonResponse>::succeed(None))?,
                }
            }
            _ => return Err(Self::not_supported()),
        };

        Ok(body)
    }
}

impl Service<Request<Body>> for DashboardService {
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        fn static_html_resp(
            builder: response::Builder,
            StaticResourceItem {
                filename: _,
                offset,
                len,
            }: &StaticResourceItem,
        ) -> Response<Body> {
            let content = &STATIC_RESOURCE[*offset..(offset + len)];
            builder.body(Body::from(content)).unwrap()
        }

        let api = self.api.clone();
        let res = async {
            let path = req.uri().path();
            let path = if ["/", "/web/", WEB_PREFIX].iter().any(|&p| p == path) {
                "/index.html"
            } else {
                if path.len() > 4 {
                    &path[4..]
                } else {
                    path
                }
            };

            Ok(match STATIC_RESOURCE_ITEM_MAPPING.get(path) {
                Some(static_res) => {
                    let mime = match mime_guess::from_path(static_res.filename).first() {
                        Some(t) => t.to_string(),
                        None => "application/octet-stream".to_string(),
                    };

                    let builder = Response::builder()
                        .status(200)
                        .header(HEADER_KEY_CONTENT_TYPE, mime);
                    static_html_resp(builder, static_res)
                }
                None => match Self::handle_request(api, req).await {
                    Some(res) => res,
                    None => {
                        let builder = Response::builder()
                            .status(404)
                            .header(HEADER_KEY_CONTENT_TYPE, "text/html");
                        let item = STATIC_RESOURCE_ITEM_MAPPING.get("/404.html").unwrap();
                        static_html_resp(builder, item)
                    }
                },
            })
        };

        Box::pin(res)
    }

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
