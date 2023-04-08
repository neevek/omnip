pub(crate) mod http_proxy_handler;
pub(crate) mod http_req;

const INITIAL_HTTP_HEADER_SIZE: usize = 1024;
const MAX_HTTP_HEADER_SIZE: usize = 1024 * 8;
