pub(crate) mod admin_server;
use serde::{Deserialize, Serialize};

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize)]
pub struct JsonRequest<T> {
    pub data: Option<T>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct JsonResponse<T = ()> {
    pub code: u16,
    pub msg: String,
    pub data: Option<T>,
}

impl<T> JsonResponse<T> {
    pub fn succeed(data: Option<T>) -> Self {
        JsonResponse::<T> {
            code: 0,
            msg: "".to_string(),
            data,
        }
    }

    pub fn fail(code: u16, msg: String) -> Self {
        JsonResponse::<T> {
            code,
            msg: msg.to_string(),
            data: None,
        }
    }
}
