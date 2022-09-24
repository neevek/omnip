use std::sync::{Arc, Mutex};

use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct TrafficData {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Serialize)]
pub(crate) enum ServerInfoType {
    DNSResolverType,
    ServerState,
    Traffic,
}

#[derive(Serialize)]
pub(crate) struct ServerInfo<T>
where
    T: ?Sized + Serialize,
{
    pub info_type: ServerInfoType,
    pub data: Box<T>,
}

impl<T> ServerInfo<T>
where
    T: ?Sized + Serialize,
{
    pub(crate) fn new(info_type: ServerInfoType, data: Box<T>) -> Self {
        Self { info_type, data }
    }
}

#[derive(Clone)]
pub(crate) struct ServerInfoBridge {
    listener: Option<Arc<Mutex<dyn FnMut(&str) + 'static + Send + Sync>>>,
}

impl ServerInfoBridge {
    pub(crate) fn new() -> Self {
        ServerInfoBridge { listener: None }
    }

    pub(crate) fn set_listener(&mut self, listener: impl FnMut(&str) + 'static + Send + Sync) {
        self.listener = Some(Arc::new(Mutex::new(listener)));
    }

    pub(crate) fn has_listener(&self) -> bool {
        self.listener.is_some()
    }

    pub(crate) fn post_server_info<T>(&self, data: &ServerInfo<T>)
    where
        T: ?Sized + Serialize,
    {
        if let Some(ref listener) = self.listener {
            if let Ok(json) = serde_json::to_string(data) {
                listener.lock().unwrap()(json.as_str());
            }
        }
    }
}
