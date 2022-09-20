use serde::Serialize;

#[derive(Serialize)]
pub(crate) enum ServerInfoType {
    DNSResolverType,
    ServerState,
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

pub(crate) struct ServerInfoBridge {
    listener: Option<Box<dyn FnMut(&str)>>,
}

impl ServerInfoBridge {
    pub(crate) fn new() -> Self {
        ServerInfoBridge { listener: None }
    }

    pub(crate) fn set_listener(&mut self, listener: impl FnMut(&str) + 'static) {
        self.listener = Some(Box::new(listener));
    }

    pub(crate) fn has_listener(&self) -> bool {
        self.listener.is_some()
    }

    pub(crate) fn post_server_info<T>(&mut self, data: &ServerInfo<T>)
    where
        T: ?Sized + Serialize,
    {
        if let Some(ref mut listener) = self.listener {
            if let Ok(json) = serde_json::to_string(data) {
                listener(json.as_str());
            }
        }
    }
}
