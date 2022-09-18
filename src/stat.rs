use serde::Serialize;

#[derive(Serialize)]
pub(crate) enum StatType {
    DNSResolverType,
    ServerState,
}

#[derive(Serialize)]
pub(crate) struct Stat<T>
where
    T: ?Sized + Serialize,
{
    pub stat_type: StatType,
    pub data: Box<T>,
}

impl<T> Stat<T>
where
    T: ?Sized + Serialize,
{
    pub(crate) fn new(stat_type: StatType, data: Box<T>) -> Self {
        Self { stat_type, data }
    }
}

pub(crate) struct StatBridge {
    callback: Option<Box<dyn FnMut(&str)>>,
}

impl StatBridge {
    pub(crate) fn new() -> Self {
        StatBridge { callback: None }
    }

    pub(crate) fn set_callback(&mut self, callback: impl FnMut(&str) + 'static) {
        self.callback = Some(Box::new(callback));
    }

    pub(crate) fn has_callback(&self) -> bool {
        self.callback.is_some()
    }

    pub(crate) fn post_stat<T>(&mut self, data: &Stat<T>)
    where
        T: ?Sized + Serialize,
    {
        if let Some(ref mut callback) = self.callback {
            if let Ok(json) = serde_json::to_string(data) {
                callback(json.as_str());
            }
        }
    }
}
