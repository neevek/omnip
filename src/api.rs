pub trait Api: Send + Sync {
    fn set_prefer_upstream(&self, flag: bool);
    fn is_prefer_upstream(&self) -> bool;
}
