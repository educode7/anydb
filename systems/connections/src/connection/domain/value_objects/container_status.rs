//! Container status state machine (DBeaver `connecting` / `connectFailed`
//! flags made explicit).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerStatus {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed(String),
}
