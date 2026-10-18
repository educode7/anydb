//! Network handler stages between auth and `open_data_source`
//! (DBeaver `networkHandler` extension point: tunnels and proxies).

use std::collections::HashMap;

use async_trait::async_trait;

use crate::ConnectionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkHandlerKind {
    Tunnel,
    Proxy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionProperties {
    pub target: String,
    pub settings: HashMap<String, String>,
}

impl ConnectionProperties {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            settings: HashMap::new(),
        }
    }
}

#[async_trait]
pub trait NetworkHandler: Send + Sync {
    fn kind(&self) -> NetworkHandlerKind;

    /// Handler stage: may rewrite `properties` before
    /// `Driver::open_data_source` runs. Initialized proxy-first (evidence
    /// digest 4.3 ordering).
    async fn initialize(
        &self,
        properties: &mut ConnectionProperties,
    ) -> Result<(), ConnectionError>;
}
