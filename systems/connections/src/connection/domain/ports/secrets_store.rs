//! Secrets resolution port (connect pipeline stage 1: shared credentials).

use std::collections::HashMap;

use async_trait::async_trait;

use anydb_shared::ConnectionError;

#[async_trait]
pub trait SecretsStore: Send + Sync {
    async fn resolve(&self, container_id: &str)
    -> Result<HashMap<String, String>, ConnectionError>;
}
