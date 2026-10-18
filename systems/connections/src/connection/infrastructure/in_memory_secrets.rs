//! Volatile secrets store used by quickstarts and tests.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use anydb_shared::ConnectionError;

use crate::connection::domain::ports::secrets_store::SecretsStore;

#[derive(Debug, Default)]
pub struct InMemorySecretsStore {
    entries: RwLock<HashMap<String, HashMap<String, String>>>,
}

impl InMemorySecretsStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, container_id: &str, secrets: HashMap<String, String>) {
        if let Ok(mut guard) = self.entries.write() {
            guard.insert(container_id.to_owned(), secrets);
        }
    }
}

#[async_trait::async_trait]
impl SecretsStore for InMemorySecretsStore {
    async fn resolve(
        &self,
        container_id: &str,
    ) -> Result<HashMap<String, String>, ConnectionError> {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(container_id)
            .cloned()
            .ok_or(ConnectionError::MissingSecrets)
    }
}

/// Convenience for composition roots: `Arc<InMemorySecretsStore>`.
pub fn shared() -> Arc<InMemorySecretsStore> {
    Arc::new(InMemorySecretsStore::new())
}
