//! In-memory container registry (repository implementation).

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use anydb_shared::ConnectionError;

use crate::connection::domain::entities::data_source_container::ContainerState;

#[derive(Debug, Default)]
pub struct ContainerRegistry {
    entries: RwLock<HashMap<String, Arc<ContainerState>>>,
}

impl ContainerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, container: Arc<ContainerState>) {
        if let Ok(mut guard) = self.entries.write() {
            guard.insert(container.id().to_owned(), container);
        }
    }

    pub fn get(&self, id: &str) -> Result<Arc<ContainerState>, ConnectionError> {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
            .ok_or(ConnectionError::ContainerNotFound)
    }

    pub fn ids(&self) -> Vec<String> {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }
}
