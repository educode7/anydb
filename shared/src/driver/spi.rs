//! Factory seam and data source contract (DBeaver
//! `DBPDataSourceProvider.openDataSource` analog).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use super::descriptor::DriverDescriptor;
use crate::ConnectionError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    pub container_id: String,
    /// Resolved target (URL or logical name) after the connect pipeline stages.
    pub target: String,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSourceMetadata {
    pub product_name: String,
    pub product_version: String,
    pub driver_name: String,
}

#[async_trait]
pub trait Driver: Send + Sync {
    fn descriptor(&self) -> &DriverDescriptor;

    /// Factory seam decoupling connection creation from the registry.
    async fn open_data_source(
        &self,
        request: OpenRequest,
    ) -> Result<Arc<dyn DataSource>, ConnectionError>;
}

#[async_trait]
pub trait DataSource: Send + Sync {
    fn metadata(&self) -> DataSourceMetadata;

    /// Keepalive probe for the `KeepAlivePingJob` analog.
    async fn ping(&self) -> Result<(), ConnectionError>;

    async fn close(&self);
}
