#![forbid(unsafe_code)]
//! Postgres driver skeleton: descriptor catalog + factory seam. The wire
//! protocol is pending; `open_data_source` validates the resolved target and
//! returns a metadata-only data source so the lifecycle contract is testable.

use std::sync::Arc;

use async_trait::async_trait;

use anydb_shared::ConnectionError;
use anydb_shared::driver::descriptor::DriverDescriptor;
use anydb_shared::driver::spi::{DataSource, DataSourceMetadata, Driver, OpenRequest};

#[derive(Debug)]
pub struct PostgresDriver {
    descriptor: DriverDescriptor,
}

impl Default for PostgresDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl PostgresDriver {
    pub fn new() -> Self {
        Self {
            descriptor: DriverDescriptor::new("postgresql", "PostgreSQL", true),
        }
    }
}

struct WirePendingDataSource;

#[async_trait]
impl DataSource for WirePendingDataSource {
    fn metadata(&self) -> DataSourceMetadata {
        DataSourceMetadata {
            product_name: "PostgreSQL".to_owned(),
            product_version: "unknown".to_owned(),
            driver_name: "anydb-postgres".to_owned(),
        }
    }

    async fn ping(&self) -> Result<(), ConnectionError> {
        // Wire protocol pending (see README); keepalive contract is exercised
        // by the shared lifecycle tests.
        Ok(())
    }

    async fn close(&self) {}
}

#[async_trait]
impl Driver for PostgresDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    async fn open_data_source(
        &self,
        request: OpenRequest,
    ) -> Result<Arc<dyn DataSource>, ConnectionError> {
        if request.target.is_empty() {
            return Err(ConnectionError::DriverFailure);
        }
        Ok(Arc::new(WirePendingDataSource))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn driver() -> PostgresDriver {
        PostgresDriver::new()
    }

    #[tokio::test]
    async fn open_requires_resolved_target() {
        let driver = driver();
        let request = OpenRequest {
            container_id: "c1".into(),
            target: String::new(),
            properties: Default::default(),
        };
        assert!(driver.open_data_source(request).await.is_err());
    }

    #[tokio::test]
    async fn open_returns_metadata_source() {
        let driver = driver();
        let request = OpenRequest {
            container_id: "c1".into(),
            target: "postgres://host/db".into(),
            properties: Default::default(),
        };
        let source = driver.open_data_source(request).await.unwrap();
        assert_eq!(source.metadata().product_name, "PostgreSQL");
        source.ping().await.unwrap();
        source.close().await;
    }
}
