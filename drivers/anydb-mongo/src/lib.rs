#![forbid(unsafe_code)]
//! MongoDB driver skeleton: same contract as `anydb-postgres`; declared
//! thread-safe is `false` on purpose so the serialized statement gate path
//! (`SingleThreadLock` analog) is exercised from day one.

use std::sync::Arc;

use async_trait::async_trait;

use anydb_shared::ConnectionError;
use anydb_shared::driver::descriptor::DriverDescriptor;
use anydb_shared::driver::spi::{DataSource, DataSourceMetadata, Driver, OpenRequest};

#[derive(Debug)]
pub struct MongoDriver {
    descriptor: DriverDescriptor,
}

impl Default for MongoDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl MongoDriver {
    pub fn new() -> Self {
        Self {
            descriptor: DriverDescriptor::new("mongodb", "MongoDB", false),
        }
    }
}

struct WirePendingDataSource;

#[async_trait]
impl DataSource for WirePendingDataSource {
    fn metadata(&self) -> DataSourceMetadata {
        DataSourceMetadata {
            product_name: "MongoDB".to_owned(),
            product_version: "unknown".to_owned(),
            driver_name: "anydb-mongo".to_owned(),
        }
    }

    async fn ping(&self) -> Result<(), ConnectionError> {
        Ok(())
    }

    async fn close(&self) {}
}

#[async_trait]
impl Driver for MongoDriver {
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

    #[test]
    fn driver_is_declared_not_thread_safe() {
        let driver = MongoDriver::new();
        assert!(!driver.descriptor().thread_safe);
    }

    #[tokio::test]
    async fn open_returns_metadata_source() {
        let driver = MongoDriver::new();
        let request = OpenRequest {
            container_id: "c1".into(),
            target: "mongodb://host".into(),
            properties: Default::default(),
        };
        let source = driver.open_data_source(request).await.unwrap();
        assert_eq!(source.metadata().driver_name, "anydb-mongo");
        source.close().await;
    }
}
