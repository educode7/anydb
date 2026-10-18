//! Invalidation target port: the recovery loop's only side effect
//! (`InvalidateJob.invalidateTransaction` / `invalidateDataSource` analog).

use async_trait::async_trait;

use anydb_shared::{ConnectionError, RecoveryScope};

#[async_trait]
pub trait InvalidationTarget: Send + Sync {
    async fn invalidate(
        &self,
        scope: RecoveryScope,
        container_id: &str,
    ) -> Result<(), ConnectionError>;
}
