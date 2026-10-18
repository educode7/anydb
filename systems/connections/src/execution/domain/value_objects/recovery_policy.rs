//! Recovery policy (DBeaver `execute.recover.enabled` + retryCount).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryPolicy {
    pub enabled: bool,
    /// Extra attempts after the first one (try_count = 1 + max_retries).
    pub max_retries: u32,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_retries: 2,
        }
    }
}
