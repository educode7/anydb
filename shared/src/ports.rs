//! Injection ports required by the kernel: clocks for deterministic tests.

/// Injection point for clocks so tests stay deterministic.
pub trait Clock: Send + Sync {
    fn now_millis(&self) -> u64;
}

/// Default wall-clock implementation.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_default()
    }
}
