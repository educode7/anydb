//! Per-operation recovery state (DBeaver `RecoveryState`: `recoveryDepth`,
//! sticky `recoveryFailed`). Explicitly threaded instead of `ThreadLocal`:
//! task-locals do not compose with `.await` ownership moves.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoveryState {
    pub depth: u32,
    pub failed: bool,
}

impl RecoveryState {
    pub fn new() -> Self {
        Self::default()
    }
}
