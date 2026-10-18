//! Module-level error surface re-exported from the shared kernel, so every
//! module keeps one error shape across versions.

pub use anydb_shared::ConnectionError;
pub use anydb_shared::ConnectionResult;
