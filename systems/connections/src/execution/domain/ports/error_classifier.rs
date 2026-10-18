//! Error type classifier port (DBeaver driver `DBPErrorAssistant` analog).
//!
//! The contract lives in the shared kernel so drivers can implement it
//! without depending on this system; the port is the system-local alias.

pub use anydb_shared::driver::classification::ErrorClassifier;
