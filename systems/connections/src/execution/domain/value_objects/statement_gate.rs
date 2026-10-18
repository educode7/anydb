//! Statement gate (DBeaver `StatementLock` NoOp vs SingleThreadLock): chosen
//! by the declared driver thread safety.
//!
//! Deviation note: a concrete enum + tokio primitive instead of a `dyn` port,
//! because an owned async lock guard cannot be abstracted trait-safely; the
//! lock must survive `.await` points.

use std::sync::Arc;

use tokio::sync::{Mutex, OwnedMutexGuard};

use anydb_shared::ConnectionError;
use anydb_shared::driver::descriptor::DriverDescriptor;

#[derive(Debug, Clone)]
pub enum StatementGate {
    Unprotected,
    Serialized { inner: Arc<Mutex<()>> },
}

impl StatementGate {
    pub fn for_driver(descriptor: &DriverDescriptor) -> Self {
        if descriptor.thread_safe {
            Self::Unprotected
        } else {
            Self::Serialized {
                inner: Arc::new(Mutex::new(())),
            }
        }
    }

    /// Returns a ticket; holding one serializes the caller's statements while
    /// `Some` (the guard is released when dropped).
    pub async fn acquire(&self) -> Result<StatementTicket, ConnectionError> {
        match self {
            Self::Unprotected => Ok(StatementTicket { owned: None }),
            Self::Serialized { inner } => Ok(StatementTicket {
                owned: Some(inner.clone().lock_owned().await),
            }),
        }
    }
}

pub struct StatementTicket {
    owned: Option<OwnedMutexGuard<()>>,
}

impl StatementTicket {
    /// True when the ticket actually serializes access.
    pub fn is_active(&self) -> bool {
        self.owned.is_some()
    }
}
