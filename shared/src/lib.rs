#![forbid(unsafe_code)]
//! Domain-agnostic kernel shared by every anydb system and driver.
//!
//! Holds the driver SPI (`driver`), the shared error taxonomy (`domain`) and
//! the injection ports (`ports`). Nothing here knows about the connections
//! system internals; this is the ACA `shared/` equivalent.

pub mod domain;
pub mod driver;
pub mod ports;

pub use domain::errors::{ConnectionError, ConnectionResult, ErrorType, RecoveryScope};
