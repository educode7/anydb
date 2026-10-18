#![forbid(unsafe_code)]
//! Bounded context `connections`: datasource container lifecycle and statement
//! execution. Dependency direction (ACA): application -> domain, and
//! infrastructure implements domain/application contracts; nothing here
//! depends on driver crates, which implement the shared driver SPI.

pub mod connection;
pub mod execution;
