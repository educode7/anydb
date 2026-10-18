//! Domain layer of module `connection`: entities, value objects, ports and
//! errors. Pure: no tokio, no tracing, no I/O.

pub mod entities;
pub mod errors;
pub mod ports;
pub mod value_objects;
