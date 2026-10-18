//! Ports declared by module `connection`; infrastructure and drivers
//! implement them. Handlers hold `Arc<dyn Port>`.

pub mod connection_events;
pub mod secrets_store;
