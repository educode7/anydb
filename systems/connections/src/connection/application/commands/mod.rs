//! Write use cases of module `connection`. Never mutate state outside these
//! handlers (commands own the status state machine).

pub mod connect;
pub mod disconnect;
pub mod invalidate;
pub mod keepalive;
