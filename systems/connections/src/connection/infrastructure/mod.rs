//! Infrastructure implementations of module `connection` ports and runtime
//! pieces: registry, volatile secrets store, no-op events, supervised job
//! queue.

pub mod in_memory_registry;
pub mod in_memory_secrets;
pub mod job_queue;
pub mod noop_events;
