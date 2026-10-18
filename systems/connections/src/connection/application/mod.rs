//! Application layer of module `connection`: one handler per use case,
//! command/query split, plus the serialized job queue contract.

pub mod commands;
pub mod dtos;
pub mod jobs;
pub mod queries;
