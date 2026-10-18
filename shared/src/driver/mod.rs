//! Driver abstraction surfaces (evidence digest 4.4): descriptor catalog,
//! factory seam (`open_data_source`) and network handler stages.

pub mod classification;
pub mod descriptor;
pub mod io;
pub mod spi;
pub mod statement;

pub use statement::{QueryParameter, StatementResult};
