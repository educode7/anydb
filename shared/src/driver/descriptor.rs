//! Declarative driver descriptor (DBeaver `driverManager` catalog analog).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverDescriptor {
    pub id: String,
    pub name: String,
    /// `false` mirrors DBeaver `isThreadSafeDriver() == false`, which selects
    /// the serialized statement gate (`SingleThreadLock` analog).
    pub thread_safe: bool,
}

impl DriverDescriptor {
    pub fn new(id: impl Into<String>, name: impl Into<String>, thread_safe: bool) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            thread_safe,
        }
    }
}
