//! Status DTO returned by queries.

use crate::connection::domain::value_objects::container_status::ContainerStatus;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerStatusDto {
    pub container_id: String,
    pub status: String,
}

impl ContainerStatusDto {
    pub fn from_status(container_id: &str, status: ContainerStatus) -> Self {
        let status = match status {
            ContainerStatus::Disconnected => "disconnected".to_owned(),
            ContainerStatus::Connecting => "connecting".to_owned(),
            ContainerStatus::Connected => "connected".to_owned(),
            ContainerStatus::Disconnecting => "disconnecting".to_owned(),
            ContainerStatus::Failed(_) => "failed".to_owned(),
        };
        Self {
            container_id: container_id.to_owned(),
            status,
        }
    }
}
