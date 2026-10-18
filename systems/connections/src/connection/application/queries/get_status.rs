//! Status query (read-only).

use std::sync::Arc;

use crate::connection::application::dtos::container_status_dto::ContainerStatusDto;
use crate::connection::domain::entities::data_source_container::ContainerState;

pub struct StatusQuery {
    pub container_id: String,
}

pub struct StatusHandler;

impl StatusHandler {
    pub fn handle(&self, container: Arc<ContainerState>) -> ContainerStatusDto {
        ContainerStatusDto::from_status(container.id(), container.status())
    }
}
