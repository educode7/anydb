//! Supervised background monitor loops (DBeaver `KeepAlivePingJob` analog):
//! a periodic sweep pings every connected container; a failed ping
//! invalidates the data source so a dead connection never stays "Connected".

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use crate::connection::api::ConnectionModule;
use crate::connection::application::commands::invalidate::InvalidateScope;
use crate::connection::domain::value_objects::container_status::ContainerStatus;

#[derive(Debug, Clone, Copy)]
pub struct KeepAliveLoopConfig {
    /// Sweep cadence (DBeaver `keepAlivePagePeriod` analog).
    pub interval: Duration,
    /// Per-ping bound; a ping exceeding this counts as a failure.
    pub ping_timeout: Duration,
}

impl Default for KeepAliveLoopConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            ping_timeout: Duration::from_secs(5),
        }
    }
}

/// Cancels the loop when dropped (or explicitly via `cancel`).
pub struct LoopHandle {
    cancel_tx: oneshot::Sender<()>,
}

impl LoopHandle {
    /// Cancels the loop; dropping the handle has the same effect.
    pub fn cancel(self) {
        let _ = self.cancel_tx.send(());
    }
}

/// Spawns a supervised keepalive sweep into the caller-owned `JoinSet`.
/// The loop holds a `Weak` module: dropping the module (or cancelling the
/// handle) ends the loop, so `App::shutdown` never deadlocks on a ticker.
pub fn spawn_keepalive_loop(
    module: &Arc<ConnectionModule>,
    config: KeepAliveLoopConfig,
    tasks: &mut JoinSet<()>,
) -> LoopHandle {
    let module = Arc::downgrade(module);
    let (cancel, mut canceled) = oneshot::channel();
    tasks.spawn(async move {
        let mut ticker = tokio::time::interval(config.interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first tick fires immediately; the first sweep runs on the next.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let Some(module) = module.upgrade() else { break };
                    sweep(&module, config.ping_timeout).await;
                }
                _ = &mut canceled => break,
            }
        }
    });
    LoopHandle { cancel_tx: cancel }
}

async fn sweep(module: &ConnectionModule, ping_timeout: Duration) {
    for container_id in module.container_ids() {
        let connected = module
            .container(&container_id)
            .is_ok_and(|container| container.status() == ContainerStatus::Connected);
        if !connected {
            continue;
        }
        if let Err(error) = module.keep_alive(&container_id, ping_timeout).await {
            tracing::debug!(
                container_id = %container_id,
                ?error,
                "keepalive failed; invalidating data source"
            );
            let _ = module
                .invalidate(&container_id, InvalidateScope::DataSource)
                .await;
        }
    }
}
