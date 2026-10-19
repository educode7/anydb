//! Supervised background monitor loops (DBeaver `KeepAlivePingJob` and
//! `DataSourceMonitorJob` analogs): a periodic sweep pings every
//! connected container; a failed ping invalidates the data source so a
//! dead connection never stays "Connected". The monitor loop goes one
//! step further for auto-restore containers: it re-schedules the
//! reconnect work THROUGH the job queue, with attempt bookkeeping so a
//! dead endpoint never produces an unbounded reconnect loop.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use crate::connection::api::ConnectionModule;
use crate::connection::application::commands::invalidate::InvalidateScope;
use crate::connection::application::jobs::ConnectionJob;
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

/// Reconciliation configuration (DBeaver `DataSourceMonitorJob` analog):
/// cadence, ping bound, spacing between automatic reconnect attempts and
/// the attempt cap.
#[derive(Debug, Clone, Copy)]
pub struct MonitorLoopConfig {
    /// Sweep cadence.
    pub interval: Duration,
    /// Per-ping bound for the health probe.
    pub ping_timeout: Duration,
    /// Minimum wait between automatic reconnect attempts (DBeaver
    /// reconnect-delay analog); rounds up to a number of sweep ticks.
    pub reconnect_cooldown: Duration,
    /// Maximum automatic reconnect attempts without an observed healthy
    /// ping (DBeaver password-retry-limit analog: never loops forever).
    pub max_reconnect_attempts: u32,
}

impl Default for MonitorLoopConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            ping_timeout: Duration::from_secs(5),
            reconnect_cooldown: Duration::from_secs(30),
            max_reconnect_attempts: 3,
        }
    }
}

/// Per-container reconciliation bookkeeping: only the monitor loop task
/// touches the map, so the `Mutex` covers interior mutability without
/// guarding any await.
#[derive(Debug, Default, Clone)]
struct Reconciliation {
    /// The monitor caused the current transition away from `Connected`;
    /// auto-restore never overrides user-owned lifecycle decisions.
    owned: bool,
    /// Auto reconnect jobs submitted since the last healthy ping.
    attempts: u32,
    /// Sweep ticks left to wait before the next attempt.
    cooldown: u32,
}

/// Spawns the state-reconciliation loop into the caller-owned `JoinSet`.
/// Correction work is NOT executed inline: it is enqueued through the
/// serialized job queue (DBeaver monitor-schedules-jobs semantics), so
/// the monitor never races the connect/disconnect/invalidate commands.
pub fn spawn_monitor_loop(
    module: &Arc<ConnectionModule>,
    queue: &crate::connection::infrastructure::job_queue::BoundJobQueue,
    config: MonitorLoopConfig,
    tasks: &mut JoinSet<()>,
) -> LoopHandle {
    let module = Arc::downgrade(module);
    let submit = queue.sender();
    let cooldown_ticks = ticks_of(config.reconnect_cooldown, config.interval);
    let (cancel, mut canceled) = oneshot::channel();
    tasks.spawn(async move {
        let mut stats = std::collections::HashMap::<String, Reconciliation>::new();
        let mut ticker = tokio::time::interval(config.interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Skip the immediate first tick: reconciliation starts observing
        // on the next cadence, mirroring the keepalive loop.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let Some(module) = module.upgrade() else { break };
                    reconcile(&module, &submit, &mut stats, config, cooldown_ticks).await;
                }
                _ = &mut canceled => break,
            }
        }
    });
    LoopHandle { cancel_tx: cancel }
}

fn ticks_of(duration: Duration, interval: Duration) -> u32 {
    let duration_ticks = duration.as_millis();
    if interval.is_zero() {
        return 1;
    }
    u32::try_from(duration_ticks.div_ceil(interval.as_millis().max(1)).max(1)).unwrap_or(u32::MAX)
}

async fn reconcile(
    module: &ConnectionModule,
    submit: &tokio::sync::mpsc::Sender<ConnectionJob>,
    stats: &mut std::collections::HashMap<String, Reconciliation>,
    config: MonitorLoopConfig,
    cooldown_ticks: u32,
) {
    for container_id in module.container_ids() {
        let Ok(container) = module.container(&container_id) else {
            continue;
        };
        if !container.auto_reconnect() {
            continue;
        }
        let snapshot = stats.entry(container_id.clone()).or_default().clone();

        match container.status() {
            ContainerStatus::Connected => match module
                .keep_alive(&container_id, config.ping_timeout)
                .await
            {
                Ok(()) => {
                    // Healthy observation: the bookkeeping resets, so a
                    // later death starts a fresh bounded attempt series.
                    stats.insert(container_id.clone(), Reconciliation::default());
                }
                Err(ping_error) => {
                    // A user disconnect may have landed mid-observation:
                    // only monitor-owned deaths reconcile.
                    if container.status() != ContainerStatus::Connected {
                        tracing::debug!(
                            container_id = %container_id,
                            state_change = true,
                            ?ping_error,
                            "monitor observed lifecycle change mid-probe"
                        );
                        continue;
                    }
                    let entry = stats.entry(container_id.clone()).or_default();
                    entry.owned = true;
                    let _ = submit
                        .send(ConnectionJob::Invalidate {
                            container_id: container_id.clone(),
                            scope: InvalidateScope::DataSource,
                        })
                        .await;
                    if snapshot.attempts < config.max_reconnect_attempts && snapshot.cooldown == 0 {
                        let _ = submit
                            .send(ConnectionJob::Connect {
                                container_id: container_id.clone(),
                            })
                            .await;
                        let entry = stats.entry(container_id.clone()).or_default();
                        entry.attempts = snapshot.attempts + 1;
                        entry.cooldown = cooldown_ticks;
                    }
                }
            },
            // Auto-restore applies to the Death states the monitor
            // produced; manual disconnects (`owned == false`) stay manual.
            ContainerStatus::Disconnected | ContainerStatus::Failed(_) => {
                if snapshot.owned
                    && snapshot.attempts < config.max_reconnect_attempts
                    && snapshot.cooldown == 0
                {
                    let _ = submit
                        .send(ConnectionJob::Connect {
                            container_id: container_id.clone(),
                        })
                        .await;
                    let entry = stats.entry(container_id.clone()).or_default();
                    entry.attempts = snapshot.attempts + 1;
                    entry.cooldown = cooldown_ticks;
                }
            }
            // In-flight lifecycle commands own these states.
            ContainerStatus::Connecting | ContainerStatus::Disconnecting => {}
        }

        // Drain one tick of cooldown after handling.
        if let Some(entry) = stats.get_mut(&container_id) {
            entry.cooldown = entry.cooldown.saturating_sub(1);
        }
    }
}
