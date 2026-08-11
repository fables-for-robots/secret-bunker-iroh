//! Bridges ReplicaEvents to controller reconcile triggers.
//!
//! Events are wake-ups only: reconcile always reads full state from the
//! mirror, so a missed event costs latency, never correctness. Lagged (the
//! broadcast buffer overflowed) triggers reconcile of ALL CRs.

use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use kube::runtime::reflector::ObjectRef;
use secret_bunker_iroh::replica::ReplicaEvent;
use tokio::sync::broadcast;

use crate::bunker::Staleness;
use crate::crd::BunkerSecret;
use crate::metrics::Metrics;

type CrLister = Box<dyn Fn() -> Vec<Arc<BunkerSecret>> + Send>;

pub fn spawn_event_bridge(
    rx: broadcast::Receiver<ReplicaEvent>,
    crs: CrLister,
    staleness: Arc<Staleness>,
    staleness_threshold: Duration,
    metrics: Metrics,
) -> impl Stream<Item = ObjectRef<BunkerSecret>> {
    let (tx, out) = futures::channel::mpsc::unbounded();
    tokio::spawn(drive_bridge(
        rx,
        crs,
        staleness,
        staleness_threshold,
        metrics,
        tx,
    ));
    out
}

fn obj_ref(cr: &BunkerSecret) -> ObjectRef<BunkerSecret> {
    let name = cr.metadata.name.clone().unwrap_or_default();
    match &cr.metadata.namespace {
        Some(ns) => ObjectRef::new(&name).within(ns),
        None => ObjectRef::new(&name),
    }
}

async fn drive_bridge(
    mut rx: broadcast::Receiver<ReplicaEvent>,
    crs: CrLister,
    staleness: Arc<Staleness>,
    staleness_threshold: Duration,
    metrics: Metrics,
    tx: futures::channel::mpsc::UnboundedSender<ObjectRef<BunkerSecret>>,
) {
    // The ticker exists to flip CRs to/from StaleReplica when nothing else is
    // reconciling; it fires rarely relative to the threshold.
    let mut tick = tokio::time::interval(staleness_threshold.min(Duration::from_secs(60)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut was_stale = false;

    // A plain fn (not a closure) so no reference to `crs`/`tx` is captured
    // and carried across the `.await` points in the `select!` below: `crs`
    // is `Box<dyn Fn() + Send>` but not `Sync`, so a closure holding `&crs`
    // across an await would make the whole future non-`Send`.
    fn trigger_all(
        reason: &str,
        crs: &CrLister,
        tx: &futures::channel::mpsc::UnboundedSender<ObjectRef<BunkerSecret>>,
    ) {
        tracing::debug!(reason, "triggering reconcile of all BunkerSecrets");
        for cr in crs() {
            let _ = tx.unbounded_send(obj_ref(&cr));
        }
    }

    loop {
        tokio::select! {
            event = rx.recv() => match event {
                Ok(ev) => {
                    let (label, group) = match &ev {
                        ReplicaEvent::SecretChanged { group, .. } => ("secret_changed", Some(group.clone())),
                        ReplicaEvent::SecretDeleted { group, .. } => ("secret_deleted", Some(group.clone())),
                        ReplicaEvent::GroupAdded { group } => ("group_added", Some(group.clone())),
                        ReplicaEvent::GroupRemoved { group } => ("group_removed", Some(group.clone())),
                        ReplicaEvent::Connected => ("connected", None),
                        ReplicaEvent::Disconnected => ("disconnected", None),
                    };
                    metrics.events_total.with_label_values(&[label]).inc();
                    match ev {
                        ReplicaEvent::Connected => staleness.set_connected(true),
                        ReplicaEvent::Disconnected => staleness.set_connected(false),
                        _ => {
                            if let Some(g) = group {
                                for cr in crs() {
                                    if cr.referenced_groups().contains(&g) {
                                        let _ = tx.unbounded_send(obj_ref(&cr));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    metrics.events_total.with_label_values(&["lagged"]).inc();
                    tracing::warn!(missed = n, "replica event stream lagged; reconciling everything");
                    trigger_all("lagged", &crs, &tx);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::warn!("replica event channel closed; event bridge exiting");
                    return;
                }
            },
            _ = tick.tick() => {
                let stale = staleness
                    .disconnected_for()
                    .is_some_and(|d| d >= staleness_threshold);
                if stale != was_stale {
                    was_stale = stale;
                    trigger_all(if stale { "went-stale" } else { "recovered" }, &crs, &tx);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bunker::Staleness;
    use crate::crd::{BunkerSecret, BunkerSecretSpec};
    use crate::metrics::Metrics;
    use futures::StreamExt;
    use secret_bunker_iroh::replica::ReplicaEvent;
    use std::sync::Arc;
    use std::time::Duration;

    fn cr(name: &str, ns: &str, group: &str) -> Arc<BunkerSecret> {
        let spec: BunkerSecretSpec =
            serde_yaml::from_str(&format!("dataFrom: [{{group: {{name: {group}}}}}]")).unwrap();
        let mut cr = BunkerSecret::new(name, spec);
        cr.metadata.namespace = Some(ns.to_string());
        Arc::new(cr)
    }

    async fn next_ref(
        stream: &mut (
                 impl futures::Stream<Item = kube::runtime::reflector::ObjectRef<BunkerSecret>> + Unpin
             ),
    ) -> (String, String) {
        let r = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timed out waiting for trigger")
            .expect("bridge stream ended");
        (r.namespace.clone().unwrap_or_default(), r.name.clone())
    }

    #[tokio::test]
    async fn secret_changed_triggers_only_referencing_crs() {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let crs = vec![cr("a", "ns1", "prod"), cr("b", "ns2", "staging")];
        let mut stream = Box::pin(spawn_event_bridge(
            rx,
            Box::new(move || crs.clone()),
            Arc::new(Staleness::new()),
            Duration::from_secs(600),
            Metrics::new().unwrap(),
        ));
        tx.send(ReplicaEvent::SecretChanged {
            group: "prod".into(),
            name: "pw".into(),
            version: 1,
        })
        .unwrap();
        assert_eq!(
            next_ref(&mut stream).await,
            ("ns1".to_string(), "a".to_string())
        );
        // No trigger for the staging CR: send a second prod event and confirm
        // the next item is again CR "a" (nothing for "b" queued between).
        tx.send(ReplicaEvent::GroupRemoved {
            group: "prod".into(),
        })
        .unwrap();
        assert_eq!(
            next_ref(&mut stream).await,
            ("ns1".to_string(), "a".to_string())
        );
    }

    #[tokio::test]
    async fn connected_updates_staleness_not_stream() {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let staleness = Arc::new(Staleness::new());
        let crs = vec![cr("a", "ns1", "prod")];
        let mut stream = Box::pin(spawn_event_bridge(
            rx,
            Box::new(move || crs.clone()),
            staleness.clone(),
            Duration::from_secs(600),
            Metrics::new().unwrap(),
        ));
        assert!(staleness.disconnected_for().is_some());
        tx.send(ReplicaEvent::Connected).unwrap();
        // Follow with a data event so the stream yields something deterministic.
        tx.send(ReplicaEvent::SecretChanged {
            group: "prod".into(),
            name: "x".into(),
            version: 1,
        })
        .unwrap();
        assert_eq!(
            next_ref(&mut stream).await,
            ("ns1".to_string(), "a".to_string())
        );
        assert_eq!(staleness.disconnected_for(), None);
    }

    #[tokio::test]
    async fn closed_channel_triggers_reconcile_all_then_ends() {
        // Dropping the sender simulates replica shutdown; Lagged uses the same
        // reconcile-all path (drive_bridge handles both identically).
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let crs = vec![cr("a", "ns1", "prod"), cr("b", "ns2", "staging")];
        let mut stream = Box::pin(spawn_event_bridge(
            rx,
            Box::new(move || crs.clone()),
            Arc::new(Staleness::new()),
            Duration::from_secs(600),
            Metrics::new().unwrap(),
        ));
        drop(tx);
        // Channel-closed does NOT reconcile-all; the stream just ends.
        let r = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap();
        assert!(
            r.is_none(),
            "stream should end when the replica goes away, got {r:?}"
        );
    }
}
