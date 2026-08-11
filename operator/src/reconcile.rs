//! The reconcile loop: render from the mirror, server-side apply, status.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::events::Recorder;
use kube::runtime::finalizer::{Event as Finalizer, finalizer};
use kube::{Client, Resource, ResourceExt};
use serde_json::json;

use crate::bunker::{ReplicaSource, Staleness};
use crate::crd::{
    BunkerSecret, BunkerSecretStatus, DeletionPolicy, FIELD_MANAGER, FINALIZER, HASH_ANNOTATION,
};
use crate::metrics::Metrics;
use crate::render::{RenderError, content_hash, render};
use crate::secretbuild::build_secret;
use secret_bunker_iroh::replica::Replica;

pub struct Context {
    pub client: Client,
    pub source: ReplicaSource,
    pub replica: Arc<Replica>,
    pub metrics: Metrics,
    pub staleness: Arc<Staleness>,
    /// Publishes Warning k8s Events on transition into a failure reason.
    pub recorder: Recorder,
    pub resync: Duration,
    pub staleness_threshold: Duration,
    /// Per-object ("namespace/name") consecutive transient-error count, used
    /// by `error_policy` to compute an exponential backoff. Cleared on the
    /// next successful reconcile of that object.
    pub backoffs: Mutex<HashMap<String, u32>>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("kube api: {0}")]
    Kube(#[from] kube::Error),
    #[error("finalizer: {0}")]
    Finalizer(#[source] Box<kube::runtime::finalizer::Error<Error>>),
    #[error("transient: {0}")]
    Transient(String),
}

/// Key `Context::backoffs` by "namespace/name" — cheap, stable, and unique
/// enough for a single-kind controller's per-object error count.
fn backoff_key(cr: &BunkerSecret) -> String {
    format!("{}/{}", cr.namespace().unwrap_or_default(), cr.name_any())
}

/// Record one more consecutive transient error for `key`, returning the new
/// count. A free function over the bare map (rather than a `Context` method)
/// so it's unit-testable without standing up a `Client`/`Replica`.
fn record_error(backoffs: &Mutex<HashMap<String, u32>>, key: &str) -> u32 {
    let mut backoffs = backoffs.lock().unwrap();
    let count = backoffs.entry(key.to_string()).or_insert(0);
    *count += 1;
    *count
}

/// Clear `key`'s consecutive-error count on a successful reconcile.
fn clear_backoff(backoffs: &Mutex<HashMap<String, u32>>, key: &str) {
    backoffs.lock().unwrap().remove(key);
}

pub async fn reconcile(cr: Arc<BunkerSecret>, ctx: Arc<Context>) -> Result<Action, Error> {
    let timer = ctx.metrics.reconcile_duration.start_timer();
    let ns = cr.namespace().unwrap_or_default();
    let key = backoff_key(&cr);
    let api: Api<BunkerSecret> = Api::namespaced(ctx.client.clone(), &ns);
    let result = finalizer(&api, FINALIZER, cr, |event| async {
        match event {
            Finalizer::Apply(cr) => apply_bunker_secret(&cr, &ctx).await,
            Finalizer::Cleanup(cr) => cleanup_bunker_secret(&cr, &ctx).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)));
    timer.observe_duration();
    ctx.metrics
        .reconciles_total
        .with_label_values(&[if result.is_ok() { "success" } else { "error" }])
        .inc();
    // A reconcile that completes without error — even one that only got as
    // far as reporting a degraded Ready condition (AwaitingSync, Conflict,
    // StaleReplica, ...) — is not a *transient* failure, so it resets this
    // object's backoff. Only Err results (kube API errors, `Error::Transient`)
    // ever reach `error_policy` and grow the count.
    if result.is_ok() {
        clear_backoff(&ctx.backoffs, &key);
    }
    result
}

const BACKOFF_BASE: Duration = Duration::from_secs(10);
const BACKOFF_CAP: Duration = Duration::from_secs(5 * 60);

/// Pure exponential-backoff schedule: `min(10s * 2^count, 5min)`. `count` is
/// the number of consecutive transient errors seen so far for an object (1
/// on the first error, 2 on the second, ...). Kept as a free function with
/// no `Context` dependency specifically so the doubling and the cap are
/// trivially unit-testable without a mock apiserver.
fn backoff_delay(count: u32) -> Duration {
    let factor = 1u64.checked_shl(count).unwrap_or(u64::MAX);
    let secs = BACKOFF_BASE.as_secs().saturating_mul(factor);
    Duration::from_secs(secs.min(BACKOFF_CAP.as_secs()))
}

pub fn error_policy(cr: Arc<BunkerSecret>, err: &Error, ctx: Arc<Context>) -> Action {
    tracing::warn!(%err, "reconcile failed; backing off");
    let key = backoff_key(&cr);
    let count = record_error(&ctx.backoffs, &key);
    Action::requeue(backoff_delay(count))
}

/// The k8s `Time` wire format is second-precision
/// (`%Y-%m-%dT%H:%M:%SZ`, see k8s-openapi's `Time::serialize`), but the
/// in-memory `jiff::Timestamp` we build it from carries sub-second
/// precision. Truncate before storing so a value we set ourselves compares
/// equal to itself after a round trip through the apiserver — otherwise the
/// status-equality check in `patch_status` never converges, and every
/// reconcile looks "changed" by a spurious sub-second delta even when
/// nothing did.
fn truncate_to_wire_precision(ts: k8s_openapi::jiff::Timestamp) -> k8s_openapi::jiff::Timestamp {
    k8s_openapi::jiff::Timestamp::from_second(ts.as_second()).unwrap_or(ts)
}

/// k8s condition convention: `lastTransitionTime` only moves when the
/// condition's (status, reason) actually changes — carry the prior
/// timestamp forward otherwise, rather than stamping `now()` on every
/// reconcile.
fn ready_condition(cr: &BunkerSecret, ok: bool, reason: &str, message: &str) -> Condition {
    let status = if ok { "True" } else { "False" }.to_string();
    let last_transition_time = cr
        .status
        .as_ref()
        .and_then(|s| s.conditions.first())
        .filter(|c| c.status == status && c.reason == reason)
        .map(|c| c.last_transition_time.clone())
        .unwrap_or_else(|| {
            Time(truncate_to_wire_precision(
                k8s_openapi::jiff::Timestamp::now(),
            ))
        });
    Condition {
        type_: "Ready".to_string(),
        status,
        reason: reason.to_string(),
        message: message.to_string(),
        last_transition_time,
        observed_generation: cr.metadata.generation,
    }
}

async fn patch_status(
    cr: &BunkerSecret,
    ctx: &Context,
    status: BunkerSecretStatus,
) -> Result<(), Error> {
    let ns = cr.namespace().unwrap_or_default();
    let ready = status
        .conditions
        .first()
        .map(|c| c.status == "True")
        .unwrap_or(false);
    ctx.metrics
        .ready
        .with_label_values(&[&ns, &cr.name_any()])
        .set(if ready { 1 } else { 0 });

    // Nothing materially changed: condition status/reason/message (with
    // lastTransitionTime already carried forward by `ready_condition` when
    // status+reason match), lastSyncTime, observedGeneration,
    // syncedSecretKeys, and targetSecretName are all identical to what's
    // already on the CR — skip the write instead of patching a no-op.
    let prev = cr.status.clone().unwrap_or_default();
    if status == prev {
        return Ok(());
    }

    let api: Api<BunkerSecret> = Api::namespaced(ctx.client.clone(), &ns);
    let patch = Patch::Apply(json!({
        "apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
        "kind": "BunkerSecret",
        "status": status,
    }));
    api.patch_status(
        &cr.name_any(),
        &PatchParams::apply(FIELD_MANAGER).force(),
        &patch,
    )
    .await?;
    Ok(())
}

fn status_with(cr: &BunkerSecret, condition: Condition) -> BunkerSecretStatus {
    // Carry forward sync bookkeeping so a degraded condition doesn't erase it.
    let prev = cr.status.clone().unwrap_or_default();
    BunkerSecretStatus {
        conditions: vec![condition],
        observed_generation: cr.metadata.generation,
        ..prev
    }
}

fn owned_by(secret: &Secret, cr: &BunkerSecret) -> bool {
    let Some(uid) = &cr.metadata.uid else {
        return false;
    };
    secret
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|o| o.kind == "BunkerSecret" && &o.uid == uid)
}

/// The Apply arm of the finalizer. Public for direct testing.
pub async fn apply_bunker_secret(cr: &BunkerSecret, ctx: &Context) -> Result<Action, Error> {
    let ns = cr.namespace().unwrap_or_default();
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);

    // Gate: never render from an unsynced mirror (a boot-time empty mirror
    // must not look like mass deletion). Tests pre-converge, production waits.
    if ctx.replica.status().last_synced.is_none() {
        let message = "replica has not completed its initial sync";
        publish_warning_on_transition(cr, ctx, "AwaitingSync", message).await;
        patch_status(
            cr,
            ctx,
            status_with(cr, ready_condition(cr, false, "AwaitingSync", message)),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(5)));
    }

    // Render.
    let data = match render(&cr.spec, &ctx.source) {
        Ok(data) => data,
        Err(e) => return handle_render_error(cr, ctx, e).await,
    };

    let target = cr.target_name();

    // Fetch current state for ownership + hash-skip. This ownership check on
    // the (possibly renamed-to) target MUST run before any cleanup of a
    // previous target name below: if the new name collides with a Secret we
    // don't own, we bail out with Conflict and leave BOTH the old and the
    // would-be Secret alone. Cleaning up the old name first and then
    // aborting here would leave the workload with no Secret at all.
    let existing = match secrets.get(&target).await {
        Ok(s) => Some(s),
        Err(kube::Error::Api(ae)) if ae.code == 404 => None,
        Err(e) => return Err(e.into()),
    };
    if let Some(existing) = &existing
        && !owned_by(existing, cr)
    {
        let message = format!(
            "Secret {ns}/{target} exists and is not owned by this BunkerSecret; refusing to adopt"
        );
        publish_warning_on_transition(cr, ctx, "Conflict", &message).await;
        patch_status(
            cr,
            ctx,
            status_with(cr, ready_condition(cr, false, "Conflict", &message)),
        )
        .await?;
        return Ok(Action::requeue(ctx.resync));
    }

    let desired = build_secret(cr, &data);
    let desired_hash = desired.metadata.annotations.as_ref().unwrap()[HASH_ANNOTATION].clone();
    // Compare CONTENT, not the (informational-only) annotation: the
    // annotation on a manually-edited Secret is left untouched by the hand
    // edit, so trusting it would let a tampered value stand forever —
    // breaking the "manual edits get reverted" promise. Hash what's
    // actually in `data` instead. `existing.data` is already base64-decoded
    // by k8s-openapi (`ByteString`), so this is a direct byte comparison via
    // the same hash the apply path used to produce the annotation. A Secret
    // with no `data` at all (freshly adopted, or wiped by hand) never
    // matches, so it always gets (re)applied.
    let existing_content_hash = existing.as_ref().and_then(|s| s.data.as_ref()).map(|d| {
        let decoded: BTreeMap<String, Vec<u8>> =
            d.iter().map(|(k, v)| (k.clone(), v.0.clone())).collect();
        content_hash(&decoded)
    });

    if existing_content_hash.as_deref() == Some(desired_hash.as_str()) {
        ctx.metrics
            .applies_total
            .with_label_values(&["skipped"])
            .inc();
    } else {
        secrets
            .patch(
                &target,
                &PatchParams::apply(FIELD_MANAGER).force(),
                &Patch::Apply(&desired),
            )
            .await?;
        ctx.metrics
            .applies_total
            .with_label_values(&["applied"])
            .inc();
    }

    // Target rename cleanup: now that the (possibly new) target is confirmed
    // safe and has been applied or skipped, retire the previous target name
    // if this reconcile renamed the Secret.
    if let Some(prev) = cr
        .status
        .as_ref()
        .and_then(|s| s.target_secret_name.clone())
        && prev != target
    {
        cleanup_target(&secrets, cr, &prev).await?;
    }

    // Status: Ready, or degraded-but-serving when the replica is stale.
    let stale = ctx
        .staleness
        .disconnected_for()
        .is_some_and(|d| d >= ctx.staleness_threshold);
    let condition = if stale {
        let message = "bunker unreachable; serving last synced state";
        publish_warning_on_transition(cr, ctx, "StaleReplica", message).await;
        ready_condition(cr, false, "StaleReplica", message)
    } else {
        ready_condition(cr, true, "Synced", "")
    };
    // A conversion failure (or, defensively, a replica that somehow reports
    // no sync at all here) must not let SSA null out a lastSyncTime this
    // field manager previously set — the AccessRevoked freeze rule keys on
    // it staying present. Carry the CR's current value forward instead.
    let prev_last_sync = cr.status.as_ref().and_then(|s| s.last_sync_time.clone());
    let last_synced = ctx
        .replica
        .status()
        .last_synced
        .and_then(system_time_to_k8s)
        .or(prev_last_sync);
    let status = BunkerSecretStatus {
        conditions: vec![condition],
        last_sync_time: last_synced,
        observed_generation: cr.metadata.generation,
        synced_secret_keys: data.keys().cloned().collect(),
        target_secret_name: Some(target),
    };
    patch_status(cr, ctx, status).await?;
    Ok(Action::requeue(ctx.resync))
}

fn system_time_to_k8s(t: SystemTime) -> Option<Time> {
    let ts = k8s_openapi::jiff::Timestamp::try_from(t).ok()?;
    Some(Time(truncate_to_wire_precision(ts)))
}

async fn handle_render_error(
    cr: &BunkerSecret,
    ctx: &Context,
    e: RenderError,
) -> Result<Action, Error> {
    let previously_synced = cr
        .status
        .as_ref()
        .and_then(|s| s.last_sync_time.as_ref())
        .is_some();
    let (reason, message) = match &e {
        RenderError::MissingGroup { group } if previously_synced => (
            "AccessRevoked",
            format!(
                "group '{group}' disappeared from the mirror after having synced; keeping the last applied Secret"
            ),
        ),
        RenderError::MissingGroup { group } => (
            "MissingGroup",
            format!("group '{group}' is not in the mirror (no read grant, or not yet created)"),
        ),
        RenderError::MissingSecret { group, name } => (
            "MissingSecret",
            format!("secret '{group}/{name}' not found; keeping the last applied Secret"),
        ),
        RenderError::InvalidKey { keys } => (
            "InvalidKey",
            format!(
                "rendered keys are not valid k8s Secret keys: {keys:?}; add rewrite rules or explicit data entries"
            ),
        ),
        RenderError::Json { group, name, msg } => (
            "JsonError",
            format!("'{group}/{name}' is not valid JSON: {msg}"),
        ),
        RenderError::Pointer {
            group,
            name,
            pointer,
        } => (
            "JsonError",
            format!("pointer '{pointer}' not found in '{group}/{name}'"),
        ),
        RenderError::NotObject { group, name } => (
            "JsonError",
            format!("'{group}/{name}' is not a JSON object; extract requires one"),
        ),
        RenderError::NotYetSynced { group, name, msg } => {
            return Err(Error::Transient(format!(
                "'{group}/{name}' not yet decryptable: {msg}"
            )));
        }
    };
    if reason == "AccessRevoked" {
        tracing::warn!(cr = %cr.name_any(), "access revoked; freezing synced Secret");
    }
    publish_warning_on_transition(cr, ctx, reason, &message).await;
    patch_status(
        cr,
        ctx,
        status_with(cr, ready_condition(cr, false, reason, &message)),
    )
    .await?;
    Ok(Action::requeue(ctx.resync))
}

/// Spec: a Warning k8s Event on every TRANSITION to a failure reason (repeat
/// reconciles with the same reason stay quiet). Event publish failures are
/// logged, never fatal — conditions are the source of truth.
async fn publish_warning_on_transition(
    cr: &BunkerSecret,
    ctx: &Context,
    reason: &str,
    message: &str,
) {
    let prev_reason = cr
        .status
        .as_ref()
        .and_then(|s| s.conditions.first())
        .map(|c| c.reason.clone());
    if prev_reason.as_deref() == Some(reason) {
        return;
    }
    use kube::runtime::events::{Event, EventType};
    let event = Event {
        type_: EventType::Warning,
        reason: reason.to_string(),
        note: Some(message.to_string()),
        action: "Reconcile".to_string(),
        secondary: None,
    };
    if let Err(e) = ctx.recorder.publish(&event, &cr.object_ref(&())).await {
        tracing::warn!(error = %e, "failed to publish warning event");
    }
}

/// Old target Secret cleanup on rename, honoring deletionPolicy.
async fn cleanup_target(secrets: &Api<Secret>, cr: &BunkerSecret, name: &str) -> Result<(), Error> {
    let existing = match secrets.get(name).await {
        Ok(s) => s,
        Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if !owned_by(&existing, cr) {
        return Ok(());
    }
    match cr.spec.deletion_policy {
        DeletionPolicy::Delete => {
            secrets.delete(name, &Default::default()).await?;
        }
        DeletionPolicy::Retain => {
            // Orphan: strip ownerReferences so GC never collects it.
            let patch = json!({"metadata": {"ownerReferences": null}});
            secrets
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
                .await?;
        }
    }
    Ok(())
}

/// The Cleanup arm of the finalizer: runs when the CR is being deleted.
/// Delete policy: nothing to do — the ownerReference lets GC cascade.
/// Retain policy: orphan the Secret by clearing its ownerReferences.
pub async fn cleanup_bunker_secret(cr: &BunkerSecret, ctx: &Context) -> Result<Action, Error> {
    let ns = cr.namespace().unwrap_or_default();
    ctx.metrics
        .ready
        .with_label_values(&[&ns, &cr.name_any()])
        .set(0);
    if cr.spec.deletion_policy == DeletionPolicy::Retain {
        let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);
        let target = cr.target_name();
        match secrets.get(&target).await {
            Ok(existing) if owned_by(&existing, cr) => {
                let patch = json!({"metadata": {"ownerReferences": null}});
                secrets
                    .patch(&target, &PatchParams::default(), &Patch::Merge(&patch))
                    .await?;
            }
            Ok(_) => {}                                       // not ours — leave it
            Err(kube::Error::Api(ae)) if ae.code == 404 => {} // already gone
            Err(e) => return Err(e.into()),
        }
    }
    Ok(Action::await_change())
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    #[test]
    fn backoff_delay_doubles_then_caps_at_five_minutes() {
        assert_eq!(backoff_delay(1), Duration::from_secs(20));
        assert_eq!(backoff_delay(2), Duration::from_secs(40));
        assert_eq!(backoff_delay(3), Duration::from_secs(80));
        assert_eq!(backoff_delay(4), Duration::from_secs(160));
        // 10 * 2^5 = 320s would exceed the 5-minute cap.
        assert_eq!(backoff_delay(5), Duration::from_secs(300));
        assert_eq!(backoff_delay(6), Duration::from_secs(300));
        assert_eq!(backoff_delay(1000), Duration::from_secs(300));
    }

    #[test]
    fn record_error_increments_per_key_and_clear_resets() {
        let backoffs = Mutex::new(HashMap::new());
        assert_eq!(record_error(&backoffs, "ns/app"), 1);
        assert_eq!(record_error(&backoffs, "ns/app"), 2);
        assert_eq!(record_error(&backoffs, "ns/app"), 3);
        // A different object's count is tracked independently.
        assert_eq!(record_error(&backoffs, "ns/other"), 1);

        clear_backoff(&backoffs, "ns/app");
        // Reset: the next error for this object starts back at 1...
        assert_eq!(record_error(&backoffs, "ns/app"), 1);
        // ...while the untouched object's count is unaffected by the reset.
        assert_eq!(*backoffs.lock().unwrap().get("ns/other").unwrap(), 1);
    }

    #[test]
    fn clear_backoff_on_unknown_key_is_a_no_op() {
        let backoffs = Mutex::new(HashMap::new());
        clear_backoff(&backoffs, "ns/never-errored");
        assert!(backoffs.lock().unwrap().is_empty());
    }
}
