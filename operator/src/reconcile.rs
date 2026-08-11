//! The reconcile loop: render from the mirror, server-side apply, status.

use std::sync::Arc;
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
use crate::render::{RenderError, render};
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

pub async fn reconcile(cr: Arc<BunkerSecret>, ctx: Arc<Context>) -> Result<Action, Error> {
    let timer = ctx.metrics.reconcile_duration.start_timer();
    let ns = cr.namespace().unwrap_or_default();
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
    result
}

pub fn error_policy(_cr: Arc<BunkerSecret>, err: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!(%err, "reconcile failed; backing off");
    Action::requeue(Duration::from_secs(10))
}

fn ready_condition(cr: &BunkerSecret, ok: bool, reason: &str, message: &str) -> Condition {
    Condition {
        type_: "Ready".to_string(),
        status: if ok { "True" } else { "False" }.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        last_transition_time: Time(k8s_openapi::jiff::Timestamp::now()),
        observed_generation: cr.metadata.generation,
    }
}

async fn patch_status(
    cr: &BunkerSecret,
    ctx: &Context,
    status: BunkerSecretStatus,
) -> Result<(), Error> {
    let ns = cr.namespace().unwrap_or_default();
    let api: Api<BunkerSecret> = Api::namespaced(ctx.client.clone(), &ns);
    let ready = status
        .conditions
        .first()
        .map(|c| c.status == "True")
        .unwrap_or(false);
    ctx.metrics
        .ready
        .with_label_values(&[&ns, &cr.name_any()])
        .set(if ready { 1 } else { 0 });
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
        patch_status(
            cr,
            ctx,
            status_with(
                cr,
                ready_condition(
                    cr,
                    false,
                    "AwaitingSync",
                    "replica has not completed its initial sync",
                ),
            ),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(5)));
    }

    // Render.
    let data = match render(&cr.spec, &ctx.source) {
        Ok(data) => data,
        Err(e) => return handle_render_error(cr, ctx, e).await,
    };

    // Target rename cleanup: the previously applied Secret, if differently named.
    let target = cr.target_name();
    if let Some(prev) = cr
        .status
        .as_ref()
        .and_then(|s| s.target_secret_name.clone())
        && prev != target
    {
        cleanup_target(&secrets, cr, &prev).await?;
    }

    // Fetch current state for ownership + hash-skip.
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
    let existing_hash = existing
        .as_ref()
        .and_then(|s| s.metadata.annotations.as_ref())
        .and_then(|a| a.get(HASH_ANNOTATION).cloned());

    if existing_hash.as_deref() == Some(desired_hash.as_str()) {
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

    // Status: Ready, or degraded-but-serving when the replica is stale.
    let stale = ctx
        .staleness
        .disconnected_for()
        .is_some_and(|d| d >= ctx.staleness_threshold);
    let condition = if stale {
        ready_condition(
            cr,
            false,
            "StaleReplica",
            "bunker unreachable; serving last synced state",
        )
    } else {
        ready_condition(cr, true, "Synced", "")
    };
    let last_synced = ctx
        .replica
        .status()
        .last_synced
        .and_then(system_time_to_k8s);
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
    Some(Time(ts))
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

/// The Cleanup arm of the finalizer — implemented in Task 9.
pub async fn cleanup_bunker_secret(cr: &BunkerSecret, ctx: &Context) -> Result<Action, Error> {
    let _ = (cr, ctx);
    Ok(Action::await_change())
}
