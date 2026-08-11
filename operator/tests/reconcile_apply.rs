mod common;
mod kubemock;

use std::sync::Arc;
use std::time::Duration;

use common::TestBunker;
use iroh::SecretKey;
use kubemock::{expect, expect_checked, scripted};
use secret_bunker_operator::bunker::{ReplicaSource, Staleness};
use secret_bunker_operator::crd::{
    BunkerSecret, BunkerSecretSpec, BunkerSecretStatus, HASH_ANNOTATION,
};
use secret_bunker_operator::metrics::Metrics;
use secret_bunker_operator::reconcile::{Context, apply_bunker_secret};
use serde_json::json;

#[allow(dead_code)]
fn cr_json(cr: &BunkerSecret) -> serde_json::Value {
    serde_json::to_value(cr).unwrap()
}

async fn synced_context(
    bunker: &TestBunker,
    reader: SecretKey,
    client: kube::Client,
) -> (Context, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let (replica, _rx) = bunker
        .replica_for(reader, &dir.path().join("m.sqlite"))
        .await;
    // Deterministic tests need a converged mirror; production gates on last_synced.
    let replica = Arc::new(replica);
    let recorder = kube::runtime::events::Recorder::new(
        client.clone(),
        kube::runtime::events::Reporter {
            controller: "secret-bunker-operator".into(),
            instance: None,
        },
    );
    let ctx = Context {
        client,
        source: ReplicaSource(replica.clone()),
        replica,
        metrics: Metrics::new().unwrap(),
        staleness: Arc::new(Staleness::new()),
        recorder,
        resync: Duration::from_secs(3600),
        staleness_threshold: Duration::from_secs(600),
        backoffs: std::sync::Mutex::new(std::collections::HashMap::new()),
    };
    (ctx, dir)
}

fn test_cr(yaml: &str) -> BunkerSecret {
    let spec: BunkerSecretSpec = serde_yaml::from_str(yaml).unwrap();
    let mut cr = BunkerSecret::new("app", spec);
    cr.metadata.namespace = Some("ns".into());
    cr.metadata.uid = Some("uid-1".into());
    cr.metadata.generation = Some(1);
    cr
}

#[tokio::test]
async fn happy_path_creates_secret_and_sets_ready() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"hunter2", 0).await;

    let cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    let script = vec![
        // 1. GET existing Secret → 404
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/app",
            404,
            json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "NotFound", "code": 404
            }),
        ),
        // 2. SSA apply of the Secret; assert rendered content + the SSA
        // contract itself (field manager, force, and the apply-patch
        // content type — not just method+path).
        expect_checked(
            "PATCH",
            "/api/v1/namespaces/ns/secrets/app",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "app", "namespace": "ns"}
            }),
            |body| {
                assert_eq!(body["data"]["PW"], json!(base64_encode(b"hunter2")));
                assert!(
                    body["metadata"]["annotations"][HASH_ANNOTATION]
                        .as_str()
                        .unwrap()
                        .starts_with("sha256:")
                );
                assert_eq!(
                    body["metadata"]["ownerReferences"][0]["kind"],
                    json!("BunkerSecret")
                );
            },
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
        // 3. status patch; assert Ready=True/Synced + bookkeeping, and the
        // same SSA contract.
        expect_checked(
            "PATCH",
            "/apis/bunker.fables-for-robots.ch/v1alpha1/namespaces/ns/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            |body| {
                let c = &body["status"]["conditions"][0];
                assert_eq!(c["type"], json!("Ready"));
                assert_eq!(c["status"], json!("True"));
                assert_eq!(c["reason"], json!("Synced"));
                assert_eq!(body["status"]["syncedSecretKeys"], json!(["PW"]));
                assert_eq!(body["status"]["targetSecretName"], json!("app"));
            },
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    let action = apply_bunker_secret(&cr, &ctx).await.unwrap();
    assert_eq!(
        action,
        kube::runtime::controller::Action::requeue(Duration::from_secs(3600))
    );
    join.await.unwrap();
}

fn base64_encode(b: &[u8]) -> String {
    use data_encoding::BASE64;
    BASE64.encode(b)
}

#[tokio::test]
async fn hash_match_skips_apply() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"hunter2", 0).await;

    let cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    // Compute the same hash the operator will: render the same map.
    let mut data = std::collections::BTreeMap::new();
    data.insert("PW".to_string(), b"hunter2".to_vec());
    let hash = secret_bunker_operator::render::content_hash(&data);

    let script = vec![
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/app",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {
                    "name": "app", "namespace": "ns",
                    "annotations": {HASH_ANNOTATION: hash},
                    "ownerReferences": [{"apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
                        "kind": "BunkerSecret", "name": "app", "uid": "uid-1", "controller": true}]
                },
                // The skip gate now hashes actual `data`, not the annotation
                // — a true no-op needs the data to genuinely match too.
                "data": {"PW": base64_encode(b"hunter2")}
            }),
        ),
        // No Secret PATCH — straight to status.
        expect(
            "PATCH",
            "/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();
    // applies_total{skipped} == 1
    let fams = ctx.metrics.registry.gather();
    let fam = fams
        .iter()
        .find(|f| f.name() == "bunker_secret_applies_total")
        .unwrap();
    let m = fam
        .metric
        .iter()
        .find(|m| m.label.iter().any(|l| l.value() == "skipped"))
        .unwrap();
    assert_eq!(m.counter.value() as u64, 1);
}

/// A manually-edited Secret data value must be reverted even though its
/// content-hash annotation still carries the CORRECT desired hash (the hand
/// edit touched `data` but left the annotation alone) — the skip gate has to
/// compare actual content, not trust the annotation as a cache of it.
#[tokio::test]
async fn manual_data_edit_is_reverted_despite_matching_annotation() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"hunter2", 0).await;

    let cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    // The annotation the operator would have written for the CORRECT
    // ("hunter2") content — a stale/tampered `data` alongside it is exactly
    // the scenario a hand edit produces (the editor changes the value but
    // never recomputes this operator-owned annotation).
    let mut data = std::collections::BTreeMap::new();
    data.insert("PW".to_string(), b"hunter2".to_vec());
    let hash = secret_bunker_operator::render::content_hash(&data);

    let script = vec![
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/app",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {
                    "name": "app", "namespace": "ns",
                    "annotations": {HASH_ANNOTATION: hash},
                    "ownerReferences": [{"apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
                        "kind": "BunkerSecret", "name": "app", "uid": "uid-1", "controller": true}]
                },
                // Tampered: a human changed the value in place without
                // touching the annotation.
                "data": {"PW": base64_encode(b"tampered-by-hand")}
            }),
        ),
        // The skip gate must NOT trust the (stale) matching annotation —
        // content differs, so this has to be a real revert PATCH.
        expect_checked(
            "PATCH",
            "/api/v1/namespaces/ns/secrets/app",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "app", "namespace": "ns"}
            }),
            |body| {
                assert_eq!(body["data"]["PW"], json!(base64_encode(b"hunter2")));
            },
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
        expect(
            "PATCH",
            "/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();
    // applies_total{applied} == 1 — this was a real revert, not a skip.
    let fams = ctx.metrics.registry.gather();
    let fam = fams
        .iter()
        .find(|f| f.name() == "bunker_secret_applies_total")
        .unwrap();
    let m = fam
        .metric
        .iter()
        .find(|m| m.label.iter().any(|l| l.value() == "applied"))
        .unwrap();
    assert_eq!(m.counter.value() as u64, 1);
}

#[tokio::test]
async fn unowned_secret_is_conflict_not_overwrite() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"x", 0).await;

    let cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    let script = vec![
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/app",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "app", "namespace": "ns"}   // no ownerReferences
            }),
        ),
        // Transition to a failure reason → one Warning k8s Event.
        expect(
            "POST",
            "events",
            201,
            json!({
                "apiVersion": "events.k8s.io/v1", "kind": "Event",
                "metadata": {"name": "app.warn", "namespace": "ns"}
            }),
        ),
        expect_checked(
            "PATCH",
            "/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            |body| {
                let c = &body["status"]["conditions"][0];
                assert_eq!(c["status"], json!("False"));
                assert_eq!(c["reason"], json!("Conflict"));
            },
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn revocation_freezes_previously_synced_cr() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"x", 0).await;

    let mut cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    // Previously synced: lastSyncTime present in status.
    cr.status = Some(BunkerSecretStatus {
        last_sync_time: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::now(),
        )),
        ..Default::default()
    });

    let script = vec![
        // No Secret GET/PATCH — the render fails first.
        // Transition to AccessRevoked → one Warning k8s Event, then status:
        expect(
            "POST",
            "events",
            201,
            json!({
                "apiVersion": "events.k8s.io/v1", "kind": "Event",
                "metadata": {"name": "app.warn", "namespace": "ns"}
            }),
        ),
        expect_checked(
            "PATCH",
            "/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            |body| {
                assert_eq!(
                    body["status"]["conditions"][0]["reason"],
                    json!("AccessRevoked")
                );
            },
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    // Revoke: remove the identity's read grant → mirror empties (GroupRemoved).
    let r = bunker
        .admin
        .request(&secret_bunker_iroh::proto::Request::Grant {
            group: "prod".into(),
            identity: "op".into(),
            perms: 0,
        })
        .await
        .unwrap();
    assert_eq!(r, secret_bunker_iroh::proto::Response::Ok);
    // Await the mirror actually emptying, with the usual deadline.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while ctx.replica.groups().map(|g| !g.is_empty()).unwrap_or(true) {
        assert!(std::time::Instant::now() < deadline, "mirror never emptied");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();
}

/// Renaming a CR onto a target name that collides with a Secret we don't own
/// must not delete/orphan the OLD Secret before discovering the collision:
/// that would leave the workload with no Secret at all. The ownership check
/// on the new name has to run, and fail with Conflict, before any cleanup of
/// the previous name is attempted. The script below has no expectation that
/// mentions "old" at all — any call the code makes to the old target (GET,
/// PATCH, or DELETE) is either a path-substring mismatch against the
/// currently-expected step, or (if the script is already exhausted) a
/// request the closed mock can't answer — both fail the test.
#[tokio::test]
async fn rename_onto_unowned_secret_is_conflict_and_old_target_untouched() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"x", 0).await;

    let mut cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    // This CR previously applied to "old"; target_name() now resolves to the
    // CR's own name "app" (no spec.target override) — a rename.
    cr.status = Some(BunkerSecretStatus {
        target_secret_name: Some("old".into()),
        ..Default::default()
    });

    let script = vec![
        // GET the NEW target ("app") — exists, but not owned by this CR.
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/app",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "app", "namespace": "ns"} // no ownerReferences
            }),
        ),
        expect(
            "POST",
            "events",
            201,
            json!({
                "apiVersion": "events.k8s.io/v1", "kind": "Event",
                "metadata": {"name": "app.warn", "namespace": "ns"}
            }),
        ),
        expect_checked(
            "PATCH",
            "/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            |body| {
                let c = &body["status"]["conditions"][0];
                assert_eq!(c["status"], json!("False"));
                assert_eq!(c["reason"], json!("Conflict"));
            },
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
        // Script ends here — no GET/PATCH/DELETE against "old" is expected.
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();
}

/// Positive rename cleanup, `deletionPolicy: Delete`: once the new target
/// ("app") is confirmed safe and applied, the previous target ("old") — a
/// Secret this CR owns — is deleted outright. Call order matters here:
/// cleanup of the old name only runs AFTER the new target's apply-or-skip
/// (see the ordering comment in `apply_bunker_secret`), so the script below
/// scripts GET-new, PATCH-new, GET-old, DELETE-old, status-PATCH in exactly
/// that order.
#[tokio::test]
async fn rename_cleanup_deletes_old_target_under_delete_policy() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"hunter2", 0).await;

    let mut cr = test_cr(
        "deletionPolicy: Delete\ndata: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]",
    );
    // Previously applied under "old"; target_name() now resolves to "app"
    // (no spec.target override) — a rename.
    cr.status = Some(BunkerSecretStatus {
        target_secret_name: Some("old".into()),
        ..Default::default()
    });

    let script = vec![
        // 1. GET the new target ("app") — absent.
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/app",
            404,
            json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "NotFound", "code": 404
            }),
        ),
        // 2. SSA apply of the new target.
        expect_checked(
            "PATCH",
            "/api/v1/namespaces/ns/secrets/app",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "app", "namespace": "ns"}
            }),
            |body| {
                assert_eq!(body["data"]["PW"], json!(base64_encode(b"hunter2")));
            },
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
        // 3. GET the old target ("old") — present, owned by this CR's uid.
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/old",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "old", "namespace": "ns",
                    "ownerReferences": [{"apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
                        "kind": "BunkerSecret", "name": "app", "uid": "uid-1", "controller": true}]}
            }),
        ),
        // 4. DELETE the old target — Delete policy, owned, so it goes.
        expect(
            "DELETE",
            "/api/v1/namespaces/ns/secrets/old",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "old", "namespace": "ns"}
            }),
        ),
        // 5. status PATCH — targetSecretName now reflects the new name.
        expect_checked(
            "PATCH",
            "/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            |body| {
                assert_eq!(body["status"]["targetSecretName"], json!("app"));
            },
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();
}

/// Same rename scenario, but `deletionPolicy: Retain`: instead of a DELETE,
/// the old target gets a merge-patch that nulls out `metadata.ownerReferences`
/// so garbage collection never touches it — GC-orphaning, not deletion.
#[tokio::test]
async fn rename_cleanup_orphans_old_target_under_retain_policy() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"hunter2", 0).await;

    // Retain is the default `deletionPolicy`, so the bare data-only spec
    // below already exercises it.
    let mut cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    cr.status = Some(BunkerSecretStatus {
        target_secret_name: Some("old".into()),
        ..Default::default()
    });

    let script = vec![
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/app",
            404,
            json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "NotFound", "code": 404
            }),
        ),
        expect_checked(
            "PATCH",
            "/api/v1/namespaces/ns/secrets/app",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "app", "namespace": "ns"}
            }),
            |body| {
                assert_eq!(body["data"]["PW"], json!(base64_encode(b"hunter2")));
            },
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/old",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "old", "namespace": "ns",
                    "ownerReferences": [{"apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
                        "kind": "BunkerSecret", "name": "app", "uid": "uid-1", "controller": true}]}
            }),
        ),
        // Retain: a merge PATCH clearing ownerReferences, not a DELETE.
        expect_checked(
            "PATCH",
            "/api/v1/namespaces/ns/secrets/old",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "old", "namespace": "ns"}
            }),
            |body| {
                assert!(
                    body["metadata"]["ownerReferences"].is_null(),
                    "Retain must orphan the old target by clearing ownerReferences, got {body}"
                );
            },
        ),
        expect_checked(
            "PATCH",
            "/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            |body| {
                assert_eq!(body["status"]["targetSecretName"], json!("app"));
            },
        )
        .with_query_contains("fieldManager=secret-bunker-operator")
        .with_query_contains("force=true")
        .with_content_type("application/apply-patch+yaml"),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();
}

/// Second call, same converged state, no bunker mutation in between: the
/// condition (status/reason/message), lastSyncTime, observedGeneration,
/// syncedSecretKeys, and targetSecretName the operator would compute are all
/// identical to what's already on the CR, so `patch_status` must skip the
/// write entirely. The second script has no status-PATCH expectation at
/// all — any attempt to PATCH status here is either a path mismatch against
/// the (already-consumed) script, or a call the closed mock can't answer;
/// both fail the test via `.unwrap()` on a `kube::Error`.
#[tokio::test]
async fn second_reconcile_with_unchanged_state_skips_status_patch() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"hunter2", 0).await;

    let cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");

    let captured_status: Arc<std::sync::Mutex<Option<serde_json::Value>>> =
        Arc::new(std::sync::Mutex::new(None));
    let captured_status_check = captured_status.clone();

    let script = vec![
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/app",
            404,
            json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "NotFound", "code": 404
            }),
        ),
        expect_checked(
            "PATCH",
            "/api/v1/namespaces/ns/secrets/app",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "app", "namespace": "ns"}
            }),
            |_body| {},
        ),
        expect_checked(
            "PATCH",
            "/apis/bunker.fables-for-robots.ch/v1alpha1/namespaces/ns/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            move |body| {
                *captured_status_check.lock().unwrap() = Some(body["status"].clone());
            },
        ),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();

    // Reconstruct the CR exactly as the apiserver would now show it, per the
    // status this reconcile just wrote.
    let status_json = captured_status.lock().unwrap().clone().unwrap();
    let status: BunkerSecretStatus = serde_json::from_value(status_json).unwrap();
    let mut cr2 = cr.clone();
    cr2.status = Some(status);

    // Same hash the (unchanged) bunker content renders to, so the Secret GET
    // below reports an owned, up-to-date Secret and the apply is skipped too
    // — isolating the assertion to the status-patch skip specifically.
    let mut data = std::collections::BTreeMap::new();
    data.insert("PW".to_string(), b"hunter2".to_vec());
    let hash = secret_bunker_operator::render::content_hash(&data);

    let script2 = vec![expect(
        "GET",
        "/api/v1/namespaces/ns/secrets/app",
        200,
        json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {
                "name": "app", "namespace": "ns",
                "annotations": {HASH_ANNOTATION: hash},
                "ownerReferences": [{"apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
                    "kind": "BunkerSecret", "name": "app", "uid": "uid-1", "controller": true}]
            },
            // The skip gate hashes actual `data` now — needs to genuinely
            // match for the apply (and therefore this status-patch-skip
            // isolation) to hold.
            "data": {"PW": base64_encode(b"hunter2")}
        }),
    )];
    let (client2, join2) = scripted(script2);
    let recorder2 = kube::runtime::events::Recorder::new(
        client2.clone(),
        kube::runtime::events::Reporter {
            controller: "secret-bunker-operator".into(),
            instance: None,
        },
    );
    let ctx2 = Context {
        client: client2,
        source: ReplicaSource(ctx.replica.clone()),
        replica: ctx.replica.clone(),
        metrics: ctx.metrics.clone(),
        staleness: ctx.staleness.clone(),
        recorder: recorder2,
        resync: ctx.resync,
        staleness_threshold: ctx.staleness_threshold,
        backoffs: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    apply_bunker_secret(&cr2, &ctx2).await.unwrap();
    join2.await.unwrap();
}

/// Ready=False transitions publish a Warning event on every transition, not
/// just the render-error reasons — AwaitingSync included. Calls
/// `apply_bunker_secret` before the replica's first sync completes (no
/// `await_mirrored`), which is only deterministic because this is a
/// current-thread `#[tokio::test]`: the replica's background sync task
/// can't run until this test task itself yields at an `.await`, and the
/// AwaitingSync gate is checked synchronously as the very first thing
/// `apply_bunker_secret` does — mirroring the same current-thread-ordering
/// argument the event-bridge Lagged test in `events.rs` relies on.
#[tokio::test]
async fn awaiting_sync_publishes_event_on_first_transition() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"x", 0).await;

    let cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    let dir = tempfile::tempdir().unwrap();
    let (replica, _rx) = bunker
        .replica_for(reader, &dir.path().join("m.sqlite"))
        .await;
    let replica = Arc::new(replica);
    assert!(
        replica.status().last_synced.is_none(),
        "replica must not have synced yet for this test to be meaningful"
    );

    let script = vec![
        expect(
            "POST",
            "events",
            201,
            json!({
                "apiVersion": "events.k8s.io/v1", "kind": "Event",
                "metadata": {"name": "app.warn", "namespace": "ns"}
            }),
        ),
        expect_checked(
            "PATCH",
            "/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            |body| {
                assert_eq!(
                    body["status"]["conditions"][0]["reason"],
                    json!("AwaitingSync")
                );
            },
        ),
    ];
    let (client, join) = scripted(script);
    let recorder = kube::runtime::events::Recorder::new(
        client.clone(),
        kube::runtime::events::Reporter {
            controller: "secret-bunker-operator".into(),
            instance: None,
        },
    );
    let ctx = Context {
        client,
        source: ReplicaSource(replica.clone()),
        replica,
        metrics: Metrics::new().unwrap(),
        staleness: Arc::new(Staleness::new()),
        recorder,
        resync: Duration::from_secs(3600),
        staleness_threshold: Duration::from_secs(600),
        backoffs: std::sync::Mutex::new(std::collections::HashMap::new()),
    };

    let action = apply_bunker_secret(&cr, &ctx).await.unwrap();
    assert_eq!(
        action,
        kube::runtime::controller::Action::requeue(Duration::from_secs(5))
    );
    join.await.unwrap();
}
