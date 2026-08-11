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
        // 2. SSA apply of the Secret; assert rendered content
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
        ),
        // 3. status patch; assert Ready=True/Synced + bookkeeping
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
        ),
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
                }
            }),
        ),
        // No Secret PATCH — straight to status.
        expect(
            "PATCH",
            "/bunkersecrets/app/status",
            200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
        ),
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
        ),
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
        ),
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
