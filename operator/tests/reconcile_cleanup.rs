mod common;
mod kubemock;

use std::sync::Arc;
use std::time::Duration;

use common::TestBunker;
use iroh::SecretKey;
use kubemock::{expect, expect_checked, scripted};
use secret_bunker_operator::bunker::{ReplicaSource, Staleness};
use secret_bunker_operator::crd::{BunkerSecret, BunkerSecretSpec};
use secret_bunker_operator::metrics::Metrics;
use secret_bunker_operator::reconcile::{Context, cleanup_bunker_secret};
use serde_json::json;

async fn ctx_with(client: kube::Client) -> (Context, tempfile::TempDir) {
    let bunker = TestBunker::spawn().await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    let dir = tempfile::tempdir().unwrap();
    let (replica, _rx) = bunker
        .replica_for(reader, &dir.path().join("m.sqlite"))
        .await;
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

fn deleting_cr(policy: &str) -> BunkerSecret {
    let spec: BunkerSecretSpec =
        serde_yaml::from_str(&format!("deletionPolicy: {policy}")).unwrap();
    let mut cr = BunkerSecret::new("app", spec);
    cr.metadata.namespace = Some("ns".into());
    cr.metadata.uid = Some("uid-1".into());
    cr
}

#[tokio::test]
async fn retain_strips_owner_references() {
    let script = vec![
        expect(
            "GET",
            "/api/v1/namespaces/ns/secrets/app",
            200,
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "app", "namespace": "ns",
                    "ownerReferences": [{"apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
                        "kind": "BunkerSecret", "name": "app", "uid": "uid-1", "controller": true}]}
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
                assert!(
                    body["metadata"]["ownerReferences"].is_null(),
                    "Retain must orphan by clearing ownerReferences, got {body}"
                );
            },
        ),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = ctx_with(client).await;
    cleanup_bunker_secret(&deleting_cr("Retain"), &ctx)
        .await
        .unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn delete_policy_leaves_gc_to_owner_reference() {
    // No API calls at all: GC cascades via the ownerReference.
    let (client, join) = scripted(vec![]);
    let (ctx, _dir) = ctx_with(client).await;
    cleanup_bunker_secret(&deleting_cr("Delete"), &ctx)
        .await
        .unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn retain_tolerates_missing_secret() {
    // 404 → nothing to orphan; done.
    let script = vec![expect(
        "GET",
        "/api/v1/namespaces/ns/secrets/app",
        404,
        json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404
        }),
    )];
    let (client, join) = scripted(script);
    let (ctx, _dir) = ctx_with(client).await;
    cleanup_bunker_secret(&deleting_cr("Retain"), &ctx)
        .await
        .unwrap();
    join.await.unwrap();
}

/// Secret exists but is owned by a different BunkerSecret (different uid) —
/// Retain must leave it alone entirely. The script contains only the GET; no
/// further expectation follows, so any PATCH or DELETE the code might issue
/// fails the test (closed/exhausted mock).
#[tokio::test]
async fn retain_leaves_unowned_secret_alone() {
    let script = vec![expect(
        "GET",
        "/api/v1/namespaces/ns/secrets/app",
        200,
        json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "app", "namespace": "ns",
                "ownerReferences": [{"apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
                    "kind": "BunkerSecret", "name": "app", "uid": "some-other-uid", "controller": true}]}
        }),
    )];
    let (client, join) = scripted(script);
    let (ctx, _dir) = ctx_with(client).await;
    cleanup_bunker_secret(&deleting_cr("Retain"), &ctx)
        .await
        .unwrap();
    join.await.unwrap();
}
