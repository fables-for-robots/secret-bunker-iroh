mod common;

use std::sync::Arc;
use std::time::Duration;

use common::TestBunker;
use iroh::SecretKey;
use secret_bunker_operator::bunker::{ReplicaSource, Staleness, spawn_replica};
use secret_bunker_operator::render::{SecretSource, SourceError};

#[tokio::test]
async fn replica_source_serves_and_classifies() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"hunter2", 0).await;

    let dir = tempfile::tempdir().unwrap();
    let (replica, _rx) = bunker
        .replica_for(reader, &dir.path().join("mirror.sqlite"))
        .await;
    common::await_mirrored(&replica, "prod", "pw").await;

    let source = ReplicaSource(Arc::new(replica));
    assert_eq!(source.get("prod", "pw").unwrap(), b"hunter2".to_vec());
    assert_eq!(source.list("prod").unwrap(), vec!["pw".to_string()]);
    assert_eq!(
        source.get("nope", "x").unwrap_err(),
        SourceError::MissingGroup
    );
    assert_eq!(source.list("nope").unwrap_err(), SourceError::MissingGroup);
    assert_eq!(
        source.get("prod", "nope").unwrap_err(),
        SourceError::MissingSecret
    );
}

#[tokio::test]
async fn spawn_replica_loads_key_from_explicit_path() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("g").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("g", "op").await;
    bunker.put("g", "s", b"v", 0).await;

    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("identity.key");
    std::fs::write(
        &key_file,
        secret_bunker_iroh::keys::encode_endpoint_key(&reader),
    )
    .unwrap();

    // Direct socket addrs from the in-process bunker's EndpointAddr.
    let addrs: Vec<std::net::SocketAddr> = bunker
        .addr
        .addrs
        .iter()
        .filter_map(|a| match a {
            iroh::TransportAddr::Ip(s) => Some(*s),
            _ => None,
        })
        .collect();
    assert!(
        !addrs.is_empty(),
        "in-process bunker must expose an IP transport addr"
    );

    let key = secret_bunker_iroh::keys::load_endpoint_key(&key_file).unwrap();
    let replica = spawn_replica(
        &bunker.addr.id.to_string(),
        &addrs,
        key,
        &dir.path().join("mirror.sqlite"),
    )
    .await
    .unwrap();
    let got = common::await_mirrored(&replica, "g", "s").await;
    assert_eq!(got, b"v".to_vec());
    // A missing key file is still a hard error at load time — file mode
    // never auto-generates an identity.
    let err =
        secret_bunker_iroh::keys::load_endpoint_key(&dir.path().join("missing.key")).unwrap_err();
    assert!(err.to_string().contains("reading endpoint key"), "{err}");
}

#[test]
fn staleness_tracks_disconnection() {
    let s = Staleness::new();
    // Fresh state counts as disconnected-since-startup.
    assert!(s.disconnected_for().is_some());
    s.set_connected(true);
    assert_eq!(s.disconnected_for(), None);
    s.set_connected(false);
    assert!(s.disconnected_for().unwrap() < Duration::from_secs(1));
}
