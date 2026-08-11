//! End-to-end test: a bunker and several clients as real iroh endpoints in
//! one process (Minimal preset: no relays, no discovery).

use std::path::Path;

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, SecretKey};

use secret_bunker_iroh::client::Client;
use secret_bunker_iroh::proto::{ALPN, Request, Response};
use secret_bunker_iroh::replica::{Replica, ReplicaEvent};
use secret_bunker_iroh::server::Bunker;
use secret_bunker_iroh::store::{RECIPIENT_BACKUP, Store};
use secret_bunker_iroh::sync::{self, SYNC_ALPN, SyncMessage, SyncRequest};

async fn client_endpoint(secret: SecretKey) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .bind()
        .await
        .expect("binding client endpoint")
}

fn init_store(
    db: &Path,
    op: &age::x25519::Identity,
    backup: &age::x25519::Identity,
    admin: &iroh::EndpointId,
) -> Store {
    let mut store = Store::open(db).unwrap();
    store
        .init(
            &op.to_public().to_string(),
            &backup.to_public().to_string(),
            &admin.to_string(),
            "admin",
        )
        .unwrap();
    store
}

#[tokio::test]
async fn full_flow() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bunker.sqlite");

    let op = age::x25519::Identity::generate();
    let backup = age::x25519::Identity::generate();

    let admin_secret = SecretKey::generate();
    let reader_secret = SecretKey::generate();
    let stranger_secret = SecretKey::generate();

    let store = init_store(&db, &op, &backup, &admin_secret.public());
    let bunker = Bunker::new(store, op).unwrap();

    let server = Endpoint::bind(presets::Minimal).await.unwrap();
    let router = Router::builder(server).accept(ALPN, bunker).spawn();
    let addr = router.endpoint().addr();

    // --- admin: create group, store a secret ---
    let admin = Client::with_endpoint(client_endpoint(admin_secret).await, addr.clone())
        .await
        .unwrap();
    assert_eq!(
        admin
            .request(&Request::CreateGroup {
                name: "prod".into()
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "prod".into(),
                name: "db-password".into(),
                value: b"hunter2".to_vec(),
                expected_version: 0,
            })
            .await
            .unwrap(),
        Response::Version { version: 1 }
    );

    // CAS: stale expected_version is rejected with the current version.
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "prod".into(),
                name: "db-password".into(),
                value: b"changed".to_vec(),
                expected_version: 0,
            })
            .await
            .unwrap(),
        Response::VersionConflict { current: 1 }
    );

    // --- register a reader and grant read-only access ---
    assert_eq!(
        admin
            .request(&Request::AddIdentity {
                name: "reader".into(),
                endpoint_id: reader_secret.public().to_string(),
                service_admin: false,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Grant {
                group: "prod".into(),
                identity: "reader".into(),
                perms: 1,
            })
            .await
            .unwrap(),
        Response::Ok
    );

    // --- reader: can read, cannot write, cannot admin ---
    let reader = Client::with_endpoint(client_endpoint(reader_secret).await, addr.clone())
        .await
        .unwrap();
    assert_eq!(
        reader
            .request(&Request::Get {
                group: "prod".into(),
                name: "db-password".into()
            })
            .await
            .unwrap(),
        Response::Secret {
            value: b"hunter2".to_vec(),
            version: 1
        }
    );
    assert_eq!(
        reader
            .request(&Request::Put {
                group: "prod".into(),
                name: "db-password".into(),
                value: b"evil".to_vec(),
                expected_version: 1,
            })
            .await
            .unwrap(),
        Response::Denied
    );
    assert_eq!(
        reader
            .request(&Request::RotateDek {
                group: "prod".into()
            })
            .await
            .unwrap(),
        Response::Denied
    );
    assert_eq!(
        reader.request(&Request::ListIdentities).await.unwrap(),
        Response::Denied
    );

    // --- stranger: can connect, can do nothing, learns nothing ---
    let stranger = Client::with_endpoint(client_endpoint(stranger_secret).await, addr.clone())
        .await
        .unwrap();
    for req in [
        Request::Get {
            group: "prod".into(),
            name: "db-password".into(),
        },
        Request::Get {
            group: "no-such-group".into(),
            name: "nope".into(),
        },
        Request::List {
            group: "prod".into(),
        },
        Request::CreateGroup {
            name: "mine".into(),
        },
        Request::ListIdentities,
        Request::RotateDek {
            group: "prod".into(),
        },
    ] {
        assert_eq!(
            stranger.request(&req).await.unwrap(),
            Response::Denied,
            "stranger must get a uniform denial for {req:?}"
        );
    }

    // Denials are uniform for authorized readers too: a missing secret and
    // a missing group are indistinguishable.
    assert_eq!(
        reader
            .request(&Request::Get {
                group: "prod".into(),
                name: "no-such-secret".into()
            })
            .await
            .unwrap(),
        Response::Denied
    );
    assert_eq!(
        reader
            .request(&Request::Get {
                group: "no-such-group".into(),
                name: "x".into()
            })
            .await
            .unwrap(),
        Response::Denied
    );

    // --- DEK rotation: old secrets stay readable, new writes use new DEK ---
    assert_eq!(
        admin
            .request(&Request::RotateDek {
                group: "prod".into()
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "prod".into(),
                name: "api-token".into(),
                value: b"tok-123".to_vec(),
                expected_version: 0,
            })
            .await
            .unwrap(),
        Response::Version { version: 1 }
    );
    assert_eq!(
        reader
            .request(&Request::Get {
                group: "prod".into(),
                name: "db-password".into()
            })
            .await
            .unwrap(),
        Response::Secret {
            value: b"hunter2".to_vec(),
            version: 1
        },
        "pre-rotation secret must remain readable via the retained old DEK"
    );

    // --- revocation: takes effect on the next request ---
    assert_eq!(
        admin
            .request(&Request::Grant {
                group: "prod".into(),
                identity: "reader".into(),
                perms: 0,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        reader
            .request(&Request::Get {
                group: "prod".into(),
                name: "db-password".into()
            })
            .await
            .unwrap(),
        Response::Denied,
        "revoked identity must be denied on its existing connection"
    );

    // --- update and delete with CAS ---
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "prod".into(),
                name: "db-password".into(),
                value: b"hunter3".to_vec(),
                expected_version: 1,
            })
            .await
            .unwrap(),
        Response::Version { version: 2 }
    );
    assert_eq!(
        admin
            .request(&Request::Get {
                group: "prod".into(),
                name: "db-password".into()
            })
            .await
            .unwrap(),
        Response::Secret {
            value: b"hunter3".to_vec(),
            version: 2
        }
    );
    assert_eq!(
        admin
            .request(&Request::Delete {
                group: "prod".into(),
                name: "db-password".into(),
                expected_version: 2,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Get {
                group: "prod".into(),
                name: "db-password".into()
            })
            .await
            .unwrap(),
        Response::Denied,
        "deleted secret is indistinguishable from one that never existed"
    );

    // The last service admin cannot be removed (would brick the service).
    assert!(matches!(
        admin
            .request(&Request::RemoveIdentity {
                name: "admin".into()
            })
            .await
            .unwrap(),
        Response::Failed { .. }
    ));

    admin.close().await;
    reader.close().await;
    stranger.close().await;
    router.shutdown().await.unwrap();
}

#[tokio::test]
async fn recovery_rewraps_deks() {
    // Simulate operational key compromise: re-wrap from backup, verify the
    // bunker serves existing secrets with the NEW operational key only.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bunker.sqlite");

    let op = age::x25519::Identity::generate();
    let backup = age::x25519::Identity::generate();
    let admin_secret = SecretKey::generate();

    // Phase 1: run with the original operational key, store a secret.
    {
        let store = init_store(&db, &op, &backup, &admin_secret.public());
        let bunker = Bunker::new(store, op.clone()).unwrap();
        let server = Endpoint::bind(presets::Minimal).await.unwrap();
        let router = Router::builder(server).accept(ALPN, bunker).spawn();
        let addr = router.endpoint().addr();
        let admin = Client::with_endpoint(client_endpoint(admin_secret.clone()).await, addr)
            .await
            .unwrap();
        assert_eq!(
            admin
                .request(&Request::CreateGroup { name: "g".into() })
                .await
                .unwrap(),
            Response::Ok
        );
        assert_eq!(
            admin
                .request(&Request::Put {
                    group: "g".into(),
                    name: "s".into(),
                    value: b"precious".to_vec(),
                    expected_version: 0,
                })
                .await
                .unwrap(),
            Response::Version { version: 1 }
        );
        admin.close().await;
        router.shutdown().await.unwrap();
    }

    // Phase 2: offline recovery with the backup key (what `recover` does).
    let new_op = age::x25519::Identity::generate();
    {
        let mut store = Store::open(&db).unwrap();
        let mut rewrapped = Vec::new();
        for (group_id, dek_version, wrapped_backup) in
            store.all_wraps_for_recipient(RECIPIENT_BACKUP).unwrap()
        {
            let dek = secret_bunker_iroh::crypto::unwrap_dek(&wrapped_backup, &backup).unwrap();
            let wrapped = secret_bunker_iroh::crypto::wrap_dek(&dek, &new_op.to_public()).unwrap();
            rewrapped.push((group_id, dek_version, wrapped));
        }
        store
            .apply_recovery(&rewrapped, &new_op.to_public().to_string())
            .unwrap();
    }

    // Phase 3: the old operational key is rejected; the new one serves.
    {
        let store = Store::open(&db).unwrap();
        assert!(
            Bunker::new(store, op).is_err(),
            "old operational key must be rejected"
        );
    }
    let store = Store::open(&db).unwrap();
    let bunker = Bunker::new(store, new_op).unwrap();
    let server = Endpoint::bind(presets::Minimal).await.unwrap();
    let router = Router::builder(server).accept(ALPN, bunker).spawn();
    let addr = router.endpoint().addr();
    let admin = Client::with_endpoint(client_endpoint(admin_secret).await, addr)
        .await
        .unwrap();
    assert_eq!(
        admin
            .request(&Request::Get {
                group: "g".into(),
                name: "s".into()
            })
            .await
            .unwrap(),
        Response::Secret {
            value: b"precious".to_vec(),
            version: 1
        }
    );
    admin.close().await;
    router.shutdown().await.unwrap();
}

#[tokio::test]
async fn mdns_discovery_connects_by_bare_endpoint_id() {
    // Server and client know nothing about each other except the server's
    // EndpointId: no relays, no DNS discovery, no address hints. mDNS
    // (swarm-discovery) on the local network must resolve it.
    // Requires a multicast-capable network interface.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bunker.sqlite");

    let op = age::x25519::Identity::generate();
    let backup = age::x25519::Identity::generate();
    let admin_secret = SecretKey::generate();

    let store = init_store(&db, &op, &backup, &admin_secret.public());
    let bunker = Bunker::new(store, op).unwrap();

    let server = Endpoint::builder(presets::Minimal)
        .address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder())
        .bind()
        .await
        .unwrap();
    let server_id = server.id();
    let router = Router::builder(server).accept(ALPN, bunker).spawn();

    let client_ep = Endpoint::builder(presets::Minimal)
        .secret_key(admin_secret)
        .address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder().advertise(false))
        .bind()
        .await
        .unwrap();

    // Bare EndpointId: the only way to find the server is mDNS resolution.
    let admin = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        Client::with_endpoint(client_ep, server_id),
    )
    .await
    .expect("mDNS resolution timed out")
    .unwrap();

    assert_eq!(
        admin
            .request(&Request::CreateGroup { name: "lan".into() })
            .await
            .unwrap(),
        Response::Ok
    );
    admin.close().await;
    router.shutdown().await.unwrap();
}

#[tokio::test]
async fn list_groups_and_acl_visibility() {
    // ListGroups shows each caller exactly what it may see: service admins
    // see all groups, users see only groups they hold permissions on, and
    // unknown peers see nothing at all. GroupAcl requires group admin.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bunker.sqlite");

    let op = age::x25519::Identity::generate();
    let backup = age::x25519::Identity::generate();
    let admin_secret = SecretKey::generate();
    let reader_secret = SecretKey::generate();
    let stranger_secret = SecretKey::generate();

    let store = init_store(&db, &op, &backup, &admin_secret.public());
    let bunker = Bunker::new(store, op).unwrap();
    let server = Endpoint::bind(presets::Minimal).await.unwrap();
    let router = Router::builder(server).accept(ALPN, bunker).spawn();
    let addr = router.endpoint().addr();

    let admin = Client::with_endpoint(client_endpoint(admin_secret).await, addr.clone())
        .await
        .unwrap();
    for group in ["alpha", "beta"] {
        assert_eq!(
            admin
                .request(&Request::CreateGroup { name: group.into() })
                .await
                .unwrap(),
            Response::Ok
        );
    }
    assert_eq!(
        admin
            .request(&Request::AddIdentity {
                name: "reader".into(),
                endpoint_id: reader_secret.public().to_string(),
                service_admin: false,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Grant {
                group: "alpha".into(),
                identity: "reader".into(),
                perms: 1,
            })
            .await
            .unwrap(),
        Response::Ok
    );

    // Service admin sees every group, with its own perms (rwa on both,
    // granted at creation).
    match admin.request(&Request::ListGroups).await.unwrap() {
        Response::Groups {
            service_admin,
            groups,
        } => {
            assert!(service_admin);
            assert_eq!(
                groups
                    .iter()
                    .map(|g| (g.name.as_str(), g.perms))
                    .collect::<Vec<_>>(),
                vec![("alpha", 7), ("beta", 7)]
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    // The reader sees only the group it was granted on — beta stays
    // invisible.
    let reader = Client::with_endpoint(client_endpoint(reader_secret).await, addr.clone())
        .await
        .unwrap();
    match reader.request(&Request::ListGroups).await.unwrap() {
        Response::Groups {
            service_admin,
            groups,
        } => {
            assert!(!service_admin);
            assert_eq!(
                groups
                    .iter()
                    .map(|g| (g.name.as_str(), g.perms))
                    .collect::<Vec<_>>(),
                vec![("alpha", 1)]
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    // Unknown peers get the uniform denial, not an empty list.
    let stranger = Client::with_endpoint(client_endpoint(stranger_secret).await, addr.clone())
        .await
        .unwrap();
    assert_eq!(
        stranger.request(&Request::ListGroups).await.unwrap(),
        Response::Denied
    );

    // GroupAcl: group admin sees the entries; a mere reader is denied.
    assert_eq!(
        admin
            .request(&Request::GroupAcl {
                group: "alpha".into()
            })
            .await
            .unwrap(),
        Response::Acl(vec![("admin".into(), 7), ("reader".into(), 1)])
    );
    assert_eq!(
        reader
            .request(&Request::GroupAcl {
                group: "alpha".into()
            })
            .await
            .unwrap(),
        Response::Denied
    );

    admin.close().await;
    reader.close().await;
    stranger.close().await;
    router.shutdown().await.unwrap();
}

// ---- replication protocol (secret-bunker-sync/1) ----

/// Authoritative router serving both the client ALPN and the sync ALPN.
async fn spawn_authoritative(store: Store, op: age::x25519::Identity) -> (Router, EndpointAddr) {
    let bunker = Bunker::new(store, op).unwrap();
    let endpoint = Endpoint::bind(presets::Minimal).await.unwrap();
    let router = Router::builder(endpoint)
        .accept(ALPN, bunker.clone())
        .accept(SYNC_ALPN, bunker.sync_handler())
        .spawn();
    let addr = router.endpoint().addr();
    (router, addr)
}

/// Open a sync stream on `conn` and send one request. The send half is
/// returned (not just dropped) so the stream stays open for the reply.
async fn sync_request(
    conn: &iroh::endpoint::Connection,
    req: &SyncRequest,
) -> (iroh::endpoint::SendStream, iroh::endpoint::RecvStream) {
    let (mut send, recv) = conn.open_bi().await.unwrap();
    sync::write_msg(&mut send, req).await.unwrap();
    (send, recv)
}

/// Read one sync message, failing loudly on timeout or stream end.
async fn next_sync_msg(recv: &mut iroh::endpoint::RecvStream) -> SyncMessage {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        sync::read_msg::<SyncMessage>(recv),
    )
    .await
    .expect("timed out waiting for a sync message")
    .expect("reading sync message")
    .expect("sync stream ended unexpectedly")
}

// ---- replica engine (`Replica`) ----

/// An endpoint that can dial the authoritative node by bare EndpointId: a
/// memory address book seeded with its full address stands in for
/// discovery, which these tests deliberately run without.
async fn replica_endpoint(secret: SecretKey, authoritative: &EndpointAddr) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .address_lookup(iroh::address_lookup::MemoryLookup::from_endpoint_info([
            authoritative.clone(),
        ]))
        .bind()
        .await
        .expect("binding replica endpoint")
}

/// Await the next replica event, failing loudly on timeout.
async fn next_replica_event(
    rx: &mut tokio::sync::broadcast::Receiver<ReplicaEvent>,
) -> ReplicaEvent {
    tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv())
        .await
        .expect("timed out waiting for a replica event")
        .expect("replica event channel closed")
}

/// Await `want`, skipping a bounded number of other events (some steps may
/// legitimately surface an extra event first, e.g. a delete-then-recreate
/// split across two push rounds).
async fn await_replica_event(
    rx: &mut tokio::sync::broadcast::Receiver<ReplicaEvent>,
    want: &ReplicaEvent,
) {
    for _ in 0..32 {
        if next_replica_event(rx).await == *want {
            return;
        }
    }
    panic!("event {want:?} never arrived");
}

#[tokio::test]
async fn replica_engine_full_flow() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bunker.sqlite");
    let replica_db = dir.path().join("replica.sqlite");

    let op = age::x25519::Identity::generate();
    let backup = age::x25519::Identity::generate();
    let admin_secret = SecretKey::generate();
    let replica_secret = SecretKey::generate();

    let store = init_store(&db, &op, &backup, &admin_secret.public());
    let (router, addr) = spawn_authoritative(store, op).await;

    // --- authoritative content: g1 (granted) and g2 (not granted) ---
    let admin = Client::with_endpoint(client_endpoint(admin_secret).await, addr.clone())
        .await
        .unwrap();
    for group in ["g1", "g2"] {
        assert_eq!(
            admin
                .request(&Request::CreateGroup { name: group.into() })
                .await
                .unwrap(),
            Response::Ok
        );
    }
    assert_eq!(
        admin
            .request(&Request::AddIdentity {
                name: "replica".into(),
                endpoint_id: replica_secret.public().to_string(),
                service_admin: false,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Grant {
                group: "g1".into(),
                identity: "replica".into(),
                perms: 1,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    for (group, name, value) in [("g1", "s1", "s1-plaintext"), ("g2", "sx", "sx-plaintext")] {
        assert_eq!(
            admin
                .request(&Request::Put {
                    group: group.into(),
                    name: name.into(),
                    value: value.as_bytes().to_vec(),
                    expected_version: 0,
                })
                .await
                .unwrap(),
            Response::Version { version: 1 }
        );
    }

    // --- spawn the replica and follow its initial sync ---
    let ep = replica_endpoint(replica_secret.clone(), &addr).await;
    let replica = Replica::builder()
        .store_path(&replica_db)
        .secret_key(replica_secret.clone())
        .authoritative(addr.id)
        .endpoint(ep.clone())
        .spawn()
        .await
        .unwrap();
    // Subscribing directly after spawn: the sync task cannot have finished
    // its QUIC handshake (let alone the manifest) in the meantime.
    let mut rx = replica.subscribe();

    assert_eq!(next_replica_event(&mut rx).await, ReplicaEvent::Connected);
    assert_eq!(
        next_replica_event(&mut rx).await,
        ReplicaEvent::GroupAdded { group: "g1".into() }
    );
    assert_eq!(
        next_replica_event(&mut rx).await,
        ReplicaEvent::SecretChanged {
            group: "g1".into(),
            name: "s1".into(),
            version: 1,
        }
    );

    // --- the mirror serves exactly the granted scope ---
    assert_eq!(&*replica.get("g1", "s1").unwrap(), b"s1-plaintext");
    assert!(
        replica.get("g2", "sx").is_err(),
        "an ungranted group must not be readable"
    );
    assert_eq!(replica.groups().unwrap(), vec!["g1".to_string()]);
    assert_eq!(replica.list("g1").unwrap(), vec![("s1".to_string(), 1)]);
    let status = replica.status();
    assert!(status.connected);
    assert!(status.last_synced.is_some());
    assert_eq!(status.authoritative, addr.id);
    assert_eq!(status.groups, vec!["g1".to_string()]);

    // --- live push: a new secret arrives as an event, then via get() ---
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "g1".into(),
                name: "s2".into(),
                value: b"s2-plaintext".to_vec(),
                expected_version: 0,
            })
            .await
            .unwrap(),
        Response::Version { version: 1 }
    );
    assert_eq!(
        next_replica_event(&mut rx).await,
        ReplicaEvent::SecretChanged {
            group: "g1".into(),
            name: "s2".into(),
            version: 1,
        }
    );
    assert_eq!(&*replica.get("g1", "s2").unwrap(), b"s2-plaintext");

    // --- revocation: the group vanishes from the mirror ---
    assert_eq!(
        admin
            .request(&Request::Grant {
                group: "g1".into(),
                identity: "replica".into(),
                perms: 0,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        next_replica_event(&mut rx).await,
        ReplicaEvent::GroupRemoved { group: "g1".into() }
    );
    assert!(replica.groups().unwrap().is_empty());
    assert!(replica.get("g1", "s1").is_err());

    // --- re-grant: the full resync brings everything back ---
    assert_eq!(
        admin
            .request(&Request::Grant {
                group: "g1".into(),
                identity: "replica".into(),
                perms: 1,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        next_replica_event(&mut rx).await,
        ReplicaEvent::GroupAdded { group: "g1".into() }
    );
    for name in ["s1", "s2"] {
        assert_eq!(
            next_replica_event(&mut rx).await,
            ReplicaEvent::SecretChanged {
                group: "g1".into(),
                name: name.into(),
                version: 1,
            }
        );
    }
    assert_eq!(&*replica.get("g1", "s1").unwrap(), b"s1-plaintext");

    // --- delete/recreate ABA: same version, same DEK, new value; only the
    // nonce tells them apart, and the replica must refetch on it ---
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "g1".into(),
                name: "aba".into(),
                value: b"first".to_vec(),
                expected_version: 0,
            })
            .await
            .unwrap(),
        Response::Version { version: 1 }
    );
    assert_eq!(
        next_replica_event(&mut rx).await,
        ReplicaEvent::SecretChanged {
            group: "g1".into(),
            name: "aba".into(),
            version: 1,
        }
    );
    assert_eq!(&*replica.get("g1", "aba").unwrap(), b"first");
    assert_eq!(
        admin
            .request(&Request::Delete {
                group: "g1".into(),
                name: "aba".into(),
                expected_version: 1,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "g1".into(),
                name: "aba".into(),
                value: b"second".to_vec(),
                expected_version: 0,
            })
            .await
            .unwrap(),
        Response::Version { version: 1 }
    );
    // Delete and re-put may land in one push round (one SecretChanged) or
    // two (SecretDeleted first), depending on the server's debounce.
    await_replica_event(
        &mut rx,
        &ReplicaEvent::SecretChanged {
            group: "g1".into(),
            name: "aba".into(),
            version: 1,
        },
    )
    .await;
    assert_eq!(
        &*replica.get("g1", "aba").unwrap(),
        b"second",
        "the recreated secret must carry the new value, not the stale mirror"
    );

    replica.shutdown().await;
    ep.close().await;
    admin.close().await;
    router.shutdown().await.unwrap();
}

#[tokio::test]
async fn replica_serves_reads_while_authoritative_down() {
    // Issue #1's headline scenario: the authoritative node goes away and
    // the replica keeps answering get() from its local mirror.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bunker.sqlite");
    let replica_db = dir.path().join("replica.sqlite");

    let op = age::x25519::Identity::generate();
    let backup = age::x25519::Identity::generate();
    let admin_secret = SecretKey::generate();
    let replica_secret = SecretKey::generate();

    let store = init_store(&db, &op, &backup, &admin_secret.public());
    let (router, addr) = spawn_authoritative(store, op).await;

    let admin = Client::with_endpoint(client_endpoint(admin_secret).await, addr.clone())
        .await
        .unwrap();
    assert_eq!(
        admin
            .request(&Request::CreateGroup { name: "g1".into() })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::AddIdentity {
                name: "replica".into(),
                endpoint_id: replica_secret.public().to_string(),
                service_admin: false,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Grant {
                group: "g1".into(),
                identity: "replica".into(),
                perms: 1,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "g1".into(),
                name: "s1".into(),
                value: b"survives-outages".to_vec(),
                expected_version: 0,
            })
            .await
            .unwrap(),
        Response::Version { version: 1 }
    );

    let ep = replica_endpoint(replica_secret.clone(), &addr).await;
    let replica = Replica::builder()
        .store_path(&replica_db)
        .secret_key(replica_secret)
        .authoritative(addr.id)
        .endpoint(ep.clone())
        .spawn()
        .await
        .unwrap();
    let mut rx = replica.subscribe();
    await_replica_event(
        &mut rx,
        &ReplicaEvent::SecretChanged {
            group: "g1".into(),
            name: "s1".into(),
            version: 1,
        },
    )
    .await;
    assert_eq!(&*replica.get("g1", "s1").unwrap(), b"survives-outages");

    // The authoritative node goes down entirely.
    admin.close().await;
    router.shutdown().await.unwrap();
    await_replica_event(&mut rx, &ReplicaEvent::Disconnected).await;
    assert!(!replica.status().connected);

    // The mirror still serves.
    assert_eq!(&*replica.get("g1", "s1").unwrap(), b"survives-outages");
    assert_eq!(replica.groups().unwrap(), vec!["g1".to_string()]);

    replica.shutdown().await;
    ep.close().await;
}

/// A fake authoritative node that walks one replica into the fetch phase
/// and then stalls forever: it serves the Hello with a manifest listing
/// one secret, reads the resulting `FetchSecrets` request, signals
/// `got_fetch`, and never answers.
async fn stalled_authoritative(ep: Endpoint, got_fetch: tokio::sync::oneshot::Sender<()>) {
    let incoming = ep
        .accept()
        .await
        .expect("endpoint closed before a connection");
    let conn = incoming.await.expect("accepting sync connection");
    let (mut send, mut recv) = conn.accept_bi().await.expect("accepting session stream");
    assert_eq!(
        sync::read_msg::<SyncRequest>(&mut recv).await.unwrap(),
        Some(SyncRequest::Hello)
    );
    sync::write_msg(
        &mut send,
        &SyncMessage::Group {
            name: "g".into(),
            acl: Vec::new(),
            deks: Vec::new(),
        },
    )
    .await
    .unwrap();
    sync::write_msg(
        &mut send,
        &SyncMessage::GroupSecrets {
            group: "g".into(),
            secrets: vec![sync::SecretEntry {
                name: "s".into(),
                current_version: 1,
                dek_version: 1,
                nonce: vec![0; 12],
            }],
        },
    )
    .await
    .unwrap();
    sync::write_msg(&mut send, &SyncMessage::ManifestDone)
        .await
        .unwrap();
    // The manifest lists a secret the replica does not hold, so it must
    // now open a fetch stream. Read the request — then go silent, keeping
    // the connection alive.
    let (_fetch_send, mut fetch_recv) = conn.accept_bi().await.expect("accepting fetch stream");
    assert!(matches!(
        sync::read_msg::<SyncRequest>(&mut fetch_recv).await,
        Ok(Some(SyncRequest::FetchSecrets { .. }))
    ));
    got_fetch.send(()).expect("test dropped the fetch signal");
    std::future::pending::<()>().await
}

#[tokio::test]
async fn replica_shutdown_unblocks_a_stalled_fetch() {
    // The session-stream reads race the shutdown watch, but the fetch
    // helpers await inside streams of their own. A peer that stalls
    // mid-fetch (or dies, leaving QUIC to time out) must not be able to
    // hold shutdown() hostage: closing the connection has to abort the
    // pending fetch immediately.
    let dir = tempfile::tempdir().unwrap();
    let replica_secret = SecretKey::generate();

    let server_ep = Endpoint::builder(presets::Minimal)
        .alpns(vec![SYNC_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let server_addr = server_ep.addr();
    let (got_fetch_tx, got_fetch_rx) = tokio::sync::oneshot::channel();
    let stall = tokio::spawn(stalled_authoritative(server_ep.clone(), got_fetch_tx));

    let ep = replica_endpoint(replica_secret.clone(), &server_addr).await;
    let replica = Replica::builder()
        .store_path(dir.path().join("replica.sqlite"))
        .secret_key(replica_secret)
        .authoritative(server_addr.id)
        .endpoint(ep.clone())
        .spawn()
        .await
        .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(30), got_fetch_rx)
        .await
        .expect("timed out waiting for the replica to enter the fetch")
        .unwrap();
    // The replica is now parked in the unraced fetch await. Well under
    // any QUIC idle timeout, and the stalled peer is still alive:
    tokio::time::timeout(std::time::Duration::from_secs(5), replica.shutdown())
        .await
        .expect("shutdown must not wait out a stalled fetch");

    stall.abort();
    ep.close().await;
    server_ep.close().await;
}

#[tokio::test]
async fn sync_manifest_fetch_and_denials() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bunker.sqlite");

    let op = age::x25519::Identity::generate();
    let backup = age::x25519::Identity::generate();
    let admin_secret = SecretKey::generate();
    let reader_secret = SecretKey::generate();
    let writer_secret = SecretKey::generate();
    let root_secret = SecretKey::generate();
    let stranger_secret = SecretKey::generate();

    let store = init_store(&db, &op, &backup, &admin_secret.public());
    let (router, addr) = spawn_authoritative(store, op).await;

    let admin = Client::with_endpoint(client_endpoint(admin_secret).await, addr.clone())
        .await
        .unwrap();
    assert_eq!(
        admin
            .request(&Request::CreateGroup { name: "g".into() })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "g".into(),
                name: "s".into(),
                value: b"top-secret".to_vec(),
                expected_version: 0,
            })
            .await
            .unwrap(),
        Response::Version { version: 1 }
    );
    // reader: explicit read on "g"; writer: write-only on "g"; root: a
    // service admin with NO explicit rows anywhere.
    for (name, secret, service_admin) in [
        ("reader", &reader_secret, false),
        ("writer", &writer_secret, false),
        ("root", &root_secret, true),
    ] {
        assert_eq!(
            admin
                .request(&Request::AddIdentity {
                    name: name.into(),
                    endpoint_id: secret.public().to_string(),
                    service_admin,
                })
                .await
                .unwrap(),
            Response::Ok
        );
    }
    for (identity, perms) in [("reader", 1), ("writer", 2)] {
        assert_eq!(
            admin
                .request(&Request::Grant {
                    group: "g".into(),
                    identity: identity.into(),
                    perms,
                })
                .await
                .unwrap(),
            Response::Ok
        );
    }

    // --- reader: Hello streams the manifest of its explicit-read scope ---
    let reader_ep = client_endpoint(reader_secret.clone()).await;
    let conn = reader_ep.connect(addr.clone(), SYNC_ALPN).await.unwrap();
    let (_hello_send, mut hello_recv) = sync_request(&conn, &SyncRequest::Hello).await;

    let mut groups = Vec::new();
    let mut listings = Vec::new();
    loop {
        match next_sync_msg(&mut hello_recv).await {
            SyncMessage::Group { name, acl, deks } => groups.push((name, acl, deks)),
            SyncMessage::GroupSecrets { group, secrets } => listings.push((group, secrets)),
            SyncMessage::ManifestDone => break,
            other => panic!("unexpected manifest message: {other:?}"),
        }
    }
    let [(group_name, acl, deks)] = &groups[..] else {
        panic!("expected exactly one Group, got {groups:?}");
    };
    assert_eq!(group_name, "g");
    // The full ACL travels (a replica must enforce it locally), with
    // endpoint ids so the replica can authenticate those peers.
    assert_eq!(
        acl.iter()
            .map(|e| (e.identity_name.as_str(), e.perms))
            .collect::<Vec<_>>(),
        vec![("admin", 7), ("reader", 1), ("writer", 2)]
    );
    assert!(acl.iter().all(|e| !e.endpoint_id.is_empty()));
    // The DEK wraps are the caller's own — decryptable with the identity
    // derived from the reader's endpoint secret, one per retained version.
    assert_eq!(deks.iter().map(|d| d.version).collect::<Vec<_>>(), vec![1]);
    let reader_age = secret_bunker_iroh::agebridge::identity_from_secret(&reader_secret).unwrap();
    let dek = secret_bunker_iroh::crypto::unwrap_dek(&deks[0].wrapped, &reader_age)
        .expect("the wrap must be addressed to the caller");
    let [(listed_group, entries)] = &listings[..] else {
        panic!("expected exactly one GroupSecrets, got {listings:?}");
    };
    assert_eq!(listed_group, "g");
    assert_eq!(
        entries
            .iter()
            .map(|e| (e.name.as_str(), e.current_version, e.dek_version))
            .collect::<Vec<_>>(),
        vec![("s", 1, 1)]
    );

    // --- FetchSecrets on a second stream while the Hello session is still
    // open: per-stream tasks must serve it concurrently ---
    let (_fetch_send, mut fetch_recv) = sync_request(
        &conn,
        &SyncRequest::FetchSecrets {
            group: "g".into(),
            names: vec!["s".into(), "no-such-secret".into()],
        },
    )
    .await;
    let SyncMessage::SecretData {
        name,
        version,
        dek_version,
        nonce,
        ciphertext,
        created_at,
        created_by,
    } = next_sync_msg(&mut fetch_recv).await
    else {
        panic!("expected SecretData first");
    };
    assert_eq!((name.as_str(), version, dek_version), ("s", 1, 1));
    assert_eq!(nonce, entries[0].nonce);
    assert!(created_at > 0);
    assert_eq!(created_by, "admin");
    // End-to-end proof: the manifest wrap + the fetched ciphertext decrypt
    // to the plaintext the admin put, under the canonical AAD.
    let aad = secret_bunker_iroh::crypto::secret_aad("g", "s", version, dek_version);
    let plain = secret_bunker_iroh::crypto::decrypt_secret(&dek, &aad, &nonce, &ciphertext)
        .expect("fetched secret must decrypt with the caller's wrap");
    assert_eq!(plain, b"top-secret");
    // The unknown name was skipped silently, not answered or denied.
    assert_eq!(next_sync_msg(&mut fetch_recv).await, SyncMessage::FetchDone);

    // --- FetchGroup happy path on yet another stream ---
    let (_fg_send, mut fg_recv) =
        sync_request(&conn, &SyncRequest::FetchGroup { group: "g".into() }).await;
    assert!(matches!(
        next_sync_msg(&mut fg_recv).await,
        SyncMessage::Group { .. }
    ));
    assert!(matches!(
        next_sync_msg(&mut fg_recv).await,
        SyncMessage::GroupSecrets { .. }
    ));
    assert_eq!(next_sync_msg(&mut fg_recv).await, SyncMessage::FetchDone);

    // --- write-only identity: FetchGroup is denied (no read bit) ---
    let writer_ep = client_endpoint(writer_secret).await;
    let writer_conn = writer_ep.connect(addr.clone(), SYNC_ALPN).await.unwrap();
    let (_w_send, mut w_recv) =
        sync_request(&writer_conn, &SyncRequest::FetchGroup { group: "g".into() }).await;
    assert_eq!(next_sync_msg(&mut w_recv).await, SyncMessage::SyncDenied);

    // --- unregistered key: Hello is denied ---
    let stranger_ep = client_endpoint(stranger_secret).await;
    let stranger_conn = stranger_ep.connect(addr.clone(), SYNC_ALPN).await.unwrap();
    let (_s_send, mut s_recv) = sync_request(&stranger_conn, &SyncRequest::Hello).await;
    assert_eq!(next_sync_msg(&mut s_recv).await, SyncMessage::SyncDenied);

    // --- service admin with no explicit grants: the implicit-read bypass
    // must NOT apply to sync (there are no wraps addressed to it) ---
    let root_ep = client_endpoint(root_secret).await;
    let root_conn = root_ep.connect(addr.clone(), SYNC_ALPN).await.unwrap();
    let (_r_send, mut r_recv) = sync_request(&root_conn, &SyncRequest::Hello).await;
    assert_eq!(
        next_sync_msg(&mut r_recv).await,
        SyncMessage::ManifestDone,
        "a service admin without explicit read gets an empty manifest"
    );
    let (_r2_send, mut r2_recv) =
        sync_request(&root_conn, &SyncRequest::FetchGroup { group: "g".into() }).await;
    assert_eq!(next_sync_msg(&mut r2_recv).await, SyncMessage::SyncDenied);

    admin.close().await;
    for conn in [conn, writer_conn, stranger_conn, root_conn] {
        conn.close(0u32.into(), b"done");
    }
    for ep in [reader_ep, writer_ep, stranger_ep, root_ep] {
        ep.close().await;
    }
    router.shutdown().await.unwrap();
}

#[tokio::test]
async fn sync_push_changed_and_scope_changed() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bunker.sqlite");

    let op = age::x25519::Identity::generate();
    let backup = age::x25519::Identity::generate();
    let admin_secret = SecretKey::generate();
    let reader_secret = SecretKey::generate();

    let store = init_store(&db, &op, &backup, &admin_secret.public());
    let (router, addr) = spawn_authoritative(store, op).await;

    let admin = Client::with_endpoint(client_endpoint(admin_secret).await, addr.clone())
        .await
        .unwrap();
    for group in ["g", "g2"] {
        assert_eq!(
            admin
                .request(&Request::CreateGroup { name: group.into() })
                .await
                .unwrap(),
            Response::Ok
        );
    }
    assert_eq!(
        admin
            .request(&Request::AddIdentity {
                name: "reader".into(),
                endpoint_id: reader_secret.public().to_string(),
                service_admin: false,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        admin
            .request(&Request::Grant {
                group: "g".into(),
                identity: "reader".into(),
                perms: 1,
            })
            .await
            .unwrap(),
        Response::Ok
    );

    // A live session over its manifest ("g" only).
    let reader_ep = client_endpoint(reader_secret.clone()).await;
    let conn = reader_ep.connect(addr.clone(), SYNC_ALPN).await.unwrap();
    let (_hello_send, mut hello_recv) = sync_request(&conn, &SyncRequest::Hello).await;
    loop {
        match next_sync_msg(&mut hello_recv).await {
            SyncMessage::ManifestDone => break,
            SyncMessage::Group { ref name, .. } => assert_eq!(name, "g"),
            SyncMessage::GroupSecrets { ref group, .. } => assert_eq!(group, "g"),
            other => panic!("unexpected manifest message: {other:?}"),
        }
    }

    // A write in scope surfaces as Changed after the debounce window.
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "g".into(),
                name: "fresh".into(),
                value: b"v".to_vec(),
                expected_version: 0,
            })
            .await
            .unwrap(),
        Response::Version { version: 1 }
    );
    assert_eq!(
        next_sync_msg(&mut hello_recv).await,
        SyncMessage::Changed { group: "g".into() }
    );

    // Gaining read on another group is a scope change, not a group change.
    assert_eq!(
        admin
            .request(&Request::Grant {
                group: "g2".into(),
                identity: "reader".into(),
                perms: 1,
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        next_sync_msg(&mut hello_recv).await,
        SyncMessage::ScopeChanged
    );

    // The re-scoped session forwards events for the newly visible group.
    assert_eq!(
        admin
            .request(&Request::Put {
                group: "g2".into(),
                name: "later".into(),
                value: b"v".to_vec(),
                expected_version: 0,
            })
            .await
            .unwrap(),
        Response::Version { version: 1 }
    );
    assert_eq!(
        next_sync_msg(&mut hello_recv).await,
        SyncMessage::Changed { group: "g2".into() }
    );

    admin.close().await;
    conn.close(0u32.into(), b"done");
    reader_ep.close().await;
    router.shutdown().await.unwrap();
}
