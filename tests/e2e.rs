//! End-to-end test: a bunker and several clients as real iroh endpoints in
//! one process (Minimal preset: no relays, no discovery).

use std::path::Path;

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, SecretKey};

use secret_bunker_iroh::client::Client;
use secret_bunker_iroh::proto::{ALPN, Request, Response};
use secret_bunker_iroh::server::Bunker;
use secret_bunker_iroh::store::Store;

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
        let store = Store::open(&db).unwrap();
        for (group_id, dek_row) in store.all_deks().unwrap() {
            let dek =
                secret_bunker_iroh::crypto::unwrap_dek(&dek_row.wrapped_backup, &backup).unwrap();
            let wrapped = secret_bunker_iroh::crypto::wrap_dek(&dek, &new_op.to_public()).unwrap();
            store
                .replace_wrapped_operational(group_id, dek_row.version, &wrapped)
                .unwrap();
        }
        store
            .meta_set("operational_pubkey", &new_op.to_public().to_string())
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
