//! In-process bunker + replica harness for operator integration tests.
#![allow(dead_code)]

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use secret_bunker_iroh::client::Client;
use secret_bunker_iroh::proto::{ALPN, Request, Response};
use secret_bunker_iroh::replica::{Replica, ReplicaEvent};
use secret_bunker_iroh::server::Bunker;
use secret_bunker_iroh::store::Store;
use secret_bunker_iroh::sync::SYNC_ALPN;

pub struct TestBunker {
    pub admin: Client,
    pub addr: EndpointAddr,
    pub router: Router,
    _dir: tempfile::TempDir,
}

impl TestBunker {
    pub async fn spawn() -> TestBunker {
        let dir = tempfile::tempdir().unwrap();
        let op = age::x25519::Identity::generate();
        let backup = age::x25519::Identity::generate();
        let admin_secret = SecretKey::generate();

        let db = dir.path().join("bunker.sqlite");
        let mut store = Store::open(&db).unwrap();
        store
            .init(
                &op.to_public().to_string(),
                &backup.to_public().to_string(),
                &admin_secret.public().to_string(),
                "admin",
            )
            .unwrap();

        let bunker = Bunker::new(store, op).unwrap();
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let router = Router::builder(endpoint)
            .accept(ALPN, bunker.clone())
            .accept(SYNC_ALPN, bunker.sync_handler())
            .spawn();
        let addr = router.endpoint().addr();

        let admin_ep = Endpoint::builder(presets::Minimal)
            .secret_key(admin_secret)
            .bind()
            .await
            .unwrap();
        let admin = Client::with_endpoint(admin_ep, addr.clone()).await.unwrap();
        TestBunker {
            admin,
            addr,
            router,
            _dir: dir,
        }
    }

    pub async fn create_group(&self, group: &str) {
        let r = self
            .admin
            .request(&Request::CreateGroup { name: group.into() })
            .await
            .unwrap();
        assert_eq!(r, Response::Ok);
    }

    pub async fn add_reader(&self, name: &str, secret: &SecretKey) {
        let r = self
            .admin
            .request(&Request::AddIdentity {
                name: name.into(),
                endpoint_id: secret.public().to_string(),
                service_admin: false,
            })
            .await
            .unwrap();
        assert_eq!(r, Response::Ok);
    }

    pub async fn grant_read(&self, group: &str, identity: &str) {
        let r = self
            .admin
            .request(&Request::Grant {
                group: group.into(),
                identity: identity.into(),
                perms: 1,
            })
            .await
            .unwrap();
        assert_eq!(r, Response::Ok);
    }

    pub async fn put(&self, group: &str, name: &str, value: &[u8], expected_version: u64) -> u64 {
        match self
            .admin
            .request(&Request::Put {
                group: group.into(),
                name: name.into(),
                value: value.to_vec(),
                expected_version,
            })
            .await
            .unwrap()
        {
            Response::Version { version } => version,
            other => panic!("put: {other:?}"),
        }
    }

    pub async fn delete(&self, group: &str, name: &str, expected_version: u64) {
        let r = self
            .admin
            .request(&Request::Delete {
                group: group.into(),
                name: name.into(),
                expected_version,
            })
            .await
            .unwrap();
        assert_eq!(r, Response::Ok);
    }

    /// Spawn an embedded replica for `secret` against this bunker, hermetically.
    pub async fn replica_for(
        &self,
        secret: SecretKey,
        store_path: &std::path::Path,
    ) -> (Replica, tokio::sync::broadcast::Receiver<ReplicaEvent>) {
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(secret.clone())
            .address_lookup(iroh::address_lookup::MemoryLookup::from_endpoint_info([
                self.addr.clone(),
            ]))
            .bind()
            .await
            .unwrap();
        let replica = Replica::builder()
            .store_path(store_path)
            .secret_key(secret)
            .authoritative(self.addr.id)
            .endpoint(ep)
            .spawn()
            .await
            .unwrap();
        let rx = replica.subscribe();
        (replica, rx)
    }
}

/// Await one event with the same 30 s deadline style as the upstream e2e suite.
pub async fn next_event(rx: &mut tokio::sync::broadcast::Receiver<ReplicaEvent>) -> ReplicaEvent {
    tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv())
        .await
        .expect("timed out waiting for a replica event")
        .expect("replica event channel closed")
}

/// Await a specific event, skipping a bounded number of others.
pub async fn await_event(
    rx: &mut tokio::sync::broadcast::Receiver<ReplicaEvent>,
    want: &ReplicaEvent,
) {
    for _ in 0..64 {
        if next_event(rx).await == *want {
            return;
        }
    }
    panic!("event {want:?} never arrived");
}

/// Poll until the replica's mirror can serve (group, name) or the deadline hits.
pub async fn await_mirrored(replica: &Replica, group: &str, name: &str) -> Vec<u8> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Ok(v) = replica.get(group, name) {
            return v.to_vec();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "mirror never served {group}/{name}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
