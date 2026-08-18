//! Self-healing serve loop.
//!
//! iroh#4476: an endpoint's relay client can wedge — home relay stuck
//! `connecting` indefinitely, published discovery record advertising a
//! relay the endpoint is not on — leaving the server unreachable for
//! every non-LAN peer until the process is restarted (the 2026-08-17
//! incident: 15+ hours). [`serve_with_rebind`] turns the restart into a
//! rebind: when a [`crate::relayhealth`] watchdog escalates, the current
//! serving generation (endpoint + router + watchdogs) is torn down and a
//! fresh one is built over the same secret key and the same open store.
//! Peers keep the same EndpointId; discovery republishes the new state.

use std::pin::Pin;
use std::time::Duration;

use anyhow::Result;
use iroh::protocol::Router;
use tokio::sync::mpsc;

use crate::relayhealth::WedgeReason;

/// One serving generation, as `build` hands it to [`serve_with_rebind`].
pub struct Generation {
    /// The router serving this generation. Shutting it down closes the
    /// endpoint it was built over (see `iroh::protocol::Router::shutdown`).
    pub router: Router,
    /// Where this generation's watchdogs report a wedge. `None` (relays
    /// disabled, say) means the generation only ends by shutdown.
    pub wedged: Option<mpsc::Receiver<WedgeReason>>,
    /// Awaited after the router (and thus the endpoint) is shut down;
    /// the replica's sync-engine teardown hangs off this.
    pub teardown: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

/// Serve until `shutdown` resolves, rebuilding the serving generation
/// whenever it reports itself wedged.
///
/// `build(generation)` is called with 1 on the first build and an
/// incremented value on every later attempt. A first-build failure is
/// fatal (startup errors stay loud); later failures are retried forever
/// every `rebuild_retry` — while wedged, there is nothing to lose by
/// retrying and no better state to be in.
pub async fn serve_with_rebind<B, BFut, S>(
    mut build: B,
    shutdown: S,
    rebuild_retry: Duration,
) -> Result<()>
where
    B: FnMut(u64) -> BFut,
    BFut: Future<Output = Result<Generation>>,
    S: Future<Output = ()>,
{
    tokio::pin!(shutdown);
    let mut generation: u64 = 0;
    loop {
        // Build the next generation; retry failures unless this is the
        // very first build. Shutdown stays live during the retry sleep.
        let built = loop {
            generation += 1;
            match build(generation).await {
                Ok(g) => break g,
                Err(err) if generation == 1 => return Err(err),
                Err(err) => {
                    tracing::warn!(
                        %err,
                        attempt = generation,
                        retry_in = ?rebuild_retry,
                        "rebinding the endpoint failed; retrying"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(rebuild_retry) => {}
                        _ = &mut shutdown => return Ok(()),
                    }
                }
            }
        };
        let Generation {
            router,
            wedged,
            teardown,
        } = built;
        // A missing or closed wedge channel (relays disabled; or every
        // watchdog ended without escalating) pends forever: only
        // shutdown ends such a generation.
        let wedge_wait = async {
            match wedged {
                Some(mut rx) => match rx.recv().await {
                    Some(reason) => reason,
                    None => std::future::pending().await,
                },
                None => std::future::pending().await,
            }
        };
        let stopping = tokio::select! {
            _ = &mut shutdown => true,
            reason = wedge_wait => {
                tracing::warn!(
                    ?reason,
                    generation,
                    "endpoint wedged — rebinding over a fresh endpoint"
                );
                false
            }
        };
        // Router shutdown closes the endpoint; teardown (the replica's
        // sync engine, say) runs strictly after, and runs even when the
        // router's own shutdown reports an error.
        let shutdown_result = router.shutdown().await;
        if let Some(td) = teardown {
            td.await;
        }
        match shutdown_result {
            Err(err) if stopping => {
                return Err(anyhow::anyhow!("router shutdown: {err}"));
            }
            Err(err) => tracing::warn!(%err, "router shutdown during rebind"),
            Ok(()) => {}
        }
        if stopping {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use iroh::endpoint::presets;
    use iroh::{Endpoint, EndpointAddr, SecretKey};

    use super::*;
    use crate::client::Client;
    use crate::proto::{ALPN, Request, Response};
    use crate::server::Bunker;
    use crate::store::Store;

    fn test_bunker(db: &std::path::Path, admin: &iroh::EndpointId) -> Bunker {
        let op = age::x25519::Identity::generate();
        let backup = age::x25519::Identity::generate();
        let mut store = Store::open(db).unwrap();
        store
            .init(
                &op.to_public().to_string(),
                &backup.to_public().to_string(),
                &admin.to_string(),
                "admin",
            )
            .unwrap();
        Bunker::new(store, op).unwrap()
    }

    async fn connect(secret: &SecretKey, addr: EndpointAddr) -> Client {
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(secret.clone())
            .bind()
            .await
            .unwrap();
        Client::with_endpoint(ep, addr).await.unwrap()
    }

    /// Poll until `cond` holds; panic after ~5s so a hung loop fails the
    /// test instead of hanging it.
    async fn wait_for(cond: impl Fn() -> bool, what: &str) {
        for _ in 0..200 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("timeout waiting for {what}");
    }

    /// What the test's build closure records about each generation.
    #[derive(Clone, Default)]
    struct Observed {
        addrs: Arc<Mutex<Vec<EndpointAddr>>>,
        wedge_txs: Arc<Mutex<Vec<mpsc::Sender<WedgeReason>>>>,
        builds: Arc<Mutex<u64>>,
    }

    impl Observed {
        fn addr(&self, i: usize) -> EndpointAddr {
            self.addrs.lock().unwrap()[i].clone()
        }
        fn generations(&self) -> usize {
            self.addrs.lock().unwrap().len()
        }
    }

    /// A build closure over one shared bunker + server key: every
    /// generation binds a fresh Minimal endpoint and records its addr and
    /// wedge sender. `fail_on` lists build attempts that return Err.
    fn build_fn(
        obs: &Observed,
        bunker: &Bunker,
        secret: &SecretKey,
        fail_on: &'static [u64],
    ) -> impl FnMut(u64) -> Pin<Box<dyn Future<Output = Result<Generation>> + Send>> + use<> {
        let obs = obs.clone();
        let bunker = bunker.clone();
        let secret = secret.clone();
        move |generation| {
            let obs = obs.clone();
            let bunker = bunker.clone();
            let secret = secret.clone();
            Box::pin(async move {
                *obs.builds.lock().unwrap() += 1;
                if fail_on.contains(&generation) {
                    anyhow::bail!("injected build failure on attempt {generation}");
                }
                let ep = Endpoint::builder(presets::Minimal)
                    .secret_key(secret)
                    .bind()
                    .await?;
                let router = Router::builder(ep).accept(ALPN, bunker).spawn();
                let (tx, rx) = mpsc::channel(2);
                obs.wedge_txs.lock().unwrap().push(tx);
                obs.addrs.lock().unwrap().push(router.endpoint().addr());
                Ok(Generation {
                    router,
                    wedged: Some(rx),
                    teardown: None,
                })
            })
        }
    }

    #[tokio::test]
    async fn wedge_signal_rebinds_and_serves_again() {
        let dir = tempfile::tempdir().unwrap();
        let admin_secret = SecretKey::generate();
        let bunker = test_bunker(&dir.path().join("db"), &admin_secret.public());
        let server_secret = SecretKey::generate();
        let obs = Observed::default();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let loop_task = tokio::spawn(serve_with_rebind(
            build_fn(&obs, &bunker, &server_secret, &[]),
            async move {
                let _ = stop_rx.await;
            },
            Duration::from_millis(50),
        ));

        // Generation 1 serves.
        wait_for(|| obs.generations() == 1, "first generation").await;
        let client = connect(&admin_secret, obs.addr(0)).await;
        assert_eq!(
            client
                .request(&Request::CreateGroup { name: "g".into() })
                .await
                .unwrap(),
            Response::Ok
        );
        client.close().await;

        // Wedge → generation 2 comes up over the same store and id.
        obs.wedge_txs.lock().unwrap()[0]
            .try_send(WedgeReason::RelayDown)
            .unwrap();
        wait_for(|| obs.generations() == 2, "rebind after wedge").await;
        assert_eq!(obs.addr(0).id, obs.addr(1).id, "EndpointId must survive");

        let client = connect(&admin_secret, obs.addr(1)).await;
        match client.request(&Request::ListGroups).await.unwrap() {
            Response::Groups { groups, .. } => {
                assert!(groups.iter().any(|g| g.name == "g"), "store must survive")
            }
            other => panic!("unexpected response: {other:?}"),
        }
        client.close().await;

        let _ = stop_tx.send(());
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_with_no_wedge_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let admin_secret = SecretKey::generate();
        let bunker = test_bunker(&dir.path().join("db"), &admin_secret.public());
        let obs = Observed::default();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let loop_task = tokio::spawn(serve_with_rebind(
            build_fn(&obs, &bunker, &SecretKey::generate(), &[]),
            async move {
                let _ = stop_rx.await;
            },
            Duration::from_millis(50),
        ));
        wait_for(|| obs.generations() == 1, "first generation").await;
        let _ = stop_tx.send(());
        loop_task.await.unwrap().unwrap();
        assert_eq!(*obs.builds.lock().unwrap(), 1, "no rebuild without a wedge");
    }

    #[tokio::test]
    async fn first_build_failure_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let admin_secret = SecretKey::generate();
        let bunker = test_bunker(&dir.path().join("db"), &admin_secret.public());
        let obs = Observed::default();

        let err = serve_with_rebind(
            build_fn(&obs, &bunker, &SecretKey::generate(), &[1]),
            std::future::pending(),
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("injected build failure"),
            "unhelpful error: {err}"
        );
    }

    #[tokio::test]
    async fn rebuild_failure_retries_until_success() {
        let dir = tempfile::tempdir().unwrap();
        let admin_secret = SecretKey::generate();
        let bunker = test_bunker(&dir.path().join("db"), &admin_secret.public());
        let server_secret = SecretKey::generate();
        let obs = Observed::default();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let loop_task = tokio::spawn(serve_with_rebind(
            build_fn(&obs, &bunker, &server_secret, &[2]), // attempt 2 fails once
            async move {
                let _ = stop_rx.await;
            },
            Duration::from_millis(50),
        ));

        wait_for(|| obs.generations() == 1, "first generation").await;
        obs.wedge_txs.lock().unwrap()[0]
            .try_send(WedgeReason::RecordMismatch)
            .unwrap();
        // Attempt 2 fails; attempt 3 must serve.
        wait_for(|| obs.generations() == 2, "recovery after failed rebuild").await;
        assert_eq!(*obs.builds.lock().unwrap(), 3);

        let client = connect(&admin_secret, obs.addr(1)).await;
        assert_eq!(
            client
                .request(&Request::CreateGroup { name: "g2".into() })
                .await
                .unwrap(),
            Response::Ok
        );
        client.close().await;

        let _ = stop_tx.send(());
        loop_task.await.unwrap().unwrap();
    }
}
