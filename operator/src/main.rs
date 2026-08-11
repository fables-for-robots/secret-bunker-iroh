//! secret-bunker-operator: syncs bunker secrets into Kubernetes Secrets.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::controller::Controller;
use kube::runtime::watcher;
use kube::{Api, Client};

use secret_bunker_operator::bunker::{ReplicaSource, Staleness, spawn_replica};
use secret_bunker_operator::crd::BunkerSecret;
use secret_bunker_operator::events::spawn_event_bridge;
use secret_bunker_operator::http::{AppState, router};
use secret_bunker_operator::metrics::Metrics;
use secret_bunker_operator::reconcile::{Context, error_policy, reconcile};

#[derive(Parser, Debug)]
#[command(
    name = "operator",
    about = "secret-bunker → Kubernetes Secret sync operator"
)]
struct Args {
    /// EndpointId of the authoritative bunker (64-char hex).
    #[arg(long, env = "BUNKER_ID")]
    bunker_id: String,
    /// Direct host:port of the bunker; repeatable. Without it, iroh n0
    /// relay/discovery is used (remote bunker).
    #[arg(long, env = "BUNKER_ADDR")]
    bunker_addr: Vec<SocketAddr>,
    /// Path to the operator's iroh ed25519 key (pre-provisioned; never generated).
    #[arg(long, env = "BUNKER_KEY_FILE")]
    key_file: PathBuf,
    /// Replica mirror SQLite path (emptyDir volume).
    #[arg(long, env = "BUNKER_MIRROR_PATH")]
    mirror_path: PathBuf,
    /// Level-reconcile backstop interval (push events do the real work).
    #[arg(long, env = "RESYNC_INTERVAL", value_parser = humantime::parse_duration, default_value = "1h")]
    resync_interval: Duration,
    /// Disconnected longer than this degrades CR readiness to StaleReplica.
    #[arg(long, env = "STALENESS_THRESHOLD", value_parser = humantime::parse_duration, default_value = "10m")]
    staleness_threshold: Duration,
    /// Health + metrics listener.
    #[arg(long, env = "LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    let metrics = Metrics::new()?;
    let replica = Arc::new(
        spawn_replica(
            &args.bunker_id,
            &args.bunker_addr,
            &args.key_file,
            &args.mirror_path,
        )
        .await
        .context("spawning embedded replica")?,
    );
    // Subscribe immediately after spawn — race-free window for the first events.
    let events_rx = replica.subscribe();
    let staleness = Arc::new(Staleness::new());

    let client = Client::try_default()
        .await
        .context("building kube client")?;
    let crs: Api<BunkerSecret> = Api::all(client.clone());
    let secrets: Api<Secret> = Api::all(client.clone());

    let controller = Controller::new(crs, watcher::Config::default()).owns(
        secrets,
        watcher::Config::default().labels("app.kubernetes.io/managed-by=secret-bunker-operator"),
    );
    let store = controller.store();
    let bridge = spawn_event_bridge(
        events_rx,
        Box::new(move || store.state()),
        staleness.clone(),
        args.staleness_threshold,
        metrics.clone(),
    );

    // Replica gauges: connected / last-sync / group count. The handle is kept
    // (not discarded) so shutdown can abort this otherwise-infinite loop and
    // await its Arc<Replica> clone actually being dropped — without that,
    // Arc::try_unwrap(replica) below would never succeed.
    let gauge_task = {
        let replica = replica.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let status = replica.status();
                metrics.connected.set(status.connected as i64);
                metrics.groups.set(status.groups.len() as i64);
                if let Some(t) = status.last_synced
                    && let Ok(d) = t.duration_since(std::time::SystemTime::UNIX_EPOCH)
                {
                    metrics.last_sync_ts.set(d.as_secs() as i64);
                }
            }
        })
    };

    let state = Arc::new(AppState {
        metrics: metrics.clone(),
        replica: replica.clone(),
    });
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(listen = %args.listen, "health/metrics listening");
    let http = tokio::spawn(async move {
        axum::serve(listener, router(state))
            .with_graceful_shutdown(shutdown_signal())
            .await
    });

    let recorder = kube::runtime::events::Recorder::new(
        client.clone(),
        kube::runtime::events::Reporter {
            controller: "secret-bunker-operator".into(),
            instance: std::env::var("HOSTNAME").ok(),
        },
    );
    let ctx = Arc::new(Context {
        client,
        source: ReplicaSource(replica.clone()),
        replica: replica.clone(),
        metrics,
        staleness,
        recorder,
        resync: args.resync_interval,
        staleness_threshold: args.staleness_threshold,
        backoffs: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    controller
        .reconcile_on(bridge)
        .graceful_shutdown_on(shutdown_signal())
        .run(reconcile, error_policy, ctx.clone())
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => tracing::debug!(%obj, "reconciled"),
                Err(e) => tracing::warn!(error = %e, "reconcile stream error"),
            }
        })
        .await;

    tracing::info!("controller stopped; shutting down replica");

    // Abort and await both background tasks so their Arc<Replica> clones
    // (gauge_task's `replica`, http's `AppState.replica` via `router(state)`)
    // are actually dropped before the try_unwrap below — abort() alone only
    // requests cancellation, it doesn't guarantee the task's captured state
    // has been released yet.
    gauge_task.abort();
    if let Err(e) = gauge_task.await
        && !e.is_cancelled()
    {
        tracing::warn!(error = %e, "gauge ticker task panicked");
    }

    http.abort();
    match http.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "http server task exited with an error"),
        Err(e) if e.is_cancelled() => {}
        Err(e) => tracing::warn!(error = %e, "http server task panicked"),
    }

    drop(ctx); // release the Context's Arc<Replica> holders
    match Arc::try_unwrap(replica) {
        Ok(r) => r.shutdown().await,
        Err(_) => tracing::warn!("replica still shared at shutdown; letting process exit reap it"),
    }
    Ok(())
}

async fn shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("sigterm handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}
