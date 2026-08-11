//! Embedded-replica integration: spawning, SecretSource impl, staleness clock.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use secret_bunker_iroh::replica::Replica;

use crate::render::{SecretSource, SourceError};

/// Wraps the replica for the render pipeline. Classification probes the mirror
/// (groups/list) instead of parsing anyhow messages.
pub struct ReplicaSource(pub Arc<Replica>);

impl SecretSource for ReplicaSource {
    fn list(&self, group: &str) -> Result<Vec<String>, SourceError> {
        if !group_exists(&self.0, group)? {
            return Err(SourceError::MissingGroup);
        }
        let entries = self
            .0
            .list(group)
            .map_err(|e| SourceError::Other(e.to_string()))?;
        Ok(entries.into_iter().map(|(name, _version)| name).collect())
    }

    fn get(&self, group: &str, name: &str) -> Result<Vec<u8>, SourceError> {
        match self.0.get(group, name) {
            Ok(v) => Ok(v.to_vec()),
            Err(e) => {
                if !group_exists(&self.0, group)? {
                    return Err(SourceError::MissingGroup);
                }
                let names = self
                    .0
                    .list(group)
                    .map_err(|e| SourceError::Other(e.to_string()))?;
                if !names.iter().any(|(n, _)| n == name) {
                    return Err(SourceError::MissingSecret);
                }
                // Present in the mirror but unreadable: DEK wrap race — retryable.
                Err(SourceError::NotYetSynced(e.to_string()))
            }
        }
    }
}

fn group_exists(replica: &Replica, group: &str) -> Result<bool, SourceError> {
    let groups = replica
        .groups()
        .map_err(|e| SourceError::Other(e.to_string()))?;
    Ok(groups.iter().any(|g| g == group))
}

/// Tracks how long the sync session has been down. Starts "disconnected" at
/// process start so a bunker that is unreachable from boot still trips the
/// staleness threshold.
pub struct Staleness {
    disconnected_since: Mutex<Option<Instant>>,
}

impl Staleness {
    pub fn new() -> Staleness {
        Staleness {
            disconnected_since: Mutex::new(Some(Instant::now())),
        }
    }

    pub fn set_connected(&self, connected: bool) {
        let mut guard = self.disconnected_since.lock().unwrap();
        if connected {
            *guard = None;
        } else if guard.is_none() {
            *guard = Some(Instant::now());
        }
    }

    pub fn disconnected_for(&self) -> Option<Duration> {
        self.disconnected_since.lock().unwrap().map(|t| t.elapsed())
    }
}

impl Default for Staleness {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn the embedded replica from operator config. Key resolution (file or
/// managed Secret) happens in `main`/`identity` before this — by the time we
/// are here an identity exists; nothing is ever auto-generated past this
/// point.
pub async fn spawn_replica(
    id: &str,
    addrs: &[SocketAddr],
    secret: iroh::SecretKey,
    mirror_path: &Path,
) -> anyhow::Result<Replica> {
    let authoritative: iroh::EndpointId =
        id.parse().context("parsing --bunker-id as an EndpointId")?;
    tracing::info!(
        operator_id = %secret.public(),
        %authoritative,
        "spawning embedded replica"
    );
    let mut builder = Replica::builder()
        .store_path(mirror_path)
        .secret_key(secret)
        .authoritative(authoritative);
    if !addrs.is_empty() {
        builder = builder.authoritative_addrs(addrs.iter().copied());
    }
    builder.spawn().await
}
