//! Replica engine: the embeddable sync client behind a read-only mirror.
//!
//! [`Replica`] connects out to an authoritative bunker over
//! `secret-bunker-sync/1`, converges the local store onto the manifest,
//! follows live push events, and reconnects with exponential backoff. A
//! library consumer (say, a Kubernetes operator) observes the mirror via
//! `subscribe`/`get`/`list`/`groups`/`status` — and keeps reading it when
//! the authoritative node is unreachable, which is the whole point.
//!
//! Change events are emitted strictly AFTER the local transaction has
//! committed: an event is a promise that a subsequent [`Replica::get`]
//! sees the new state.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail, ensure};
use iroh::endpoint::{Connection, presets};
use iroh::{Endpoint, EndpointId, SecretKey};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use tokio::sync::{broadcast, watch};
use zeroize::Zeroizing;

use crate::agebridge;
use crate::crypto;
use crate::store::{AppliedChange, Store};
use crate::sync::{self, FetchedSecret, GroupSyncState, SYNC_ALPN, SyncMessage, SyncRequest};

/// First reconnect delay; doubles per failed attempt up to [`BACKOFF_CAP`]
/// and resets once a Hello succeeds.
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(60);

/// Broadcast capacity. A subscriber that falls further behind than this
/// observes `Lagged` and should resynchronize from `groups()`/`list()`.
const EVENTS_CAPACITY: usize = 1024;

/// What changed in the local mirror (or in the connection feeding it).
/// Data events fire only after their transaction has committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicaEvent {
    SecretChanged {
        group: String,
        name: String,
        version: u64,
    },
    SecretDeleted {
        group: String,
        name: String,
    },
    GroupAdded {
        group: String,
    },
    GroupRemoved {
        group: String,
    },
    Connected,
    Disconnected,
}

/// A point-in-time snapshot of the replica's sync state.
#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub connected: bool,
    pub last_synced: Option<SystemTime>,
    pub groups: Vec<String>,
    pub authoritative: EndpointId,
}

struct StatusInner {
    connected: bool,
    last_synced: Option<SystemTime>,
}

struct ReplicaInner {
    store: Mutex<Store>,
    /// The age identity derived from the replica's endpoint secret — the
    /// only identity that can open the mirror's DEK wraps.
    age_identity: age::x25519::Identity,
    /// This replica's own EndpointId in the lowercase-hex form used as
    /// `dek_wrap.recipient`.
    endpoint_hex: String,
    events: broadcast::Sender<ReplicaEvent>,
    status: Mutex<StatusInner>,
    authoritative: EndpointId,
    endpoint: Endpoint,
    /// Whether `spawn` bound `endpoint` itself (then `shutdown` closes it)
    /// or the embedder supplied it (then its lifecycle stays theirs).
    owned_endpoint: bool,
    shutdown: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ReplicaInner {
    /// Serialized store access. The guard must never live across an await
    /// point; all users take it in a sync block, work, and drop it before
    /// the next await. A poisoned lock is taken over rather than
    /// propagated: SQLite transactions keep the data consistent even if a
    /// task panicked mid-call.
    fn lock_store(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_status(&self) -> MutexGuard<'_, StatusInner> {
        self.status.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn emit(&self, event: ReplicaEvent) {
        // Err only means nobody is subscribed right now.
        let _ = self.events.send(event);
    }
}

/// A running replica: a handle over the shared engine state. Dropping it
/// without [`Replica::shutdown`] leaves the sync task running until the
/// runtime shuts down.
pub struct Replica {
    inner: Arc<ReplicaInner>,
}

impl std::fmt::Debug for Replica {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replica")
            .field("authoritative", &self.inner.authoritative)
            .finish_non_exhaustive()
    }
}

impl Replica {
    pub fn builder() -> ReplicaBuilder {
        ReplicaBuilder::default()
    }

    /// Subscribe to mirror change events. Only events sent after this call
    /// are delivered — subscribe before awaiting anything if the initial
    /// sync matters to you.
    pub fn subscribe(&self) -> broadcast::Receiver<ReplicaEvent> {
        self.inner.events.subscribe()
    }

    /// Decrypt one secret's current version from the local mirror. Purely
    /// local: works with the authoritative node unreachable.
    pub fn get(&self, group: &str, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        let (sv, wrapped) = {
            let store = self.inner.lock_store();
            let group_id = store
                .group_id(group)?
                .with_context(|| format!("no group '{group}' in the local mirror"))?;
            let sv = store
                .secret_current(group_id, name)?
                .with_context(|| format!("no secret '{name}' in group '{group}'"))?;
            let wrapped = store
                .dek_wrap(group_id, sv.dek_version, &self.inner.endpoint_hex)?
                .with_context(|| {
                    format!(
                        "no DEK wrap for group '{group}' version {} — not yet synced",
                        sv.dek_version
                    )
                })?;
            (sv, wrapped)
        };
        // Unwrap and decrypt outside the lock; only this replica's derived
        // identity can open the wrap.
        let dek = crypto::unwrap_dek(&wrapped, &self.inner.age_identity)?;
        let aad = crypto::secret_aad(group, name, sv.version, sv.dek_version);
        let plaintext = crypto::decrypt_secret(&dek, &aad, &sv.nonce, &sv.ciphertext)?;
        Ok(Zeroizing::new(plaintext))
    }

    /// `(name, current_version)` of every secret in a mirrored group.
    pub fn list(&self, group: &str) -> Result<Vec<(String, u64)>> {
        let store = self.inner.lock_store();
        let group_id = store
            .group_id(group)?
            .with_context(|| format!("no group '{group}' in the local mirror"))?;
        store.list_secrets(group_id)
    }

    /// Every mirrored group name, ascending.
    pub fn groups(&self) -> Result<Vec<String>> {
        self.inner.lock_store().replica_group_names()
    }

    pub fn status(&self) -> SyncStatus {
        let (connected, last_synced) = {
            let status = self.inner.lock_status();
            (status.connected, status.last_synced)
        };
        let groups = self
            .inner
            .lock_store()
            .replica_group_names()
            .unwrap_or_default();
        SyncStatus {
            connected,
            last_synced,
            groups,
            authoritative: self.inner.authoritative,
        }
    }

    /// The handler serving this replica's mirror to its own clients over
    /// the client ALPN. Task 9 implements `ProtocolHandler` on it; until
    /// then it is constructible but not mountable.
    pub fn protocol_handler(&self) -> ReplicaServer {
        ReplicaServer {
            inner: self.inner.clone(),
        }
    }

    /// Stop the sync task and, if `spawn` bound the endpoint, close it.
    pub async fn shutdown(self) {
        let _ = self.inner.shutdown.send(true);
        let task = self
            .inner
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
        if self.inner.owned_endpoint {
            self.inner.endpoint.close().await;
        }
    }
}

/// The replica's serving side (client-ALPN reads answered from the local
/// mirror, writes redirected to the authoritative node). Task 9 gives it
/// its `ProtocolHandler` impl.
pub struct ReplicaServer {
    inner: Arc<ReplicaInner>,
}

impl std::fmt::Debug for ReplicaServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplicaServer")
            .field("authoritative", &self.inner.authoritative)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
pub struct ReplicaBuilder {
    store_path: Option<PathBuf>,
    secret_key: Option<SecretKey>,
    authoritative: Option<EndpointId>,
    endpoint: Option<Endpoint>,
}

impl ReplicaBuilder {
    /// Path of the local mirror database (created on first use).
    pub fn store_path(mut self, p: impl Into<PathBuf>) -> Self {
        self.store_path = Some(p.into());
        self
    }

    /// The replica's iroh secret key: its transport identity AND (via the
    /// derived age identity) the key its DEK wraps are addressed to.
    pub fn secret_key(mut self, k: SecretKey) -> Self {
        self.secret_key = Some(k);
        self
    }

    /// The authoritative bunker to sync from.
    pub fn authoritative(mut self, id: EndpointId) -> Self {
        self.authoritative = Some(id);
        self
    }

    /// Optional pre-bound endpoint; its secret key must match
    /// [`ReplicaBuilder::secret_key`]. Without one, `spawn` binds its own
    /// (n0 preset + mDNS resolve-only, as [`crate::client::Client`] does).
    pub fn endpoint(mut self, ep: Endpoint) -> Self {
        self.endpoint = Some(ep);
        self
    }

    /// Open (and role-check) the store, derive the age identity, bind the
    /// endpoint if none was supplied, and start the sync task.
    pub async fn spawn(self) -> Result<Replica> {
        let store_path = self
            .store_path
            .context("ReplicaBuilder: store_path is required")?;
        let secret = self
            .secret_key
            .context("ReplicaBuilder: secret_key is required")?;
        let authoritative = self
            .authoritative
            .context("ReplicaBuilder: authoritative is required")?;
        let endpoint_hex = secret.public().to_string();

        let store = Store::open(&store_path)?;
        check_role(&store, &authoritative, &endpoint_hex)?;
        let age_identity = agebridge::identity_from_secret(&secret)?;

        let (endpoint, owned_endpoint) = match self.endpoint {
            Some(ep) => {
                ensure!(
                    ep.id() == secret.public(),
                    "supplied endpoint belongs to {}, not to secret_key's {endpoint_hex} — \
                     its DEK wraps would be undecryptable",
                    ep.id()
                );
                (ep, false)
            }
            None => {
                let ep = Endpoint::builder(presets::N0)
                    .secret_key(secret)
                    .address_lookup(MdnsAddressLookup::builder().advertise(false))
                    .bind()
                    .await
                    .context("binding replica endpoint")?;
                (ep, true)
            }
        };

        let (events, _) = broadcast::channel(EVENTS_CAPACITY);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let inner = Arc::new(ReplicaInner {
            store: Mutex::new(store),
            age_identity,
            endpoint_hex,
            events,
            status: Mutex::new(StatusInner {
                connected: false,
                last_synced: None,
            }),
            authoritative,
            endpoint,
            owned_endpoint,
            shutdown,
            task: Mutex::new(None),
        });
        let task = tokio::spawn(run_sync(inner.clone(), shutdown_rx));
        *inner.task.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
        Ok(Replica { inner })
    }
}

/// Enforce the store's role bookkeeping: a database is stamped for one
/// role, one authoritative node, and one endpoint key on first use, and
/// refuses any other combination afterwards — syncing a mirror over the
/// wrong database must fail before the first byte moves.
fn check_role(store: &Store, authoritative: &EndpointId, own_hex: &str) -> Result<()> {
    match store.meta_get("role")?.as_deref() {
        None => {
            store.meta_set("role", "replica")?;
            store.meta_set("authoritative", &authoritative.to_string())?;
            store.meta_set("replica_endpoint_id", own_hex)?;
        }
        Some("replica") => {
            let stored = store.meta_get("authoritative")?.unwrap_or_default();
            ensure!(
                stored == authoritative.to_string(),
                "replica database syncs from authoritative node {stored}, not {authoritative}"
            );
            let stored = store.meta_get("replica_endpoint_id")?.unwrap_or_default();
            ensure!(
                stored == own_hex,
                "replica database belongs to endpoint {stored}, not {own_hex}"
            );
        }
        Some("authoritative") => {
            bail!(
                "this is an authoritative database, not a replica mirror — refusing to sync over it"
            )
        }
        Some(other) => bail!("database has unknown role '{other}'"),
    }
    Ok(())
}

// ---- the sync task ----

/// Why a session ended without an error.
enum SessionEnd {
    /// The server sent `ScopeChanged`: the whole manifest is stale. Cycle
    /// the stream — new bi stream, new Hello — on the same connection.
    CycleStream,
    /// [`Replica::shutdown`] was called.
    Shutdown,
}

/// The reconnect loop: one [`run_connection`] per attempt, exponential
/// backoff between failures, until shutdown.
async fn run_sync(inner: Arc<ReplicaInner>, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = BACKOFF_INITIAL;
    loop {
        match run_connection(&inner, &mut shutdown, &mut backoff).await {
            Ok(()) => return, // shutdown requested
            Err(err) => tracing::debug!(%err, "sync connection lost"),
        }
        set_disconnected(&inner);
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.changed() => return,
        }
        backoff = (backoff * 2).min(BACKOFF_CAP);
    }
}

/// Dial the authoritative node and run Hello sessions on the connection
/// until it fails (`Err`) or shutdown is requested (`Ok`).
async fn run_connection(
    inner: &Arc<ReplicaInner>,
    shutdown: &mut watch::Receiver<bool>,
    backoff: &mut Duration,
) -> Result<()> {
    let conn = tokio::select! {
        res = inner.endpoint.connect(inner.authoritative, SYNC_ALPN) => {
            res.context("connecting to authoritative node")?
        }
        _ = shutdown.changed() => return Ok(()),
    };
    loop {
        match run_session(inner, &conn, shutdown, backoff).await? {
            SessionEnd::CycleStream => continue,
            SessionEnd::Shutdown => {
                conn.close(0u32.into(), b"shutdown");
                return Ok(());
            }
        }
    }
}

/// One Hello session: stream the manifest, apply it as a full resync,
/// then follow live push events.
async fn run_session(
    inner: &Arc<ReplicaInner>,
    conn: &Connection,
    shutdown: &mut watch::Receiver<bool>,
    backoff: &mut Duration,
) -> Result<SessionEnd> {
    // The send half stays open (unfinished) for the session's lifetime;
    // the server only ever reads the one Hello from it.
    let (mut send, mut recv) = conn.open_bi().await.context("opening session stream")?;
    sync::write_msg(&mut send, &SyncRequest::Hello).await?;

    // Manifest phase: stash Group/GroupSecrets until ManifestDone.
    // Repeated Group messages with one name merge (acl/deks append), and
    // GroupSecrets chunks append — the server's chunking contract.
    let mut hello_ok = false;
    let mut stash: Vec<GroupSyncState> = Vec::new();
    loop {
        let msg = tokio::select! {
            msg = sync::read_msg::<SyncMessage>(&mut recv) => msg?,
            _ = shutdown.changed() => return Ok(SessionEnd::Shutdown),
        };
        let Some(msg) = msg else {
            bail!("session stream ended during manifest");
        };
        if !hello_ok {
            // The first reply decides: SyncDenied means this key is not
            // registered (or holds no identity row) upstream. Anything
            // else means the session is live.
            if matches!(msg, SyncMessage::SyncDenied) {
                bail!(
                    "authoritative node denied sync — is this replica's identity \
                     registered with a read grant?"
                );
            }
            hello_ok = true;
            *backoff = BACKOFF_INITIAL;
            set_connected(inner);
        }
        match msg {
            SyncMessage::Group { name, acl, deks } => {
                if let Some(entry) = stash.iter_mut().find(|s| s.name == name) {
                    entry.acl.extend(acl);
                    entry.deks.extend(deks);
                } else {
                    stash.push(GroupSyncState {
                        name,
                        acl,
                        deks,
                        secrets: Vec::new(),
                    });
                }
            }
            SyncMessage::GroupSecrets { group, secrets } => {
                if let Some(entry) = stash.iter_mut().find(|s| s.name == group) {
                    entry.secrets.extend(secrets);
                } else {
                    stash.push(GroupSyncState {
                        name: group,
                        secrets,
                        ..GroupSyncState::default()
                    });
                }
            }
            SyncMessage::ManifestDone => break,
            other => bail!("unexpected message during manifest: {other:?}"),
        }
    }

    full_resync(inner, conn, &stash).await?;

    // Live phase: follow push events until the scope moves, the peer goes
    // away, or shutdown.
    loop {
        let msg = tokio::select! {
            msg = sync::read_msg::<SyncMessage>(&mut recv) => msg?,
            _ = shutdown.changed() => return Ok(SessionEnd::Shutdown),
        };
        match msg {
            Some(SyncMessage::Changed { group }) => {
                sync_group_via_fetch(inner, conn, &group).await?;
            }
            Some(SyncMessage::ScopeChanged) => return Ok(SessionEnd::CycleStream),
            Some(other) => bail!("unexpected live-push message: {other:?}"),
            None => bail!("session stream ended"),
        }
    }
}

/// Apply a complete manifest: converge every stashed group, then drop the
/// local groups the manifest does not carry. Only a COMPLETED manifest
/// proves absence — a torn stream never reaches this function — so this
/// is the one place manifest-diff drops may happen. Ends with an identity
/// sweep: a drop can orphan identity rows shared with no other group.
async fn full_resync(
    inner: &Arc<ReplicaInner>,
    conn: &Connection,
    stash: &[GroupSyncState],
) -> Result<()> {
    for state in stash {
        sync_one_group(inner, conn, state).await?;
    }
    let manifest: BTreeSet<&str> = stash.iter().map(|s| s.name.as_str()).collect();
    let stale: Vec<String> = {
        let store = inner.lock_store();
        store
            .replica_group_names()?
            .into_iter()
            .filter(|name| !manifest.contains(name.as_str()))
            .collect()
    };
    for name in &stale {
        drop_group(inner, name)?;
    }
    inner.lock_store().gc_unreferenced_identities()?;
    touch_last_synced(inner);
    Ok(())
}

/// Converge one group onto `state`: fetch what differs, apply, publish.
/// Undecryptable entries (the state raced a DEK rotation upstream) get
/// ONE immediate re-fetch of the whole group; if that still skips, the
/// group is left short and the next `Changed` push heals it.
async fn sync_one_group(
    inner: &Arc<ReplicaInner>,
    conn: &Connection,
    state: &GroupSyncState,
) -> Result<()> {
    match apply_group_state(inner, conn, state).await? {
        ApplyOutcome::Applied {
            skipped_undecryptable: false,
        } => Ok(()),
        ApplyOutcome::Applied {
            skipped_undecryptable: true,
        } => match fetch_group_state(conn, &state.name).await? {
            Some(fresh) => {
                if matches!(
                    apply_group_state(inner, conn, &fresh).await?,
                    ApplyOutcome::Denied
                ) {
                    drop_group_and_gc(inner, &state.name)?;
                }
                Ok(())
            }
            None => drop_group_and_gc(inner, &state.name),
        },
        ApplyOutcome::Denied => drop_group_and_gc(inner, &state.name),
    }
}

/// The `Changed{group}` path: re-fetch the group's state and converge.
/// `SyncDenied` on a held group means read access was revoked — its local
/// mirror goes.
async fn sync_group_via_fetch(
    inner: &Arc<ReplicaInner>,
    conn: &Connection,
    group: &str,
) -> Result<()> {
    match fetch_group_state(conn, group).await? {
        Some(state) => sync_one_group(inner, conn, &state).await,
        None => drop_group_and_gc(inner, group),
    }
}

enum ApplyOutcome {
    /// The state was applied and its events published.
    /// `skipped_undecryptable` flags fetched secrets whose `dek_version`
    /// had no wrap in the state. They MUST be withheld from the apply:
    /// once a row matches the manifest's `(version, dek_version, nonce)`,
    /// `secrets_needing_fetch` never lists it again, and an applied-but-
    /// undecryptable secret would be wedged until its next upstream write.
    Applied { skipped_undecryptable: bool },
    /// The authoritative node denied the secret fetch: read access on
    /// this group is gone.
    Denied,
}

/// Fetch the secrets `state` obsoletes and apply the whole state in one
/// local transaction; publish `GroupAdded` and per-secret events strictly
/// after the commit.
async fn apply_group_state(
    inner: &Arc<ReplicaInner>,
    conn: &Connection,
    state: &GroupSyncState,
) -> Result<ApplyOutcome> {
    let (needed, was_absent) = {
        let store = inner.lock_store();
        (
            store.secrets_needing_fetch(state)?,
            store.group_id(&state.name)?.is_none(),
        )
    };
    let mut fetched = Vec::new();
    if !needed.is_empty() {
        match fetch_secrets(conn, &state.name, needed).await? {
            Some(secrets) => fetched = secrets,
            None => return Ok(ApplyOutcome::Denied),
        }
    }
    let wrapped_versions: BTreeSet<u64> = state.deks.iter().map(|d| d.version).collect();
    let before = fetched.len();
    fetched.retain(|s| wrapped_versions.contains(&s.dek_version));
    let skipped_undecryptable = fetched.len() != before;

    let changes = {
        let mut store = inner.lock_store();
        let changes = store.apply_group_sync(&inner.endpoint_hex, state, &fetched)?;
        // The replica keeps its own audit chain: one row per applied sync.
        if let Err(err) = store.audit("(sync)", "sync-apply", &state.name, "ok") {
            tracing::error!(%err, "audit append failed");
        }
        changes
    };
    // Events strictly after the commit (`apply_group_sync` committed
    // above, the lock is dropped): each event is a promise that `get`
    // sees the new state.
    if was_absent {
        inner.emit(ReplicaEvent::GroupAdded {
            group: state.name.clone(),
        });
    }
    for change in changes {
        inner.emit(match change {
            AppliedChange::SecretChanged { name, version } => ReplicaEvent::SecretChanged {
                group: state.name.clone(),
                name,
                version,
            },
            AppliedChange::SecretDeleted { name } => ReplicaEvent::SecretDeleted {
                group: state.name.clone(),
                name,
            },
        });
    }
    touch_last_synced(inner);
    Ok(ApplyOutcome::Applied {
        skipped_undecryptable,
    })
}

/// `FetchSecrets` on a fresh bi stream: `SecretData*` until `FetchDone`,
/// or `None` on `SyncDenied`. Names that vanished upstream are silently
/// absent from the result — the server skips them, and the push channel
/// reports the mutation that removed them separately.
async fn fetch_secrets(
    conn: &Connection,
    group: &str,
    names: Vec<String>,
) -> Result<Option<Vec<FetchedSecret>>> {
    let (mut send, mut recv) = conn.open_bi().await.context("opening fetch stream")?;
    sync::write_msg(
        &mut send,
        &SyncRequest::FetchSecrets {
            group: group.to_string(),
            names,
        },
    )
    .await?;
    send.finish().context("finishing fetch stream")?;
    let mut out = Vec::new();
    loop {
        match sync::read_msg::<SyncMessage>(&mut recv).await? {
            Some(SyncMessage::SecretData {
                name,
                version,
                dek_version,
                nonce,
                ciphertext,
                created_at,
                created_by,
            }) => out.push(FetchedSecret {
                name,
                version,
                dek_version,
                nonce,
                ciphertext,
                created_at,
                created_by,
            }),
            Some(SyncMessage::FetchDone) => return Ok(Some(out)),
            Some(SyncMessage::SyncDenied) => return Ok(None),
            Some(other) => bail!("unexpected message during secret fetch: {other:?}"),
            None => bail!("secret fetch stream ended before FetchDone"),
        }
    }
}

/// `FetchGroup` on a fresh bi stream: `Group` + `GroupSecrets` chunks
/// until `FetchDone`, merged the same way the manifest merges. `None` on
/// `SyncDenied` (access revoked, or the group vanished upstream).
async fn fetch_group_state(conn: &Connection, group: &str) -> Result<Option<GroupSyncState>> {
    let (mut send, mut recv) = conn.open_bi().await.context("opening fetch stream")?;
    sync::write_msg(
        &mut send,
        &SyncRequest::FetchGroup {
            group: group.to_string(),
        },
    )
    .await?;
    send.finish().context("finishing fetch stream")?;
    let mut state = GroupSyncState {
        name: group.to_string(),
        ..GroupSyncState::default()
    };
    loop {
        match sync::read_msg::<SyncMessage>(&mut recv).await? {
            Some(SyncMessage::Group { name, acl, deks }) => {
                ensure!(
                    name == group,
                    "fetch for '{group}' answered with group '{name}'"
                );
                state.acl.extend(acl);
                state.deks.extend(deks);
            }
            Some(SyncMessage::GroupSecrets {
                group: listed,
                secrets,
            }) => {
                ensure!(
                    listed == group,
                    "fetch for '{group}' answered with listing for '{listed}'"
                );
                state.secrets.extend(secrets);
            }
            Some(SyncMessage::FetchDone) => return Ok(Some(state)),
            Some(SyncMessage::SyncDenied) => return Ok(None),
            Some(other) => bail!("unexpected message during group fetch: {other:?}"),
            None => bail!("group fetch stream ended before FetchDone"),
        }
    }
}

/// Drop a group's local mirror and publish `GroupRemoved` if it was held.
fn drop_group(inner: &ReplicaInner, name: &str) -> Result<()> {
    let dropped = {
        let mut store = inner.lock_store();
        store.drop_group_local(name)?
    };
    if dropped {
        inner.emit(ReplicaEvent::GroupRemoved {
            group: name.to_string(),
        });
    }
    Ok(())
}

/// [`drop_group`] plus the identity sweep, for drops outside a full
/// resync (which sweeps once at its end instead).
fn drop_group_and_gc(inner: &ReplicaInner, name: &str) -> Result<()> {
    drop_group(inner, name)?;
    inner.lock_store().gc_unreferenced_identities()?;
    Ok(())
}

fn set_connected(inner: &ReplicaInner) {
    let flipped = {
        let mut status = inner.lock_status();
        !std::mem::replace(&mut status.connected, true)
    };
    if flipped {
        inner.emit(ReplicaEvent::Connected);
    }
}

fn set_disconnected(inner: &ReplicaInner) {
    let flipped = {
        let mut status = inner.lock_status();
        std::mem::replace(&mut status.connected, false)
    };
    if flipped {
        inner.emit(ReplicaEvent::Disconnected);
    }
}

fn touch_last_synced(inner: &ReplicaInner) {
    inner.lock_status().last_synced = Some(SystemTime::now());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_secret() -> SecretKey {
        SecretKey::generate()
    }

    #[tokio::test]
    async fn spawn_requires_the_builder_fields() {
        let err = Replica::builder().spawn().await.unwrap_err().to_string();
        assert!(err.contains("store_path"), "unhelpful error: {err}");
    }

    #[tokio::test]
    async fn spawn_refuses_an_authoritative_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("auth.sqlite");
        {
            let mut store = Store::open(&db).unwrap();
            let op = age::x25519::Identity::generate();
            store
                .init(
                    &op.to_public().to_string(),
                    &op.to_public().to_string(),
                    &fresh_secret().public().to_string(),
                    "admin",
                )
                .unwrap();
        }
        let err = Replica::builder()
            .store_path(&db)
            .secret_key(fresh_secret())
            .authoritative(fresh_secret().public())
            .spawn()
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("authoritative database"),
            "unhelpful error: {err}"
        );
    }

    #[tokio::test]
    async fn spawn_refuses_a_mismatched_replica_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("replica.sqlite");
        let secret = fresh_secret();
        let stamped_auth = fresh_secret().public();
        {
            let store = Store::open(&db).unwrap();
            store.meta_set("role", "replica").unwrap();
            store
                .meta_set("authoritative", &stamped_auth.to_string())
                .unwrap();
            store
                .meta_set("replica_endpoint_id", &secret.public().to_string())
                .unwrap();
        }
        // A different authoritative node is refused ...
        let err = Replica::builder()
            .store_path(&db)
            .secret_key(secret.clone())
            .authoritative(fresh_secret().public())
            .spawn()
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("syncs from"), "unhelpful error: {err}");
        // ... and so is a different endpoint key.
        let err = Replica::builder()
            .store_path(&db)
            .secret_key(fresh_secret())
            .authoritative(stamped_auth)
            .spawn()
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("belongs to endpoint"),
            "unhelpful error: {err}"
        );
    }

    #[tokio::test]
    async fn spawn_refuses_an_endpoint_under_a_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(fresh_secret())
            .bind()
            .await
            .unwrap();
        let err = Replica::builder()
            .store_path(dir.path().join("replica.sqlite"))
            .secret_key(fresh_secret())
            .authoritative(fresh_secret().public())
            .endpoint(ep.clone())
            .spawn()
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("supplied endpoint"), "unhelpful error: {err}");
        ep.close().await;
    }

    #[tokio::test]
    async fn spawn_stamps_a_fresh_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("replica.sqlite");
        let secret = fresh_secret();
        let authoritative = fresh_secret().public(); // unreachable: fine, the task backs off
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(secret.clone())
            .bind()
            .await
            .unwrap();
        let replica = Replica::builder()
            .store_path(&db)
            .secret_key(secret.clone())
            .authoritative(authoritative)
            .endpoint(ep.clone())
            .spawn()
            .await
            .unwrap();
        let status = replica.status();
        assert!(!status.connected);
        assert_eq!(status.authoritative, authoritative);
        assert!(status.last_synced.is_none());
        assert!(replica.groups().unwrap().is_empty());
        replica.shutdown().await;
        ep.close().await;

        let store = Store::open(&db).unwrap();
        assert_eq!(store.meta_get("role").unwrap().unwrap(), "replica");
        assert_eq!(
            store.meta_get("authoritative").unwrap().unwrap(),
            authoritative.to_string()
        );
        assert_eq!(
            store.meta_get("replica_endpoint_id").unwrap().unwrap(),
            secret.public().to_string()
        );
        // Reopening with the same key and authoritative node is fine.
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(secret.clone())
            .bind()
            .await
            .unwrap();
        let replica = Replica::builder()
            .store_path(&db)
            .secret_key(secret.clone())
            .authoritative(authoritative)
            .endpoint(ep.clone())
            .spawn()
            .await
            .unwrap();
        replica.shutdown().await;
        ep.close().await;
    }
}
