//! The bunker protocol handler.
//!
//! Authentication is the iroh handshake: `Connection::remote_id()` is the
//! cryptographically verified EndpointId of the peer. Anyone may connect;
//! authorization happens per request against the ACL, and unknown identity,
//! missing permission, and nonexistent target are indistinguishable
//! (`Response::Denied`). See design/crypto-design.md sections 5 and 7.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::Result;
use iroh::endpoint::{Connection, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::sync::broadcast;
use zeroize::Zeroize;

use crate::crypto;
use crate::proto::{self, IdentityInfo, Request, Response};
use crate::store::{
    CasOutcome, Identity, PERM_ADMIN, PERM_READ, PERM_WRITE, RECIPIENT_BACKUP,
    RECIPIENT_OPERATIONAL, Store,
};
use crate::sync::{self, SyncMessage, SyncRequest};

pub struct Bunker(Arc<Inner>);

struct Inner {
    store: Mutex<Store>,
    op_identity: age::x25519::Identity,
    op_recipient: age::x25519::Recipient,
    backup_recipient: age::x25519::Recipient,
    /// Names of groups touched by successful mutations, fanned out to
    /// live sync sessions. A session that falls behind the channel
    /// capacity observes `Lagged` and resynchronizes via `ScopeChanged`,
    /// so dropped events degrade to extra work, never to missed changes.
    events: broadcast::Sender<String>,
}

impl Inner {
    /// See [`Bunker::lock_store`]; shared with the sync handler.
    fn lock_store(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Clone for Bunker {
    fn clone(&self) -> Self {
        Bunker(self.0.clone())
    }
}

impl fmt::Debug for Bunker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bunker").finish_non_exhaustive()
    }
}

impl Bunker {
    /// Opens the bunker over an initialized store. Verifies that the
    /// supplied operational identity matches the pubkey recorded at init.
    pub fn new(store: Store, op_identity: age::x25519::Identity) -> Result<Self> {
        let recorded = store
            .meta_get("operational_pubkey")?
            .ok_or_else(|| anyhow::anyhow!("database is not initialized (run `init` first)"))?;
        let op_recipient = op_identity.to_public();
        anyhow::ensure!(
            op_recipient.to_string() == recorded,
            "operational key does not match the one recorded in the database"
        );
        let backup = store
            .meta_get("backup_pubkey")?
            .ok_or_else(|| anyhow::anyhow!("database has no backup pubkey"))?;
        let backup_recipient = crate::keys::parse_age_recipient(&backup)?;
        Ok(Bunker(Arc::new(Inner {
            store: Mutex::new(store),
            op_identity,
            op_recipient,
            backup_recipient,
            events: broadcast::channel(1024).0,
        })))
    }

    /// Lock the store, recovering from poisoning: a panicked request must
    /// not brick every later one, and SQLite transactions roll back when
    /// dropped mid-panic, so the store itself stays consistent.
    pub(crate) fn lock_store(&self) -> MutexGuard<'_, Store> {
        self.0.lock_store()
    }

    /// Create the reader wraps that grants made before per-reader
    /// wrapping existed never got: one wrap per read-granted identity per
    /// retained DEK version. Idempotent — returns how many rows it
    /// created, 0 once the database is fully wrapped. Run at startup, on
    /// the authoritative node, before serving.
    pub fn backfill_reader_wraps(&self) -> Result<usize> {
        let inner = &*self.0;
        let store = self.lock_store();
        let missing = store.missing_reader_wraps()?;
        for (group_id, version, endpoint_id) in &missing {
            let dek = Self::unwrap_dek(inner, &store, *group_id, *version)?;
            let wrapped = Self::wrap_for_reader(&dek, endpoint_id)?.1;
            store.add_dek_wrap(*group_id, *version, endpoint_id, &wrapped)?;
        }
        Ok(missing.len())
    }

    /// The operational and backup wraps every DEK version carries.
    fn base_wraps(inner: &Inner, dek: &crypto::Dek) -> Result<Vec<(String, Vec<u8>)>> {
        Ok(vec![
            (
                RECIPIENT_OPERATIONAL.to_string(),
                crypto::wrap_dek(dek, &inner.op_recipient)?,
            ),
            (
                RECIPIENT_BACKUP.to_string(),
                crypto::wrap_dek(dek, &inner.backup_recipient)?,
            ),
        ])
    }

    /// A reader's wrap, keyed by its EndpointId, encrypted to the age
    /// recipient derived from that same EndpointId.
    fn wrap_for_reader(dek: &crypto::Dek, endpoint_id: &str) -> Result<(String, Vec<u8>)> {
        let recipient = crate::agebridge::recipient_for_endpoint_hex(endpoint_id)?;
        Ok((endpoint_id.to_string(), crypto::wrap_dek(dek, &recipient)?))
    }

    /// Wrap `dek` to operational + backup + every explicit reader of the
    /// group, skipping `exclude_endpoint` (the identity being revoked,
    /// whose ACL row is still in place while the new wraps are built).
    fn wrap_set_for_group(
        inner: &Inner,
        store: &Store,
        group_id: i64,
        dek: &crypto::Dek,
        exclude_endpoint: Option<&str>,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let mut wraps = Self::base_wraps(inner, dek)?;
        for reader in store.read_granted_identities(group_id)? {
            if Some(reader.endpoint_id.as_str()) == exclude_endpoint {
                continue;
            }
            wraps.push(Self::wrap_for_reader(dek, &reader.endpoint_id)?);
        }
        Ok(wraps)
    }

    /// Every retained DEK version of a group, re-wrapped to a new reader:
    /// `(dek_version, wrapped)`. Needs the operational key to unwrap what
    /// it re-wraps, so this only runs on the authoritative node.
    fn wraps_for_new_reader(
        inner: &Inner,
        store: &Store,
        group_id: i64,
        endpoint_id: &str,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        let recipient = crate::agebridge::recipient_for_endpoint_hex(endpoint_id)?;
        let mut wraps = Vec::new();
        for version in store.dek_versions(group_id)? {
            let dek = Self::unwrap_dek(inner, store, group_id, version)?;
            wraps.push((version, crypto::wrap_dek(&dek, &recipient)?));
        }
        Ok(wraps)
    }

    /// Decode and handle one raw request frame from an authenticated peer.
    /// Frames that fail to decode get the uniform denial and an audit entry.
    pub fn handle_raw(&self, remote: &str, bytes: &[u8]) -> Response {
        match proto::decode::<Request>(bytes) {
            Ok(mut req) => {
                let response = self.handle(remote, &req);
                // Best-effort scrub of the plaintext copy decode made.
                if let Request::Put { value, .. } = &mut req {
                    value.zeroize();
                }
                response
            }
            Err(_) => {
                let store = self.lock_store();
                if let Err(err) = store.audit(remote, "malformed", "", "denied") {
                    tracing::error!(%err, "audit append failed");
                }
                Response::Denied
            }
        }
    }

    /// Handle one decoded request from an authenticated peer. Synchronous:
    /// the store lock is never held across an await point.
    pub fn handle(&self, remote: &str, req: &Request) -> Response {
        let inner = &*self.0;
        let mut store = self.lock_store();
        // Groups a successful RemoveIdentity is about to touch (its ACL
        // rows cascade away, its read-granted groups rotate): resolved
        // before dispatch, published after — the identity is gone by then.
        let removal_scope: Vec<String> = match req {
            Request::RemoveIdentity { name } => match store.identity_by_name(name) {
                Ok(Some(target)) => store
                    .groups_for_identity(target.id)
                    .map(|groups| groups.into_iter().map(|(name, _)| name).collect())
                    .unwrap_or_default(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };
        let outcome = Self::dispatch(inner, &mut store, remote, req);
        let audit_outcome = match &outcome {
            Response::Denied => "denied",
            Response::VersionConflict { .. } => "conflict",
            Response::Failed { .. } => "failed",
            _ => "ok",
        };
        if let Err(err) = store.audit(remote, req.op(), &req.target(), audit_outcome) {
            tracing::error!(%err, "audit append failed");
        }
        if audit_outcome == "ok" {
            for group in Self::touched_groups(req, removal_scope) {
                // Err only means no live sync session is subscribed.
                let _ = inner.events.send(group);
            }
        }
        outcome
    }

    /// The group names a successful `req` mutated, for the sync event
    /// channel. Deliberately exhaustive: a new Request variant must decide
    /// here what it touches. Over-notification only costs a session a
    /// scope recheck; under-notification is a correctness bug.
    fn touched_groups(req: &Request, removal_scope: Vec<String>) -> Vec<String> {
        match req {
            Request::Put { group, .. }
            | Request::Delete { group, .. }
            | Request::Grant { group, .. }
            | Request::RotateDek { group } => vec![group.clone()],
            Request::CreateGroup { name } => vec![name.clone()],
            // Every group the removed identity held any row on: the
            // read-granted ones rotated, and even write/admin-only rows
            // change the ACL a replica mirrors.
            Request::RemoveIdentity { .. } => removal_scope,
            // Reads and identity-level ops touch no group data or ACL row
            // (the service-admin flag carries no explicit-read scope).
            Request::Get { .. }
            | Request::List { .. }
            | Request::ListGroups
            | Request::GroupAcl { .. }
            | Request::ListIdentities
            | Request::ListIdentityNames { .. }
            | Request::AddIdentity { .. }
            | Request::SetServiceAdmin { .. } => Vec::new(),
        }
    }

    fn dispatch(inner: &Inner, store: &mut Store, remote: &str, req: &Request) -> Response {
        // Every code path below that touches a group, secret, or service
        // operation must pass through `perms` / `service_admin` checks and
        // fall back to Denied. Internal errors on unauthorized paths also
        // collapse to Denied so errors cannot be used as an oracle.
        let Ok(Some(ident)) = store.identity_by_endpoint(remote) else {
            return Response::Denied;
        };
        match req {
            Request::Get { group, name } => Self::get(inner, store, &ident, group, name),
            Request::Put {
                group,
                name,
                value,
                expected_version,
            } => Self::put(inner, store, &ident, group, name, value, *expected_version),
            Request::Delete {
                group,
                name,
                expected_version,
            } => Self::delete(store, &ident, group, name, *expected_version),
            Request::List { group } => Self::list(store, &ident, group),
            Request::CreateGroup { name } => Self::create_group(inner, store, &ident, name),
            Request::AddIdentity {
                name,
                endpoint_id,
                service_admin,
            } => Self::add_identity(store, &ident, name, endpoint_id, *service_admin),
            Request::RemoveIdentity { name } => Self::remove_identity(inner, store, &ident, name),
            Request::ListIdentities => Self::list_identities(store, &ident),
            Request::Grant {
                group,
                identity,
                perms,
            } => Self::grant(inner, store, &ident, group, identity, *perms),
            Request::RotateDek { group } => Self::rotate_dek(inner, store, &ident, group),
            Request::ListGroups => Self::list_groups(store, &ident),
            Request::GroupAcl { group } => Self::group_acl(store, &ident, group),
            Request::ListIdentityNames { group } => Self::list_identity_names(store, &ident, group),
            Request::SetServiceAdmin {
                name,
                service_admin,
            } => Self::set_service_admin(store, &ident, name, *service_admin),
        }
    }

    fn list_groups(store: &Store, ident: &Identity) -> Response {
        let groups = if ident.service_admin {
            store.all_groups_with_perms(ident.id)
        } else {
            store.groups_for_identity(ident.id)
        };
        match groups {
            Ok(groups) => Response::Groups {
                service_admin: ident.service_admin,
                groups: groups
                    .into_iter()
                    .map(|(name, perms)| crate::proto::GroupInfo {
                        name,
                        // Report effective perms: service admins hold
                        // every bit on every group.
                        perms: if ident.service_admin {
                            PERM_READ | PERM_WRITE | PERM_ADMIN
                        } else {
                            perms
                        },
                    })
                    .collect(),
            },
            Err(_) => Response::Failed {
                reason: "internal error".into(),
            },
        }
    }

    fn group_acl(store: &Store, ident: &Identity, group: &str) -> Response {
        let Some(group_id) = Self::authorize_group(store, ident, group, PERM_ADMIN) else {
            return Response::Denied;
        };
        match store.group_acl_entries(group_id) {
            Ok(entries) => Response::Acl(entries),
            Err(_) => Response::Failed {
                reason: "internal error".into(),
            },
        }
    }

    fn list_identity_names(store: &Store, ident: &Identity, group: &str) -> Response {
        if Self::authorize_group(store, ident, group, PERM_ADMIN).is_none() {
            return Response::Denied;
        }
        match store.list_identities() {
            Ok(ids) => Response::IdentityNames(ids.into_iter().map(|i| i.name).collect()),
            Err(_) => Response::Failed {
                reason: "internal error".into(),
            },
        }
    }

    /// Resolve a group and check that `ident` holds all bits in `needed`.
    /// Service admins implicitly hold every bit on every group.
    fn authorize_group(store: &Store, ident: &Identity, group: &str, needed: u8) -> Option<i64> {
        let group_id = store.group_id(group).ok()??;
        if ident.service_admin {
            return Some(group_id);
        }
        let perms = store.perms(ident.id, group_id).ok()?;
        (perms & needed == needed).then_some(group_id)
    }

    fn unwrap_dek(
        inner: &Inner,
        store: &Store,
        group_id: i64,
        version: u64,
    ) -> Result<crypto::Dek> {
        let wrapped = store
            .dek_wrap(group_id, version, RECIPIENT_OPERATIONAL)?
            .ok_or_else(|| {
                anyhow::anyhow!("no operational wrap for group {group_id} DEK v{version}")
            })?;
        crypto::unwrap_dek(&wrapped, &inner.op_identity)
    }

    fn get(inner: &Inner, store: &Store, ident: &Identity, group: &str, name: &str) -> Response {
        let Some(group_id) = Self::authorize_group(store, ident, group, PERM_READ) else {
            return Response::Denied;
        };
        let Ok(Some(sv)) = store.secret_current(group_id, name) else {
            return Response::Denied;
        };
        let plaintext = Self::unwrap_dek(inner, store, group_id, sv.dek_version).and_then(|dek| {
            let aad = crypto::secret_aad(group, name, sv.version, sv.dek_version);
            crypto::decrypt_secret(&dek, &aad, &sv.nonce, &sv.ciphertext)
        });
        match plaintext {
            Ok(value) => Response::Secret {
                value,
                version: sv.version,
            },
            Err(err) => {
                tracing::error!(%err, group, name, "failed to decrypt secret");
                Response::Failed {
                    reason: "internal error".into(),
                }
            }
        }
    }

    fn put(
        inner: &Inner,
        store: &mut Store,
        ident: &Identity,
        group: &str,
        name: &str,
        value: &[u8],
        expected_version: u64,
    ) -> Response {
        let Some(group_id) = Self::authorize_group(store, ident, group, PERM_WRITE) else {
            return Response::Denied;
        };
        let Ok(dek_version) = store.current_dek_version(group_id) else {
            return Response::Failed {
                reason: "internal error".into(),
            };
        };
        let wrapped_op = match store.dek_wrap(group_id, dek_version, RECIPIENT_OPERATIONAL) {
            Ok(Some(w)) => w,
            _ => {
                return Response::Failed {
                    reason: "internal error".into(),
                };
            }
        };
        let new_version = match store.secret_version(group_id, name) {
            Ok(v) => v.unwrap_or(0) + 1,
            Err(_) => {
                return Response::Failed {
                    reason: "internal error".into(),
                };
            }
        };
        // The CAS inside put_secret is authoritative; new_version here is
        // only used to bind the AAD, and equals current+1 exactly when the
        // CAS succeeds (expected_version == current). checked_add: the wire
        // can carry u64::MAX, which must be a conflict, not an overflow
        // panic (debug builds) while the store lock is held.
        let Some(target_version) = expected_version.checked_add(1) else {
            return Response::VersionConflict {
                current: new_version - 1,
            };
        };
        if target_version != new_version && expected_version != 0 {
            // Fast-path conflict; the store would reject it anyway.
            return Response::VersionConflict {
                current: new_version - 1,
            };
        }
        let encrypted = crypto::unwrap_dek(&wrapped_op, &inner.op_identity)
            .map_err(|e| anyhow::anyhow!(e))
            .and_then(|dek| {
                let aad = crypto::secret_aad(group, name, target_version, dek_version);
                crypto::encrypt_secret(&dek, &aad, value)
            });
        let (nonce, ciphertext) = match encrypted {
            Ok(pair) => pair,
            Err(err) => {
                tracing::error!(%err, group, name, "failed to encrypt secret");
                return Response::Failed {
                    reason: "internal error".into(),
                };
            }
        };
        match store.put_secret(
            group_id,
            name,
            expected_version,
            dek_version,
            &nonce,
            &ciphertext,
            &ident.name,
        ) {
            Ok(CasOutcome::Applied { new_version }) => Response::Version {
                version: new_version,
            },
            Ok(CasOutcome::Conflict { current }) => Response::VersionConflict { current },
            Err(err) => {
                tracing::error!(%err, group, name, "failed to store secret");
                Response::Failed {
                    reason: "internal error".into(),
                }
            }
        }
    }

    fn delete(
        store: &mut Store,
        ident: &Identity,
        group: &str,
        name: &str,
        expected_version: u64,
    ) -> Response {
        let Some(group_id) = Self::authorize_group(store, ident, group, PERM_WRITE) else {
            return Response::Denied;
        };
        match store.delete_secret(group_id, name, expected_version) {
            Ok(CasOutcome::Applied { .. }) => Response::Ok,
            // A nonexistent secret surfaces as Conflict{current: 0}; after
            // a passed ACL check that is accurate feedback, not a leak.
            Ok(CasOutcome::Conflict { current }) => Response::VersionConflict { current },
            Err(err) => {
                tracing::error!(%err, group, name, "failed to delete secret");
                Response::Failed {
                    reason: "internal error".into(),
                }
            }
        }
    }

    fn list(store: &Store, ident: &Identity, group: &str) -> Response {
        let Some(group_id) = Self::authorize_group(store, ident, group, PERM_READ) else {
            return Response::Denied;
        };
        match store.list_secrets(group_id) {
            Ok(names) => Response::Names(names),
            Err(err) => {
                tracing::error!(%err, group, "failed to list secrets");
                Response::Failed {
                    reason: "internal error".into(),
                }
            }
        }
    }

    fn create_group(inner: &Inner, store: &mut Store, ident: &Identity, name: &str) -> Response {
        if !ident.service_admin {
            return Response::Denied;
        }
        if matches!(store.group_id(name), Ok(Some(_))) {
            return Response::Failed {
                reason: format!("group '{name}' already exists"),
            };
        }
        let dek = crypto::Dek::generate();
        // Every group needs a group admin from the start: the creator,
        // granted in the same transaction that creates the group — and
        // wrapped to, since that grant carries the read bit.
        let wraps = Self::base_wraps(inner, &dek).and_then(|mut wraps| {
            wraps.push(Self::wrap_for_reader(&dek, &ident.endpoint_id)?);
            Ok(wraps)
        });
        let wraps = match wraps {
            Ok(wraps) => wraps,
            Err(err) => {
                tracing::error!(%err, name, "failed to wrap group DEK");
                return Response::Failed {
                    reason: "internal error".into(),
                };
            }
        };
        if let Err(err) =
            store.create_group(name, &wraps, ident.id, PERM_READ | PERM_WRITE | PERM_ADMIN)
        {
            tracing::error!(%err, name, "failed to create group");
            return Response::Failed {
                reason: "internal error".into(),
            };
        }
        Response::Ok
    }

    fn add_identity(
        store: &Store,
        ident: &Identity,
        name: &str,
        endpoint_id: &str,
        service_admin: bool,
    ) -> Response {
        if !ident.service_admin {
            return Response::Denied;
        }
        // Validate and canonicalize to lowercase hex.
        let Ok(parsed) = endpoint_id.parse::<iroh::EndpointId>() else {
            return Response::Failed {
                reason: "invalid endpoint id".into(),
            };
        };
        match store.add_identity(name, &parsed.to_string(), service_admin) {
            Ok(()) => Response::Ok,
            Err(_) => Response::Failed {
                reason: "identity name or endpoint id already registered".into(),
            },
        }
    }

    fn remove_identity(inner: &Inner, store: &mut Store, ident: &Identity, name: &str) -> Response {
        if !ident.service_admin {
            return Response::Denied;
        }
        let target = match store.identity_by_name(name) {
            Ok(Some(target)) => target,
            Ok(None) => {
                return Response::Failed {
                    reason: format!("no identity named '{name}'"),
                };
            }
            Err(_) => {
                return Response::Failed {
                    reason: "internal error".into(),
                };
            }
        };
        if target.service_admin {
            let admins = store
                .list_identities()
                .map(|ids| ids.iter().filter(|i| i.service_admin).count())
                .unwrap_or(0);
            if admins <= 1 {
                return Response::Failed {
                    reason: "cannot remove the last service admin".into(),
                };
            }
        }
        // A removed identity keeps whatever DEK copies it already
        // unwrapped, so every group it could read is rotated away from it
        // — in the same transaction as the removal.
        let Ok(group_ids) = store.groups_with_read(target.id) else {
            return Response::Failed {
                reason: "internal error".into(),
            };
        };
        let mut rotations = Vec::with_capacity(group_ids.len());
        let mut rotated_names = Vec::with_capacity(group_ids.len());
        for group_id in group_ids {
            let dek = crypto::Dek::generate();
            let wraps = match Self::wrap_set_for_group(
                inner,
                store,
                group_id,
                &dek,
                Some(&target.endpoint_id),
            ) {
                Ok(wraps) => wraps,
                Err(err) => {
                    tracing::error!(%err, group_id, "failed to wrap rotated DEK");
                    return Response::Failed {
                        reason: "internal error".into(),
                    };
                }
            };
            rotations.push((group_id, target.endpoint_id.clone(), wraps));
            if let Ok(Some(group)) = store.group_name(group_id) {
                rotated_names.push(group);
            }
        }
        match store.remove_identity_with_rotations(name, &rotations) {
            Ok(true) => {
                // One rotate-dek row per rotated group, ahead of the
                // remove-identity row `handle` appends after dispatch.
                for group in rotated_names {
                    if let Err(err) = store.audit(&ident.endpoint_id, "rotate-dek", &group, "ok") {
                        tracing::error!(%err, "audit append failed");
                    }
                }
                Response::Ok
            }
            Ok(false) => Response::Failed {
                reason: format!("no identity named '{name}'"),
            },
            Err(err) => {
                tracing::error!(%err, name, "failed to remove identity");
                Response::Failed {
                    reason: "internal error".into(),
                }
            }
        }
    }

    fn list_identities(store: &Store, ident: &Identity) -> Response {
        if !ident.service_admin {
            return Response::Denied;
        }
        match store.list_identities() {
            Ok(ids) => Response::Identities(
                ids.into_iter()
                    .map(|i| IdentityInfo {
                        name: i.name,
                        endpoint_id: i.endpoint_id,
                        service_admin: i.service_admin,
                    })
                    .collect(),
            ),
            Err(_) => Response::Failed {
                reason: "internal error".into(),
            },
        }
    }

    fn set_service_admin(
        store: &Store,
        ident: &Identity,
        name: &str,
        service_admin: bool,
    ) -> Response {
        if !ident.service_admin {
            return Response::Denied;
        }
        match store.identity_by_name(name) {
            Ok(Some(target)) => {
                // Same lockout guard as RemoveIdentity: a bunker without a
                // service admin cannot be administered over the wire.
                if target.service_admin && !service_admin {
                    let admins = store
                        .list_identities()
                        .map(|ids| ids.iter().filter(|i| i.service_admin).count())
                        .unwrap_or(0);
                    if admins <= 1 {
                        return Response::Failed {
                            reason: "cannot revoke the last service admin".into(),
                        };
                    }
                }
                match store.set_service_admin(name, service_admin) {
                    Ok(true) => Response::Ok,
                    _ => Response::Failed {
                        reason: "internal error".into(),
                    },
                }
            }
            Ok(None) => Response::Failed {
                reason: format!("no identity named '{name}'"),
            },
            Err(_) => Response::Failed {
                reason: "internal error".into(),
            },
        }
    }

    fn grant(
        inner: &Inner,
        store: &mut Store,
        ident: &Identity,
        group: &str,
        identity: &str,
        perms: u8,
    ) -> Response {
        let Some(group_id) = Self::authorize_group(store, ident, group, PERM_ADMIN) else {
            return Response::Denied;
        };
        if perms & !(PERM_READ | PERM_WRITE | PERM_ADMIN) != 0 {
            return Response::Failed {
                reason: "invalid permission bits".into(),
            };
        }
        let target = match store.identity_by_name(identity) {
            Ok(Some(target)) => target,
            Ok(None) => {
                return Response::Failed {
                    reason: format!("no identity named '{identity}'"),
                };
            }
            Err(_) => {
                return Response::Failed {
                    reason: "internal error".into(),
                };
            }
        };
        // Refuse to leave the group without any admin: an ACL edit is
        // never urgent the way removing a compromised identity is, and an
        // admin-less group is unmanageable without local database surgery
        // (`db grant`).
        let Ok(current) = store.perms(target.id, group_id) else {
            return Response::Failed {
                reason: "internal error".into(),
            };
        };
        if current & PERM_ADMIN != 0 && perms & PERM_ADMIN == 0 {
            match store.admin_count(group_id) {
                Ok(admins) if admins <= 1 => {
                    return Response::Failed {
                        reason: format!("cannot remove the last admin of group '{group}'"),
                    };
                }
                Ok(_) => {}
                Err(_) => {
                    return Response::Failed {
                        reason: "internal error".into(),
                    };
                }
            }
        }
        match (current & PERM_READ != 0, perms & PERM_READ != 0) {
            // Gaining read: hand the grantee every retained DEK version,
            // wrapped to the recipient derived from its EndpointId.
            (false, true) => {
                let wraps = Self::wraps_for_new_reader(inner, store, group_id, &target.endpoint_id);
                let wraps = match wraps {
                    Ok(wraps) => wraps,
                    Err(err) => {
                        tracing::error!(%err, group, identity, "failed to wrap DEKs for grantee");
                        return Response::Failed {
                            reason: "internal error".into(),
                        };
                    }
                };
                match store.grant_with_wraps(
                    target.id,
                    group_id,
                    perms,
                    &wraps,
                    &target.endpoint_id,
                ) {
                    Ok(()) => Response::Ok,
                    Err(err) => {
                        tracing::error!(%err, group, identity, "failed to grant with wraps");
                        Response::Failed {
                            reason: "internal error".into(),
                        }
                    }
                }
            }
            // Losing read: drop the grantee's wraps and rotate, so the
            // DEK it already holds a copy of stops protecting anything
            // written from now on.
            (true, false) => {
                let dek = crypto::Dek::generate();
                let new_wraps = Self::wrap_set_for_group(
                    inner,
                    store,
                    group_id,
                    &dek,
                    Some(&target.endpoint_id),
                );
                let new_wraps = match new_wraps {
                    Ok(wraps) => wraps,
                    Err(err) => {
                        tracing::error!(%err, group, "failed to wrap rotated DEK");
                        return Response::Failed {
                            reason: "internal error".into(),
                        };
                    }
                };
                match store.revoke_read_and_rotate(
                    group_id,
                    target.id,
                    perms,
                    &target.endpoint_id,
                    &new_wraps,
                ) {
                    Ok(_) => {
                        // The rotation is a second, distinct event; record
                        // it as one. `handle` appends the Grant entry only
                        // once dispatch returns, so in the log the
                        // rotate-dek row sits just *before* the grant row
                        // that caused it.
                        if let Err(err) = store.audit(&ident.endpoint_id, "rotate-dek", group, "ok")
                        {
                            tracing::error!(%err, "audit append failed");
                        }
                        Response::Ok
                    }
                    Err(err) => {
                        tracing::error!(%err, group, identity, "failed to revoke and rotate");
                        Response::Failed {
                            reason: "internal error".into(),
                        }
                    }
                }
            }
            // Read unchanged: a plain ACL edit, no key material moves.
            _ => match store.set_perms(target.id, group_id, perms) {
                Ok(()) => Response::Ok,
                Err(_) => Response::Failed {
                    reason: "internal error".into(),
                },
            },
        }
    }

    fn rotate_dek(inner: &Inner, store: &mut Store, ident: &Identity, group: &str) -> Response {
        let Some(group_id) = Self::authorize_group(store, ident, group, PERM_ADMIN) else {
            return Response::Denied;
        };
        let dek = crypto::Dek::generate();
        // The new version goes to operational, backup, and every current
        // reader; nobody loses access to what they were granted.
        match Self::wrap_set_for_group(inner, store, group_id, &dek, None) {
            Ok(wraps) => match store.add_dek(group_id, &wraps) {
                Ok(_) => Response::Ok,
                Err(err) => {
                    tracing::error!(%err, group, "failed to store rotated DEK");
                    Response::Failed {
                        reason: "internal error".into(),
                    }
                }
            },
            Err(err) => {
                tracing::error!(%err, group, "failed to wrap rotated DEK");
                Response::Failed {
                    reason: "internal error".into(),
                }
            }
        }
    }
}

impl ProtocolHandler for Bunker {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id().to_string();
        tracing::debug!(remote, "connection accepted");
        // Serve requests until the peer closes the connection. Per-stream
        // errors terminate only this connection.
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => break, // peer closed (or connection error): done
            };
            let mut response = match recv.read_to_end(proto::MAX_MSG).await {
                Ok(mut bytes) => {
                    let response = self.handle_raw(&remote, &bytes);
                    bytes.zeroize(); // may hold a Put plaintext
                    response
                }
                Err(_) => break,
            };
            let mut encoded =
                proto::encode(&response).map_err(|e| std::io::Error::other(e.to_string()))?;
            // Best-effort scrub of plaintext copies once encoded/sent.
            if let Response::Secret { value, .. } = &mut response {
                value.zeroize();
            }
            let sent = send.write_all(&encoded).await;
            encoded.zeroize();
            sent.map_err(std::io::Error::other)?;
            send.finish()?;
        }
        Ok(())
    }
}

// ---- replication (`secret-bunker-sync/1`) ----

/// How long a sync session keeps draining further events after the first
/// one of a batch, before emitting the deduplicated result.
const SYNC_DEBOUNCE: Duration = Duration::from_millis(200);

/// Maximum `SecretEntry` rows per `GroupSecrets` message.
const SYNC_SECRETS_CHUNK: usize = 1000;

/// Handler for the replication ALPN, sharing the [`Bunker`]'s state. Sync
/// scope is the caller's EXPLICIT read grants only — the service-admin
/// implicit-read bypass never applies here, because sync only ever ships
/// DEK wraps addressed to the caller and implicit readers have none.
pub struct SyncServer(Arc<Inner>);

impl Clone for SyncServer {
    fn clone(&self) -> Self {
        SyncServer(self.0.clone())
    }
}

impl fmt::Debug for SyncServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncServer").finish_non_exhaustive()
    }
}

impl Bunker {
    /// The sync-ALPN handler backed by this bunker's store and event
    /// channel.
    pub fn sync_handler(&self) -> SyncServer {
        SyncServer(self.0.clone())
    }
}

impl ProtocolHandler for SyncServer {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id().to_string();
        tracing::debug!(remote, "sync connection accepted");
        // One task per stream, so a long-lived Hello session never blocks
        // the fetch streams multiplexed on the same connection. The
        // JoinSet aborts whatever still runs once the connection closes;
        // aborts land only at await points and the store lock is never
        // held across one, so an abort cannot strand the lock.
        let mut streams = tokio::task::JoinSet::new();
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => break, // peer closed (or connection error): done
            };
            let inner = self.0.clone();
            let remote = remote.clone();
            streams.spawn(async move {
                if let Err(err) = handle_sync_stream(&inner, &remote, &mut send, &mut recv).await {
                    tracing::debug!(%err, remote, "sync stream ended");
                }
                let _ = send.finish();
            });
        }
        streams.shutdown().await;
        Ok(())
    }
}

/// One request per stream: read it, dispatch. `Ok(None)` (stream closed
/// before any request) is a no-op, not an error.
async fn handle_sync_stream(
    inner: &Inner,
    remote: &str,
    send: &mut SendStream,
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<()> {
    let Some(req) = sync::read_msg::<SyncRequest>(recv).await? else {
        return Ok(());
    };
    match req {
        SyncRequest::Hello => sync_hello(inner, remote, send).await,
        SyncRequest::FetchGroup { group } => sync_fetch_group(inner, remote, &group, send).await,
        SyncRequest::FetchSecrets { group, names } => {
            sync_fetch_secrets(inner, remote, &group, &names, send).await
        }
    }
}

/// Resolve `remote` and require the EXPLICIT read bit on `group`. This is
/// sync's whole authorization: no service-admin bypass (deliberately not
/// [`Bunker::authorize_group`]), and unknown identity, unknown group, and
/// missing permission are indistinguishable (`None` → `SyncDenied`).
fn sync_read_authorized(store: &Store, remote: &str, group: &str) -> Option<i64> {
    let ident = store.identity_by_endpoint(remote).ok()??;
    let group_id = store.group_id(group).ok()??;
    let perms = store.perms(ident.id, group_id).ok()?;
    (perms & PERM_READ != 0).then_some(group_id)
}

/// One group's manifest, snapshotted under the store lock so it can be
/// sent without holding it.
struct GroupSnapshot {
    name: String,
    acl: Vec<sync::AclEntry>,
    deks: Vec<sync::DekEntry>,
    secrets: Vec<sync::SecretEntry>,
}

/// Read one group's manifest. The DEK wraps are the caller's own and
/// nothing else — sync never carries plaintext, unwrapped DEKs, or wraps
/// addressed to another recipient. A version without a wrap for the
/// caller (a revoke interleaved with this snapshot) is omitted.
fn snapshot_group(store: &Store, group_id: i64, name: &str, remote: &str) -> Result<GroupSnapshot> {
    let acl = store
        .acl_entries_full(group_id)?
        .into_iter()
        .map(|(identity_name, endpoint_id, perms)| sync::AclEntry {
            identity_name,
            endpoint_id,
            perms,
        })
        .collect();
    let mut deks = Vec::new();
    for version in store.dek_versions(group_id)? {
        if let Some(wrapped) = store.dek_wrap(group_id, version, remote)? {
            deks.push(sync::DekEntry { version, wrapped });
        }
    }
    let secrets = store
        .secret_entries(group_id)?
        .into_iter()
        .map(
            |(name, current_version, dek_version, nonce)| sync::SecretEntry {
                name,
                current_version,
                dek_version,
                nonce,
            },
        )
        .collect();
    Ok(GroupSnapshot {
        name: name.to_string(),
        acl,
        deks,
        secrets,
    })
}

/// Send one snapshot: `Group`, then the listing in `GroupSecrets` chunks.
/// Always at least one `GroupSecrets`, so a group without secrets is an
/// explicit empty listing rather than an absence.
async fn send_group_snapshot(send: &mut SendStream, snap: GroupSnapshot) -> Result<()> {
    let GroupSnapshot {
        name,
        acl,
        deks,
        secrets,
    } = snap;
    sync::write_msg(
        send,
        &SyncMessage::Group {
            name: name.clone(),
            acl,
            deks,
        },
    )
    .await?;
    let chunks: Vec<&[sync::SecretEntry]> = if secrets.is_empty() {
        vec![&[]]
    } else {
        secrets.chunks(SYNC_SECRETS_CHUNK).collect()
    };
    for chunk in chunks {
        sync::write_msg(
            send,
            &SyncMessage::GroupSecrets {
                group: name.clone(),
                secrets: chunk.to_vec(),
            },
        )
        .await?;
    }
    Ok(())
}

/// The caller's explicit-read scope as a set of group names, freshly
/// resolved from the endpoint (a removed-and-re-registered identity gets
/// a new row, so the id is never cached). Empty on unknown identity.
fn current_scope_names(inner: &Inner, remote: &str) -> BTreeSet<String> {
    let store = inner.lock_store();
    store
        .identity_by_endpoint(remote)
        .ok()
        .flatten()
        .and_then(|ident| store.read_scope(ident.id).ok())
        .map(|scope| scope.into_iter().map(|(_, name)| name).collect())
        .unwrap_or_default()
}

/// The session stream: manifest, then live push until the peer goes away.
async fn sync_hello(inner: &Inner, remote: &str, send: &mut SendStream) -> Result<()> {
    // Subscribe BEFORE the snapshot: every mutation from here on is either
    // in the snapshot or in the channel (or both — a duplicate Changed is
    // wasted work, a lost one would be a hole), never in neither.
    let mut events = inner.events.subscribe();
    let scope = {
        let store = inner.lock_store();
        let scope = store
            .identity_by_endpoint(remote)
            .ok()
            .flatten()
            .and_then(|ident| store.read_scope(ident.id).ok());
        let outcome = if scope.is_some() { "ok" } else { "denied" };
        if let Err(err) = store.audit(remote, "sync-hello", "", outcome) {
            tracing::error!(%err, "audit append failed");
        }
        scope
    };
    let Some(scope) = scope else {
        sync::write_msg(send, &SyncMessage::SyncDenied).await?;
        return Ok(());
    };
    let mut cached: BTreeSet<String> = scope.iter().map(|(_, name)| name.clone()).collect();
    for (group_id, name) in &scope {
        // One lock acquisition per group, released before every send.
        let snap = {
            let store = inner.lock_store();
            snapshot_group(&store, *group_id, name, remote)?
        };
        send_group_snapshot(send, snap).await?;
    }
    sync::write_msg(send, &SyncMessage::ManifestDone).await?;

    // Live push. Exits when the peer closes (a write fails, or the accept
    // loop tears this task down with the connection) or the Bunker drops.
    loop {
        let mut lagged = false;
        let mut batch: BTreeSet<String> = BTreeSet::new();
        match events.recv().await {
            Ok(group) => {
                batch.insert(group);
            }
            // Events were dropped: only a full scope recheck is sound.
            Err(broadcast::error::RecvError::Lagged(_)) => lagged = true,
            // Sender gone: the Bunker was dropped, nothing changes again.
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
        // Debounce: keep draining until the channel stays quiet for the
        // whole window, then emit one deduplicated batch.
        loop {
            match tokio::time::timeout(SYNC_DEBOUNCE, events.recv()).await {
                Ok(Ok(group)) => {
                    batch.insert(group);
                }
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => lagged = true,
                Ok(Err(broadcast::error::RecvError::Closed)) => break,
                Err(_) => break, // window elapsed without another event
            }
        }
        let scope = current_scope_names(inner, remote);
        if lagged || scope != cached {
            // The scope itself moved (or we cannot know): the session's
            // manifest is stale as a whole, not just single groups.
            cached = scope;
            sync::write_msg(send, &SyncMessage::ScopeChanged).await?;
        } else {
            for group in batch.intersection(&cached) {
                sync::write_msg(
                    send,
                    &SyncMessage::Changed {
                        group: group.clone(),
                    },
                )
                .await?;
            }
        }
    }
}

async fn sync_fetch_group(
    inner: &Inner,
    remote: &str,
    group: &str,
    send: &mut SendStream,
) -> Result<()> {
    let snap = {
        let store = inner.lock_store();
        let authorized = sync_read_authorized(&store, remote, group);
        let outcome = if authorized.is_some() { "ok" } else { "denied" };
        if let Err(err) = store.audit(remote, "sync-fetch-group", group, outcome) {
            tracing::error!(%err, "audit append failed");
        }
        match authorized {
            Some(group_id) => Some(snapshot_group(&store, group_id, group, remote)?),
            None => None,
        }
    };
    let Some(snap) = snap else {
        sync::write_msg(send, &SyncMessage::SyncDenied).await?;
        return Ok(());
    };
    send_group_snapshot(send, snap).await?;
    sync::write_msg(send, &SyncMessage::FetchDone).await?;
    Ok(())
}

async fn sync_fetch_secrets(
    inner: &Inner,
    remote: &str,
    group: &str,
    names: &[String],
    send: &mut SendStream,
) -> Result<()> {
    let authorized = {
        let store = inner.lock_store();
        let authorized = sync_read_authorized(&store, remote, group);
        let outcome = if authorized.is_some() { "ok" } else { "denied" };
        if let Err(err) = store.audit(remote, "sync-fetch-secrets", group, outcome) {
            tracing::error!(%err, "audit append failed");
        }
        authorized
    };
    let Some(group_id) = authorized else {
        sync::write_msg(send, &SyncMessage::SyncDenied).await?;
        return Ok(());
    };
    for name in names {
        // One lock acquisition per secret: bounded memory for arbitrarily
        // long fetch lists, and the lock is never held across a send.
        let row = {
            let store = inner.lock_store();
            store.secret_data_current(group_id, name)?
        };
        // Names that (no longer) exist are skipped silently: the peer
        // asked from a listing that may already be stale, which is
        // exactly what the push channel will tell it about.
        let Some((version, dek_version, nonce, ciphertext, created_at, created_by)) = row else {
            continue;
        };
        sync::write_msg(
            send,
            &SyncMessage::SecretData {
                name: name.clone(),
                version,
                dek_version,
                nonce,
                ciphertext,
                created_at,
                created_by,
            },
        )
        .await?;
    }
    sync::write_msg(send, &SyncMessage::FetchDone).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bunker over an in-memory store with one service admin, plus that
    /// admin's EndpointId (a real one, so AddIdentity targets parse).
    fn test_bunker() -> (Bunker, String) {
        let mut store = Store::open_in_memory().unwrap();
        let op = age::x25519::Identity::generate();
        let backup = age::x25519::Identity::generate();
        let admin_id = iroh::SecretKey::generate().public().to_string();
        store
            .init(
                &op.to_public().to_string(),
                &backup.to_public().to_string(),
                &admin_id,
                "admin",
            )
            .unwrap();
        (Bunker::new(store, op).unwrap(), admin_id)
    }

    /// Successful mutations publish the touched group name(s) on the
    /// event channel; reads, failures, and denials publish nothing.
    #[test]
    fn successful_mutations_publish_events() {
        let (bunker, admin) = test_bunker();
        let mut rx = bunker.0.events.subscribe();
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        assert_eq!(rx.try_recv().unwrap(), "g");
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Put {
                    group: "g".into(),
                    name: "s".into(),
                    value: b"v".to_vec(),
                    expected_version: 0,
                }
            ),
            Response::Version { version: 1 }
        );
        assert_eq!(rx.try_recv().unwrap(), "g");
        // Reads publish nothing.
        assert!(matches!(
            bunker.handle(
                &admin,
                &Request::Get {
                    group: "g".into(),
                    name: "s".into(),
                }
            ),
            Response::Secret { .. }
        ));
        assert!(rx.try_recv().is_err());
        // Conflicted mutations publish nothing.
        assert!(matches!(
            bunker.handle(
                &admin,
                &Request::Put {
                    group: "g".into(),
                    name: "s".into(),
                    value: b"v2".to_vec(),
                    expected_version: 7,
                }
            ),
            Response::VersionConflict { .. }
        ));
        assert!(rx.try_recv().is_err());
        // Denied mutations publish nothing.
        let stranger = iroh::SecretKey::generate().public().to_string();
        assert_eq!(
            bunker.handle(
                &stranger,
                &Request::Put {
                    group: "g".into(),
                    name: "s".into(),
                    value: b"evil".to_vec(),
                    expected_version: 1,
                }
            ),
            Response::Denied
        );
        assert!(rx.try_recv().is_err());
        // AddIdentity touches no group; Grant publishes its group.
        let bob = iroh::SecretKey::generate().public().to_string();
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::AddIdentity {
                    name: "bob".into(),
                    endpoint_id: bob,
                    service_admin: false,
                }
            ),
            Response::Ok
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Grant {
                    group: "g".into(),
                    identity: "bob".into(),
                    perms: PERM_READ,
                }
            ),
            Response::Ok
        );
        assert_eq!(rx.try_recv().unwrap(), "g");
        // RemoveIdentity publishes every group the identity had a row on.
        assert_eq!(
            bunker.handle(&admin, &Request::RemoveIdentity { name: "bob".into() }),
            Response::Ok
        );
        assert_eq!(rx.try_recv().unwrap(), "g");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn put_with_max_expected_version_is_a_conflict_not_a_panic() {
        let (bunker, admin) = test_bunker();
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Put {
                    group: "g".into(),
                    name: "s".into(),
                    value: b"v".to_vec(),
                    expected_version: 0,
                }
            ),
            Response::Version { version: 1 }
        );
        // u64::MAX + 1 must not overflow-panic (which would poison the store
        // lock); it is just an unmatchable precondition.
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Put {
                    group: "g".into(),
                    name: "s".into(),
                    value: b"v2".to_vec(),
                    expected_version: u64::MAX,
                }
            ),
            Response::VersionConflict { current: 1 }
        );
    }

    #[test]
    fn grant_cannot_drop_the_last_group_admin() {
        let (bunker, admin) = test_bunker();
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::AddIdentity {
                    name: "bob".into(),
                    endpoint_id: iroh::SecretKey::generate().public().to_string(),
                    service_admin: false,
                }
            ),
            Response::Ok
        );
        // The creator is the sole group admin: neither downgrading nor
        // revoking it may leave the group without an admin.
        for perms in [PERM_READ | PERM_WRITE, 0] {
            assert!(
                matches!(
                    bunker.handle(
                        &admin,
                        &Request::Grant {
                            group: "g".into(),
                            identity: "admin".into(),
                            perms,
                        }
                    ),
                    Response::Failed { .. }
                ),
                "dropping the last group admin (perms {perms}) must be refused"
            );
        }
        // With a second admin in place, stepping down is fine.
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Grant {
                    group: "g".into(),
                    identity: "bob".into(),
                    perms: PERM_READ | PERM_WRITE | PERM_ADMIN,
                }
            ),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Grant {
                    group: "g".into(),
                    identity: "admin".into(),
                    perms: PERM_READ,
                }
            ),
            Response::Ok
        );
    }

    #[test]
    fn group_admins_can_list_identity_names_without_service_admin() {
        let (bunker, admin) = test_bunker();
        let bob = iroh::SecretKey::generate().public().to_string();
        let carol = iroh::SecretKey::generate().public().to_string();
        for (name, endpoint_id) in [("bob", &bob), ("carol", &carol)] {
            assert_eq!(
                bunker.handle(
                    &admin,
                    &Request::AddIdentity {
                        name: name.into(),
                        endpoint_id: endpoint_id.clone(),
                        service_admin: false,
                    }
                ),
                Response::Ok
            );
        }
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        for (identity, perms) in [
            ("bob", PERM_READ | PERM_WRITE | PERM_ADMIN),
            ("carol", PERM_READ),
        ] {
            assert_eq!(
                bunker.handle(
                    &admin,
                    &Request::Grant {
                        group: "g".into(),
                        identity: identity.into(),
                        perms,
                    }
                ),
                Response::Ok
            );
        }
        // The full identity listing stays service-admin only...
        assert_eq!(
            bunker.handle(&bob, &Request::ListIdentities),
            Response::Denied
        );
        // ...but a group admin can list candidate names for granting.
        assert_eq!(
            bunker.handle(&bob, &Request::ListIdentityNames { group: "g".into() }),
            Response::IdentityNames(vec!["admin".into(), "bob".into(), "carol".into()])
        );
        // Non-admin members and unknown groups are denied.
        assert_eq!(
            bunker.handle(&carol, &Request::ListIdentityNames { group: "g".into() }),
            Response::Denied
        );
        assert_eq!(
            bunker.handle(
                &bob,
                &Request::ListIdentityNames {
                    group: "nope".into()
                }
            ),
            Response::Denied
        );
    }

    #[test]
    fn service_admins_implicitly_access_all_groups() {
        let (bunker, admin) = test_bunker();
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Put {
                    group: "g".into(),
                    name: "s".into(),
                    value: b"v".to_vec(),
                    expected_version: 0,
                }
            ),
            Response::Version { version: 1 }
        );
        // A second service admin with no explicit grant on "g" can still
        // read its secrets and manage its ACL.
        let root = iroh::SecretKey::generate().public().to_string();
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::AddIdentity {
                    name: "root".into(),
                    endpoint_id: root.clone(),
                    service_admin: true,
                }
            ),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(
                &root,
                &Request::Get {
                    group: "g".into(),
                    name: "s".into(),
                }
            ),
            Response::Secret {
                value: b"v".to_vec(),
                version: 1,
            }
        );
        assert!(matches!(
            bunker.handle(&root, &Request::GroupAcl { group: "g".into() }),
            Response::Acl(_)
        ));
        // ListGroups reports the effective (full) bitmask.
        let Response::Groups { groups, .. } = bunker.handle(&root, &Request::ListGroups) else {
            panic!("expected Groups");
        };
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].perms, PERM_READ | PERM_WRITE | PERM_ADMIN);
        // A nonexistent group is still a uniform denial, not an oracle.
        assert_eq!(
            bunker.handle(
                &root,
                &Request::Get {
                    group: "nope".into(),
                    name: "s".into(),
                }
            ),
            Response::Denied
        );
    }

    #[test]
    fn revoking_service_admin_removes_implicit_access() {
        let (bunker, admin) = test_bunker();
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Put {
                    group: "g".into(),
                    name: "s".into(),
                    value: b"v".to_vec(),
                    expected_version: 0,
                }
            ),
            Response::Version { version: 1 }
        );
        let root = iroh::SecretKey::generate().public().to_string();
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::AddIdentity {
                    name: "root".into(),
                    endpoint_id: root.clone(),
                    service_admin: true,
                }
            ),
            Response::Ok
        );
        assert!(matches!(
            bunker.handle(
                &root,
                &Request::Get {
                    group: "g".into(),
                    name: "s".into(),
                }
            ),
            Response::Secret { .. }
        ));
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::SetServiceAdmin {
                    name: "root".into(),
                    service_admin: false,
                }
            ),
            Response::Ok
        );
        // The flag is gone: no secret access, no service operations.
        assert_eq!(
            bunker.handle(
                &root,
                &Request::Get {
                    group: "g".into(),
                    name: "s".into(),
                }
            ),
            Response::Denied
        );
        assert_eq!(
            bunker.handle(&root, &Request::ListIdentities),
            Response::Denied
        );
        // And it can be granted back.
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::SetServiceAdmin {
                    name: "root".into(),
                    service_admin: true,
                }
            ),
            Response::Ok
        );
        assert!(matches!(
            bunker.handle(
                &root,
                &Request::Get {
                    group: "g".into(),
                    name: "s".into(),
                }
            ),
            Response::Secret { .. }
        ));
    }

    #[test]
    fn set_service_admin_authorization_and_guards() {
        let (bunker, admin) = test_bunker();
        let bob = iroh::SecretKey::generate().public().to_string();
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::AddIdentity {
                    name: "bob".into(),
                    endpoint_id: bob.clone(),
                    service_admin: false,
                }
            ),
            Response::Ok
        );
        // Only service admins may toggle the flag.
        assert_eq!(
            bunker.handle(
                &bob,
                &Request::SetServiceAdmin {
                    name: "bob".into(),
                    service_admin: true,
                }
            ),
            Response::Denied
        );
        // The last service admin cannot revoke itself.
        assert!(matches!(
            bunker.handle(
                &admin,
                &Request::SetServiceAdmin {
                    name: "admin".into(),
                    service_admin: false,
                }
            ),
            Response::Failed { .. }
        ));
        // Unknown identities fail informatively (caller is authorized).
        assert!(matches!(
            bunker.handle(
                &admin,
                &Request::SetServiceAdmin {
                    name: "nope".into(),
                    service_admin: true,
                }
            ),
            Response::Failed { .. }
        ));
    }

    #[test]
    fn malformed_requests_are_denied_and_audited() {
        use crate::store::AuditVerification;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("bunker.sqlite");
        let op = age::x25519::Identity::generate();
        let backup = age::x25519::Identity::generate();
        let remote = iroh::SecretKey::generate().public().to_string();
        let mut store = Store::open(&db).unwrap();
        store
            .init(
                &op.to_public().to_string(),
                &backup.to_public().to_string(),
                &remote,
                "admin",
            )
            .unwrap();
        let bunker = Bunker::new(store, op).unwrap();
        assert_eq!(
            bunker.handle_raw(&remote, b"\xffnot-cbor"),
            Response::Denied
        );
        drop(bunker);
        let verified = Store::open(&db).unwrap().verify_audit_chain().unwrap();
        assert!(
            matches!(verified, AuditVerification::Valid { entries: 1, .. }),
            "expected one audit entry for the malformed frame, got {verified:?}"
        );
    }

    /// Grant of read wraps every retained DEK version to the grantee's
    /// derived recipient; revoke deletes them and rotates.
    #[test]
    fn grant_read_wraps_and_revoke_rotates() {
        let (bunker, admin) = test_bunker();
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        // Two retained DEK versions before bob arrives.
        assert_eq!(
            bunker.handle(&admin, &Request::RotateDek { group: "g".into() }),
            Response::Ok
        );
        let bob_secret = iroh::SecretKey::generate();
        let bob = bob_secret.public().to_string();
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::AddIdentity {
                    name: "bob".into(),
                    endpoint_id: bob.clone(),
                    service_admin: false,
                }
            ),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Grant {
                    group: "g".into(),
                    identity: "bob".into(),
                    perms: crate::store::PERM_READ,
                }
            ),
            Response::Ok
        );
        // Both versions wrapped to bob, and bob's derived identity can unwrap.
        let bob_identity = crate::agebridge::identity_from_secret(&bob_secret).unwrap();
        {
            let store = bunker.lock_store();
            let gid = store.group_id("g").unwrap().unwrap();
            for v in [1u64, 2] {
                let wrapped = store
                    .dek_wrap(gid, v, &bob)
                    .unwrap()
                    .expect("wrap row exists");
                crate::crypto::unwrap_dek(&wrapped, &bob_identity).expect("bob can unwrap");
            }
            assert_eq!(store.current_dek_version(gid).unwrap(), 2);
        }
        // Revoke read: wraps deleted, DEK auto-rotated to version 3 without bob.
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Grant {
                    group: "g".into(),
                    identity: "bob".into(),
                    perms: 0,
                }
            ),
            Response::Ok
        );
        {
            let store = bunker.lock_store();
            let gid = store.group_id("g").unwrap().unwrap();
            assert_eq!(store.current_dek_version(gid).unwrap(), 3);
            for v in [1u64, 2, 3] {
                assert!(
                    store.dek_wrap(gid, v, &bob).unwrap().is_none(),
                    "v{v} wrap must be gone"
                );
            }
            assert!(
                store
                    .dek_wrap(gid, 3, RECIPIENT_OPERATIONAL)
                    .unwrap()
                    .is_some()
            );
            assert!(store.dek_wrap(gid, 3, RECIPIENT_BACKUP).unwrap().is_some());
        }
    }

    /// A write-only grant creates no wraps; upgrading to rw does.
    #[test]
    fn write_only_grant_creates_no_wraps() {
        let (bunker, admin) = test_bunker();
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        let bob_secret = iroh::SecretKey::generate();
        let bob = bob_secret.public().to_string();
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::AddIdentity {
                    name: "bob".into(),
                    endpoint_id: bob.clone(),
                    service_admin: false,
                }
            ),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Grant {
                    group: "g".into(),
                    identity: "bob".into(),
                    perms: PERM_WRITE,
                }
            ),
            Response::Ok
        );
        {
            let store = bunker.lock_store();
            let gid = store.group_id("g").unwrap().unwrap();
            assert!(
                store.dek_wrap(gid, 1, &bob).unwrap().is_none(),
                "a write-only grantee must not be wrapped to"
            );
            // No rotation either: a write grant does not touch the DEK.
            assert_eq!(store.current_dek_version(gid).unwrap(), 1);
        }
        // Upgrading to rw wraps the retained version.
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Grant {
                    group: "g".into(),
                    identity: "bob".into(),
                    perms: PERM_READ | PERM_WRITE,
                }
            ),
            Response::Ok
        );
        {
            let store = bunker.lock_store();
            let gid = store.group_id("g").unwrap().unwrap();
            let wrapped = store
                .dek_wrap(gid, 1, &bob)
                .unwrap()
                .expect("wrap row exists after gaining read");
            let bob_identity = crate::agebridge::identity_from_secret(&bob_secret).unwrap();
            crate::crypto::unwrap_dek(&wrapped, &bob_identity).expect("bob can unwrap");
            assert_eq!(
                store.current_dek_version(gid).unwrap(),
                1,
                "gaining read wraps the existing DEK, it does not rotate"
            );
        }
    }

    /// RemoveIdentity rotates every group the identity could read, atomically.
    #[test]
    fn remove_identity_rotates_all_readable_groups() {
        let (bunker, admin) = test_bunker();
        for group in ["g1", "g2"] {
            assert_eq!(
                bunker.handle(&admin, &Request::CreateGroup { name: group.into() }),
                Response::Ok
            );
        }
        let bob = iroh::SecretKey::generate().public().to_string();
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::AddIdentity {
                    name: "bob".into(),
                    endpoint_id: bob.clone(),
                    service_admin: false,
                }
            ),
            Response::Ok
        );
        for group in ["g1", "g2"] {
            assert_eq!(
                bunker.handle(
                    &admin,
                    &Request::Grant {
                        group: group.into(),
                        identity: "bob".into(),
                        perms: PERM_READ,
                    }
                ),
                Response::Ok
            );
        }
        {
            let store = bunker.lock_store();
            for group in ["g1", "g2"] {
                let gid = store.group_id(group).unwrap().unwrap();
                assert!(store.dek_wrap(gid, 1, &bob).unwrap().is_some());
                assert_eq!(store.current_dek_version(gid).unwrap(), 1);
            }
        }
        assert_eq!(
            bunker.handle(&admin, &Request::RemoveIdentity { name: "bob".into() }),
            Response::Ok
        );
        {
            let store = bunker.lock_store();
            assert!(store.identity_by_name("bob").unwrap().is_none());
            for group in ["g1", "g2"] {
                let gid = store.group_id(group).unwrap().unwrap();
                assert_eq!(
                    store.current_dek_version(gid).unwrap(),
                    2,
                    "{group} must be rotated away from the removed identity"
                );
                for v in [1u64, 2] {
                    assert!(
                        store.dek_wrap(gid, v, &bob).unwrap().is_none(),
                        "{group} v{v} wrap must be gone"
                    );
                }
                assert!(
                    store
                        .dek_wrap(gid, 2, RECIPIENT_OPERATIONAL)
                        .unwrap()
                        .is_some()
                );
                assert!(store.dek_wrap(gid, 2, RECIPIENT_BACKUP).unwrap().is_some());
                assert!(
                    store.dek_wrap(gid, 2, &admin).unwrap().is_some(),
                    "the remaining reader keeps access to {group}"
                );
            }
        }
    }

    /// CreateGroup wraps to operational + backup + creator.
    #[test]
    fn create_group_wraps_to_creator() {
        let (bunker, admin) = test_bunker();
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        let store = bunker.lock_store();
        let gid = store.group_id("g").unwrap().unwrap();
        assert!(store.dek_wrap(gid, 1, &admin).unwrap().is_some());
        assert!(
            store
                .dek_wrap(gid, 1, RECIPIENT_OPERATIONAL)
                .unwrap()
                .is_some()
        );
        assert!(store.dek_wrap(gid, 1, RECIPIENT_BACKUP).unwrap().is_some());
    }

    /// Manual RotateDek wraps the new version to every current reader.
    #[test]
    fn rotate_dek_wraps_to_readers() {
        let (bunker, admin) = test_bunker();
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        let bob_secret = iroh::SecretKey::generate();
        let bob = bob_secret.public().to_string();
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::AddIdentity {
                    name: "bob".into(),
                    endpoint_id: bob.clone(),
                    service_admin: false,
                }
            ),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Grant {
                    group: "g".into(),
                    identity: "bob".into(),
                    perms: PERM_READ,
                }
            ),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(&admin, &Request::RotateDek { group: "g".into() }),
            Response::Ok
        );
        let store = bunker.lock_store();
        let gid = store.group_id("g").unwrap().unwrap();
        assert_eq!(store.current_dek_version(gid).unwrap(), 2);
        let wrapped = store
            .dek_wrap(gid, 2, &bob)
            .unwrap()
            .expect("the new version is wrapped to the reader");
        let bob_identity = crate::agebridge::identity_from_secret(&bob_secret).unwrap();
        crate::crypto::unwrap_dek(&wrapped, &bob_identity).expect("bob can unwrap v2");
        assert!(
            store
                .dek_wrap(gid, 2, RECIPIENT_OPERATIONAL)
                .unwrap()
                .is_some()
        );
        assert!(store.dek_wrap(gid, 2, RECIPIENT_BACKUP).unwrap().is_some());
        assert!(
            store.dek_wrap(gid, 2, &admin).unwrap().is_some(),
            "the creator is a reader too"
        );
    }

    /// Backfill creates missing reader wraps idempotently.
    #[test]
    fn backfill_creates_missing_wraps() {
        let (bunker, admin) = test_bunker();
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        // Simulate a pre-redesign grant: an ACL row without wraps. The
        // creator (admin) already has wraps, so only carol is missing.
        let carol = iroh::SecretKey::generate().public().to_string();
        {
            let store = bunker.lock_store();
            let gid = store.group_id("g").unwrap().unwrap();
            store.add_identity("carol", &carol, false).unwrap();
            let carol_id = store.identity_by_name("carol").unwrap().unwrap();
            store.set_perms(carol_id.id, gid, PERM_READ).unwrap();
            assert!(store.dek_wrap(gid, 1, &carol).unwrap().is_none());
        }
        let n = bunker.backfill_reader_wraps().unwrap();
        assert_eq!(n, 1);
        assert_eq!(bunker.backfill_reader_wraps().unwrap(), 0, "idempotent");
        let store = bunker.lock_store();
        let gid = store.group_id("g").unwrap().unwrap();
        assert!(store.dek_wrap(gid, 1, &carol).unwrap().is_some());
    }

    #[test]
    fn removing_an_identity_is_never_blocked_by_group_admin_status() {
        // Revocation of a (possibly compromised) identity always wins over
        // lockout protection; the recovery path is `db grant` on the server.
        let (bunker, admin) = test_bunker();
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::AddIdentity {
                    name: "bob".into(),
                    endpoint_id: iroh::SecretKey::generate().public().to_string(),
                    service_admin: false,
                }
            ),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Grant {
                    group: "g".into(),
                    identity: "bob".into(),
                    perms: PERM_READ | PERM_WRITE | PERM_ADMIN,
                }
            ),
            Response::Ok
        );
        // Admin steps down; bob is now the sole group admin.
        assert_eq!(
            bunker.handle(
                &admin,
                &Request::Grant {
                    group: "g".into(),
                    identity: "admin".into(),
                    perms: 0,
                }
            ),
            Response::Ok
        );
        assert_eq!(
            bunker.handle(&admin, &Request::RemoveIdentity { name: "bob".into() }),
            Response::Ok,
            "removing a sole group admin identity must stay possible"
        );
    }
}
