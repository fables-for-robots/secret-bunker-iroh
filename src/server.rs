//! The bunker protocol handler.
//!
//! Authentication is the iroh handshake: `Connection::remote_id()` is the
//! cryptographically verified EndpointId of the peer. Anyone may connect;
//! authorization happens per request against the ACL, and unknown identity,
//! missing permission, and nonexistent target are indistinguishable
//! (`Response::Denied`). See design/crypto-design.md sections 5 and 7.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use anyhow::Result;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use zeroize::Zeroize;

use crate::crypto;
use crate::proto::{self, IdentityInfo, Request, Response};
use crate::store::{CasOutcome, Identity, PERM_ADMIN, PERM_READ, PERM_WRITE, Store};

pub struct Bunker(Arc<Inner>);

struct Inner {
    store: Mutex<Store>,
    op_identity: age::x25519::Identity,
    op_recipient: age::x25519::Recipient,
    backup_recipient: age::x25519::Recipient,
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
        })))
    }

    /// Lock the store, recovering from poisoning: a panicked request must
    /// not brick every later one, and SQLite transactions roll back when
    /// dropped mid-panic, so the store itself stays consistent.
    fn lock_store(&self) -> MutexGuard<'_, Store> {
        self.0.store.lock().unwrap_or_else(PoisonError::into_inner)
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
        outcome
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
            Request::RemoveIdentity { name } => Self::remove_identity(store, &ident, name),
            Request::ListIdentities => Self::list_identities(store, &ident),
            Request::Grant {
                group,
                identity,
                perms,
            } => Self::grant(store, &ident, group, identity, *perms),
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
        let wrapped = store.dek(group_id, version)?;
        crypto::unwrap_dek(&wrapped.wrapped_operational, &inner.op_identity)
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
        let Ok(wrapped) = store.current_dek(group_id) else {
            return Response::Failed {
                reason: "internal error".into(),
            };
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
        let encrypted = crypto::unwrap_dek(&wrapped.wrapped_operational, &inner.op_identity)
            .map_err(|e| anyhow::anyhow!(e))
            .and_then(|dek| {
                let aad = crypto::secret_aad(group, name, target_version, wrapped.version);
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
            wrapped.version,
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
        let wrapped = crypto::wrap_dek(&dek, &inner.op_recipient)
            .and_then(|op| crypto::wrap_dek(&dek, &inner.backup_recipient).map(|bk| (op, bk)));
        let (wrapped_op, wrapped_backup) = match wrapped {
            Ok(pair) => pair,
            Err(err) => {
                tracing::error!(%err, name, "failed to wrap group DEK");
                return Response::Failed {
                    reason: "internal error".into(),
                };
            }
        };
        // Every group needs a group admin from the start: the creator,
        // granted in the same transaction that creates the group.
        if let Err(err) = store.create_group(
            name,
            &wrapped_op,
            &wrapped_backup,
            ident.id,
            PERM_READ | PERM_WRITE | PERM_ADMIN,
        ) {
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

    fn remove_identity(store: &Store, ident: &Identity, name: &str) -> Response {
        if !ident.service_admin {
            return Response::Denied;
        }
        match store.identity_by_name(name) {
            Ok(Some(target)) => {
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
                match store.remove_identity(name) {
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

    fn grant(store: &Store, ident: &Identity, group: &str, identity: &str, perms: u8) -> Response {
        let Some(group_id) = Self::authorize_group(store, ident, group, PERM_ADMIN) else {
            return Response::Denied;
        };
        if perms & !(PERM_READ | PERM_WRITE | PERM_ADMIN) != 0 {
            return Response::Failed {
                reason: "invalid permission bits".into(),
            };
        }
        match store.identity_by_name(identity) {
            Ok(Some(target)) => {
                // Refuse to leave the group without any admin: an ACL edit
                // is never urgent the way removing a compromised identity
                // is, and an admin-less group is unmanageable without local
                // database surgery (`db grant`).
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
                match store.set_perms(target.id, group_id, perms) {
                    Ok(()) => Response::Ok,
                    Err(_) => Response::Failed {
                        reason: "internal error".into(),
                    },
                }
            }
            Ok(None) => Response::Failed {
                reason: format!("no identity named '{identity}'"),
            },
            Err(_) => Response::Failed {
                reason: "internal error".into(),
            },
        }
    }

    fn rotate_dek(inner: &Inner, store: &mut Store, ident: &Identity, group: &str) -> Response {
        let Some(group_id) = Self::authorize_group(store, ident, group, PERM_ADMIN) else {
            return Response::Denied;
        };
        let dek = crypto::Dek::generate();
        let wrapped = crypto::wrap_dek(&dek, &inner.op_recipient)
            .and_then(|op| crypto::wrap_dek(&dek, &inner.backup_recipient).map(|bk| (op, bk)));
        match wrapped {
            Ok((op, bk)) => match store.add_dek(group_id, &op, &bk) {
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
