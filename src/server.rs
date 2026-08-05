//! The bunker protocol handler.
//!
//! Authentication is the iroh handshake: `Connection::remote_id()` is the
//! cryptographically verified EndpointId of the peer. Anyone may connect;
//! authorization happens per request against the ACL, and unknown identity,
//! missing permission, and nonexistent target are indistinguishable
//! (`Response::Denied`). See design/crypto-design.md sections 5 and 7.

use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};

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

    /// Handle one decoded request from an authenticated peer. Synchronous:
    /// the store lock is never held across an await point.
    pub fn handle(&self, remote: &str, req: &Request) -> Response {
        let inner = &*self.0;
        let mut store = inner.store.lock().expect("store lock poisoned");
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
                    .map(|(name, perms)| crate::proto::GroupInfo { name, perms })
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

    /// Resolve a group and check that `ident` holds all bits in `needed`.
    fn authorize_group(store: &Store, ident: &Identity, group: &str, needed: u8) -> Option<i64> {
        let group_id = store.group_id(group).ok()??;
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
        // CAS succeeds (expected_version == current).
        if expected_version + 1 != new_version && expected_version != 0 {
            // Fast-path conflict; the store would reject it anyway.
            return Response::VersionConflict {
                current: new_version - 1,
            };
        }
        let encrypted = crypto::unwrap_dek(&wrapped.wrapped_operational, &inner.op_identity)
            .map_err(|e| anyhow::anyhow!(e))
            .and_then(|dek| {
                let aad = crypto::secret_aad(group, name, expected_version + 1, wrapped.version);
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
        if let Err(err) = store.create_group(name, &wrapped_op, &wrapped_backup) {
            tracing::error!(%err, name, "failed to create group");
            return Response::Failed {
                reason: "internal error".into(),
            };
        }
        // Every group needs a group admin from the start: the creator.
        let grant = store
            .group_id(name)
            .ok()
            .flatten()
            .map(|gid| store.set_perms(ident.id, gid, PERM_READ | PERM_WRITE | PERM_ADMIN));
        if !matches!(grant, Some(Ok(()))) {
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
            Ok(Some(target)) => match store.set_perms(target.id, group_id, perms) {
                Ok(()) => Response::Ok,
                Err(_) => Response::Failed {
                    reason: "internal error".into(),
                },
            },
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
            let response = match recv.read_to_end(proto::MAX_MSG).await {
                Ok(bytes) => match proto::decode::<Request>(&bytes) {
                    Ok(req) => self.handle(&remote, &req),
                    Err(_) => Response::Denied,
                },
                Err(_) => break,
            };
            let encoded =
                proto::encode(&response).map_err(|e| std::io::Error::other(e.to_string()))?;
            send.write_all(&encoded)
                .await
                .map_err(std::io::Error::other)?;
            send.finish()?;
        }
        Ok(())
    }
}
