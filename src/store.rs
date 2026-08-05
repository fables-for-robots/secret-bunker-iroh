//! SQLite persistence: identities, groups, ACLs, wrapped DEKs, secret
//! versions, and the hash-chained audit log.
//!
//! The store holds only public key material, ciphertext, and wrapped DEKs.
//! See design/crypto-design.md section 4.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

pub const PERM_READ: u8 = 1;
pub const PERM_WRITE: u8 = 2;
pub const PERM_ADMIN: u8 = 4;

#[derive(Debug, Clone)]
pub struct Identity {
    pub id: i64,
    pub endpoint_id: String,
    pub name: String,
    pub service_admin: bool,
}

#[derive(Debug, Clone)]
pub struct WrappedDek {
    pub version: u64,
    pub wrapped_operational: Vec<u8>,
    pub wrapped_backup: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SecretVersion {
    pub version: u64,
    pub dek_version: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct Store {
    conn: Connection,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identity (
  id            INTEGER PRIMARY KEY,
  endpoint_id   TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL UNIQUE,
  service_admin INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS secret_group (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_acl (
  identity_id INTEGER NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  group_id    INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
  perms       INTEGER NOT NULL,
  PRIMARY KEY (identity_id, group_id)
);
CREATE TABLE IF NOT EXISTS group_dek (
  group_id            INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
  version             INTEGER NOT NULL,
  wrapped_operational BLOB NOT NULL,
  wrapped_backup      BLOB NOT NULL,
  created_at          INTEGER NOT NULL,
  PRIMARY KEY (group_id, version)
);
CREATE TABLE IF NOT EXISTS secret (
  id              INTEGER PRIMARY KEY,
  group_id        INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  current_version INTEGER NOT NULL,
  UNIQUE (group_id, name)
);
CREATE TABLE IF NOT EXISTS secret_version (
  secret_id   INTEGER NOT NULL REFERENCES secret(id) ON DELETE CASCADE,
  version     INTEGER NOT NULL,
  dek_version INTEGER NOT NULL,
  nonce       BLOB NOT NULL,
  ciphertext  BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  created_by  TEXT NOT NULL,
  PRIMARY KEY (secret_id, version)
);
CREATE TABLE IF NOT EXISTS audit_log (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  endpoint_id TEXT NOT NULL,
  op          TEXT NOT NULL,
  target      TEXT NOT NULL,
  outcome     TEXT NOT NULL,
  prev_hash   BLOB NOT NULL,
  hash        BLOB NOT NULL
);
"#;

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn })
    }

    // ---- initialization ----

    pub fn is_initialized(&self) -> Result<bool> {
        Ok(self.meta_get("operational_pubkey")?.is_some())
    }

    pub fn init(
        &mut self,
        operational_pubkey: &str,
        backup_pubkey: &str,
        admin_endpoint_id: &str,
        admin_name: &str,
    ) -> Result<()> {
        anyhow::ensure!(!self.is_initialized()?, "database is already initialized");
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('operational_pubkey', ?1), ('backup_pubkey', ?2), ('schema_version', '1')",
            params![operational_pubkey, backup_pubkey],
        )?;
        tx.execute(
            "INSERT INTO identity (endpoint_id, name, service_admin, created_at) VALUES (?1, ?2, 1, ?3)",
            params![admin_endpoint_id, admin_name, now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = ?2",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    // ---- identities ----

    pub fn identity_by_endpoint(&self, endpoint_id: &str) -> Result<Option<Identity>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, endpoint_id, name, service_admin FROM identity WHERE endpoint_id = ?1",
                [endpoint_id],
                |r| {
                    Ok(Identity {
                        id: r.get(0)?,
                        endpoint_id: r.get(1)?,
                        name: r.get(2)?,
                        service_admin: r.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()?)
    }

    pub fn identity_by_name(&self, name: &str) -> Result<Option<Identity>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, endpoint_id, name, service_admin FROM identity WHERE name = ?1",
                [name],
                |r| {
                    Ok(Identity {
                        id: r.get(0)?,
                        endpoint_id: r.get(1)?,
                        name: r.get(2)?,
                        service_admin: r.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()?)
    }

    pub fn add_identity(&self, name: &str, endpoint_id: &str, service_admin: bool) -> Result<()> {
        self.conn.execute(
            "INSERT INTO identity (endpoint_id, name, service_admin, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![endpoint_id, name, service_admin as i64, now()],
        )?;
        Ok(())
    }

    pub fn remove_identity(&self, name: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM identity WHERE name = ?1", [name])?;
        Ok(n > 0)
    }

    pub fn list_identities(&self) -> Result<Vec<Identity>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, endpoint_id, name, service_admin FROM identity ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok(Identity {
                id: r.get(0)?,
                endpoint_id: r.get(1)?,
                name: r.get(2)?,
                service_admin: r.get::<_, i64>(3)? != 0,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    // ---- groups, ACLs, DEKs ----

    pub fn group_id(&self, name: &str) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row("SELECT id FROM secret_group WHERE name = ?1", [name], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Creates a group along with its first wrapped DEK (version 1).
    pub fn create_group(
        &mut self,
        name: &str,
        wrapped_op: &[u8],
        wrapped_backup: &[u8],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO secret_group (name, created_at) VALUES (?1, ?2)",
            params![name, now()],
        )?;
        let group_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO group_dek (group_id, version, wrapped_operational, wrapped_backup, created_at) VALUES (?1, 1, ?2, ?3, ?4)",
            params![group_id, wrapped_op, wrapped_backup, now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Permission bitmask for an identity on a group; 0 when no ACL row.
    pub fn perms(&self, identity_id: i64, group_id: i64) -> Result<u8> {
        let perms: Option<i64> = self
            .conn
            .query_row(
                "SELECT perms FROM group_acl WHERE identity_id = ?1 AND group_id = ?2",
                [identity_id, group_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(perms.unwrap_or(0) as u8)
    }

    pub fn set_perms(&self, identity_id: i64, group_id: i64, perms: u8) -> Result<()> {
        if perms == 0 {
            self.conn.execute(
                "DELETE FROM group_acl WHERE identity_id = ?1 AND group_id = ?2",
                [identity_id, group_id],
            )?;
        } else {
            self.conn.execute(
                "INSERT INTO group_acl (identity_id, group_id, perms) VALUES (?1, ?2, ?3)
                 ON CONFLICT (identity_id, group_id) DO UPDATE SET perms = ?3",
                params![identity_id, group_id, perms as i64],
            )?;
        }
        Ok(())
    }

    pub fn current_dek(&self, group_id: i64) -> Result<WrappedDek> {
        Ok(self.conn.query_row(
            "SELECT version, wrapped_operational, wrapped_backup FROM group_dek
             WHERE group_id = ?1 ORDER BY version DESC LIMIT 1",
            [group_id],
            |r| {
                Ok(WrappedDek {
                    version: r.get::<_, i64>(0)? as u64,
                    wrapped_operational: r.get(1)?,
                    wrapped_backup: r.get(2)?,
                })
            },
        )?)
    }

    pub fn dek(&self, group_id: i64, version: u64) -> Result<WrappedDek> {
        Ok(self.conn.query_row(
            "SELECT version, wrapped_operational, wrapped_backup FROM group_dek
             WHERE group_id = ?1 AND version = ?2",
            params![group_id, version as i64],
            |r| {
                Ok(WrappedDek {
                    version: r.get::<_, i64>(0)? as u64,
                    wrapped_operational: r.get(1)?,
                    wrapped_backup: r.get(2)?,
                })
            },
        )?)
    }

    pub fn add_dek(&self, group_id: i64, wrapped_op: &[u8], wrapped_backup: &[u8]) -> Result<u64> {
        let next: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM group_dek WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )?;
        self.conn.execute(
            "INSERT INTO group_dek (group_id, version, wrapped_operational, wrapped_backup, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![group_id, next, wrapped_op, wrapped_backup, now()],
        )?;
        Ok(next as u64)
    }

    /// All wrapped DEKs across all groups, for offline recovery re-wrapping.
    pub fn all_deks(&self) -> Result<Vec<(i64, WrappedDek)>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, version, wrapped_operational, wrapped_backup FROM group_dek",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                WrappedDek {
                    version: r.get::<_, i64>(1)? as u64,
                    wrapped_operational: r.get(2)?,
                    wrapped_backup: r.get(3)?,
                },
            ))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn replace_wrapped_operational(
        &self,
        group_id: i64,
        version: u64,
        wrapped_op: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE group_dek SET wrapped_operational = ?3 WHERE group_id = ?1 AND version = ?2",
            params![group_id, version as i64, wrapped_op],
        )?;
        Ok(())
    }

    // ---- secrets ----

    pub fn secret_current(&self, group_id: i64, name: &str) -> Result<Option<SecretVersion>> {
        Ok(self
            .conn
            .query_row(
                "SELECT sv.version, sv.dek_version, sv.nonce, sv.ciphertext
                 FROM secret s JOIN secret_version sv
                   ON sv.secret_id = s.id AND sv.version = s.current_version
                 WHERE s.group_id = ?1 AND s.name = ?2",
                params![group_id, name],
                |r| {
                    Ok(SecretVersion {
                        version: r.get::<_, i64>(0)? as u64,
                        dek_version: r.get::<_, i64>(1)? as u64,
                        nonce: r.get(2)?,
                        ciphertext: r.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn secret_version(&self, group_id: i64, name: &str) -> Result<Option<u64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT current_version FROM secret WHERE group_id = ?1 AND name = ?2",
                params![group_id, name],
                |r| r.get::<_, i64>(0).map(|v| v as u64),
            )
            .optional()?)
    }

    /// Compare-and-set write. `expected_version` 0 means "must not exist".
    /// Returns Ok(new_version) or Err(CasConflict{current}) via the enum below.
    #[allow(clippy::too_many_arguments)] // mirrors the secret_version row
    pub fn put_secret(
        &mut self,
        group_id: i64,
        name: &str,
        expected_version: u64,
        dek_version: u64,
        nonce: &[u8],
        ciphertext: &[u8],
        created_by: &str,
    ) -> Result<CasOutcome> {
        let tx = self.conn.transaction()?;
        let existing: Option<(i64, i64)> = tx
            .query_row(
                "SELECT id, current_version FROM secret WHERE group_id = ?1 AND name = ?2",
                params![group_id, name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (secret_id, current) = match existing {
            Some((id, v)) => (id, v as u64),
            None => {
                if expected_version != 0 {
                    return Ok(CasOutcome::Conflict { current: 0 });
                }
                tx.execute(
                    "INSERT INTO secret (group_id, name, current_version) VALUES (?1, ?2, 0)",
                    params![group_id, name],
                )?;
                (tx.last_insert_rowid(), 0)
            }
        };
        if current != expected_version {
            return Ok(CasOutcome::Conflict { current });
        }
        let new_version = current + 1;
        tx.execute(
            "INSERT INTO secret_version (secret_id, version, dek_version, nonce, ciphertext, created_at, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![secret_id, new_version as i64, dek_version as i64, nonce, ciphertext, now(), created_by],
        )?;
        tx.execute(
            "UPDATE secret SET current_version = ?2 WHERE id = ?1",
            params![secret_id, new_version as i64],
        )?;
        tx.commit()?;
        Ok(CasOutcome::Applied { new_version })
    }

    /// Compare-and-set delete: removes the secret and all its versions.
    pub fn delete_secret(
        &mut self,
        group_id: i64,
        name: &str,
        expected_version: u64,
    ) -> Result<CasOutcome> {
        let tx = self.conn.transaction()?;
        let existing: Option<(i64, i64)> = tx
            .query_row(
                "SELECT id, current_version FROM secret WHERE group_id = ?1 AND name = ?2",
                params![group_id, name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((secret_id, current)) = existing else {
            return Ok(CasOutcome::Conflict { current: 0 });
        };
        if current as u64 != expected_version {
            return Ok(CasOutcome::Conflict {
                current: current as u64,
            });
        }
        tx.execute("DELETE FROM secret WHERE id = ?1", [secret_id])?;
        tx.commit()?;
        Ok(CasOutcome::Applied { new_version: 0 })
    }

    pub fn list_secrets(&self, group_id: i64) -> Result<Vec<(String, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, current_version FROM secret WHERE group_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map([group_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    // ---- audit log ----

    /// Append an entry to the hash-chained audit log.
    /// hash = SHA-256(prev_hash || ts || endpoint_id || op || target || outcome)
    /// with length-prefixed fields.
    pub fn audit(&self, endpoint_id: &str, op: &str, target: &str, outcome: &str) -> Result<()> {
        let ts = now();
        let prev: Vec<u8> = self
            .conn
            .query_row(
                "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| vec![0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(&prev);
        hasher.update(ts.to_be_bytes());
        for field in [endpoint_id, op, target, outcome] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        let hash = hasher.finalize();
        self.conn.execute(
            "INSERT INTO audit_log (ts, endpoint_id, op, target, outcome, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![ts, endpoint_id, op, target, outcome, prev, hash.as_slice()],
        )?;
        Ok(())
    }

    pub fn verify_audit_chain(&self) -> Result<bool> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, endpoint_id, op, target, outcome, prev_hash, hash FROM audit_log ORDER BY seq",
        )?;
        type AuditRow = (i64, String, String, String, String, Vec<u8>, Vec<u8>);
        let rows: Vec<AuditRow> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .collect::<std::result::Result<_, _>>()?;
        let mut prev = vec![0u8; 32];
        for (ts, endpoint_id, op, target, outcome, prev_hash, hash) in rows {
            if prev_hash != prev {
                return Ok(false);
            }
            let mut hasher = Sha256::new();
            hasher.update(&prev);
            hasher.update(ts.to_be_bytes());
            for field in [&endpoint_id, &op, &target, &outcome] {
                hasher.update((field.len() as u64).to_be_bytes());
                hasher.update(field.as_bytes());
            }
            if hasher.finalize().as_slice() != hash {
                return Ok(false);
            }
            prev = hash;
        }
        Ok(true)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CasOutcome {
    Applied { new_version: u64 },
    Conflict { current: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        let mut s = Store::open_in_memory().unwrap();
        s.init("age1op", "age1backup", "endpoint-admin", "admin")
            .unwrap();
        s
    }

    #[test]
    fn init_is_one_shot() {
        let mut s = store();
        assert!(s.is_initialized().unwrap());
        assert!(s.init("x", "y", "z", "w").is_err());
    }

    #[test]
    fn unknown_endpoint_has_no_identity_and_no_perms() {
        let mut s = store();
        assert!(s.identity_by_endpoint("stranger").unwrap().is_none());
        s.create_group("g", b"op", b"bk").unwrap();
        let gid = s.group_id("g").unwrap().unwrap();
        let admin = s.identity_by_endpoint("endpoint-admin").unwrap().unwrap();
        // Even the service admin has no per-group perms until granted.
        assert_eq!(s.perms(admin.id, gid).unwrap(), 0);
    }

    #[test]
    fn acl_grant_and_revoke() {
        let mut s = store();
        s.add_identity("alice", "endpoint-alice", false).unwrap();
        s.create_group("g", b"op", b"bk").unwrap();
        let gid = s.group_id("g").unwrap().unwrap();
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        s.set_perms(alice.id, gid, PERM_READ | PERM_WRITE).unwrap();
        assert_eq!(s.perms(alice.id, gid).unwrap(), PERM_READ | PERM_WRITE);
        s.set_perms(alice.id, gid, 0).unwrap();
        assert_eq!(s.perms(alice.id, gid).unwrap(), 0);
    }

    #[test]
    fn removing_identity_cascades_acl() {
        let mut s = store();
        s.add_identity("alice", "endpoint-alice", false).unwrap();
        s.create_group("g", b"op", b"bk").unwrap();
        let gid = s.group_id("g").unwrap().unwrap();
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        s.set_perms(alice.id, gid, PERM_READ).unwrap();
        assert!(s.remove_identity("alice").unwrap());
        assert!(s.identity_by_endpoint("endpoint-alice").unwrap().is_none());
    }

    #[test]
    fn put_secret_cas() {
        let mut s = store();
        s.create_group("g", b"op", b"bk").unwrap();
        let gid = s.group_id("g").unwrap().unwrap();
        // Create requires expected_version 0.
        assert_eq!(
            s.put_secret(gid, "tok", 0, 1, b"n", b"ct", "admin")
                .unwrap(),
            CasOutcome::Applied { new_version: 1 }
        );
        // Re-create fails.
        assert_eq!(
            s.put_secret(gid, "tok", 0, 1, b"n", b"ct2", "admin")
                .unwrap(),
            CasOutcome::Conflict { current: 1 }
        );
        // Update with right version succeeds.
        assert_eq!(
            s.put_secret(gid, "tok", 1, 1, b"n", b"ct2", "admin")
                .unwrap(),
            CasOutcome::Applied { new_version: 2 }
        );
        // Stale update fails.
        assert_eq!(
            s.put_secret(gid, "tok", 1, 1, b"n", b"ct3", "admin")
                .unwrap(),
            CasOutcome::Conflict { current: 2 }
        );
        let cur = s.secret_current(gid, "tok").unwrap().unwrap();
        assert_eq!(cur.version, 2);
        assert_eq!(cur.ciphertext, b"ct2");
    }

    #[test]
    fn delete_secret_cas() {
        let mut s = store();
        s.create_group("g", b"op", b"bk").unwrap();
        let gid = s.group_id("g").unwrap().unwrap();
        s.put_secret(gid, "tok", 0, 1, b"n", b"ct", "admin")
            .unwrap();
        assert_eq!(
            s.delete_secret(gid, "tok", 2).unwrap(),
            CasOutcome::Conflict { current: 1 }
        );
        assert_eq!(
            s.delete_secret(gid, "tok", 1).unwrap(),
            CasOutcome::Applied { new_version: 0 }
        );
        assert!(s.secret_current(gid, "tok").unwrap().is_none());
    }

    #[test]
    fn dek_versioning() {
        let mut s = store();
        s.create_group("g", b"op1", b"bk1").unwrap();
        let gid = s.group_id("g").unwrap().unwrap();
        assert_eq!(s.current_dek(gid).unwrap().version, 1);
        let v = s.add_dek(gid, b"op2", b"bk2").unwrap();
        assert_eq!(v, 2);
        assert_eq!(s.current_dek(gid).unwrap().version, 2);
        // Old DEK still retrievable for historical versions.
        assert_eq!(s.dek(gid, 1).unwrap().wrapped_operational, b"op1");
    }

    #[test]
    fn audit_chain_verifies_and_detects_tampering() {
        let s = store();
        s.audit("endpoint-a", "get", "g/tok", "ok").unwrap();
        s.audit("endpoint-b", "put", "g/tok", "denied").unwrap();
        assert!(s.verify_audit_chain().unwrap());
        s.conn
            .execute(
                "UPDATE audit_log SET outcome = 'ok' WHERE outcome = 'denied'",
                [],
            )
            .unwrap();
        assert!(!s.verify_audit_chain().unwrap());
    }
}
