//! SQLite persistence: identities, groups, ACLs, wrapped DEKs, secret
//! versions, and the hash-chained audit log.
//!
//! The store holds only public key material, ciphertext, and wrapped DEKs.
//! See design/crypto-design.md section 4.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::sync::{AclEntry, FetchedSecret, GroupSyncState};

pub const PERM_READ: u8 = 1;
pub const PERM_WRITE: u8 = 2;
pub const PERM_ADMIN: u8 = 4;

/// Well-known `dek_wrap.recipient` values. Reader identities use their
/// lowercase-hex EndpointId (as stored in `identity.endpoint_id`) instead.
pub const RECIPIENT_OPERATIONAL: &str = "operational";
pub const RECIPIENT_BACKUP: &str = "backup";

#[derive(Debug, Clone)]
pub struct Identity {
    pub id: i64,
    pub endpoint_id: String,
    pub name: String,
    pub service_admin: bool,
}

/// One group's share of an identity removal: the group to rotate, the
/// `dek_wrap.recipient` whose rows go away, and the full wrap set of the
/// DEK version that replaces the old one.
pub type GroupRotation = (i64, String, Vec<(String, Vec<u8>)>);

/// One row of a group's sync manifest listing:
/// `(name, current_version, dek_version, nonce)`.
pub type SecretEntryRow = (String, u64, u64, Vec<u8>);

/// The full current-version row of one secret, as a sync fetch ships it:
/// `(version, dek_version, nonce, ciphertext, created_at, created_by)`.
pub type SecretDataRow = (u64, u64, Vec<u8>, Vec<u8>, i64, String);

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
  group_id   INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
  version    INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, version)
);
CREATE TABLE IF NOT EXISTS dek_wrap (
  group_id    INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
  dek_version INTEGER NOT NULL,
  recipient   TEXT NOT NULL,
  wrapped     BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (group_id, dek_version, recipient)
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

/// v1 → v2: group_dek's two wrap columns become dek_wrap rows.
fn migrate(conn: &Connection) -> Result<()> {
    let has_old_columns: bool = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('group_dek') WHERE name = 'wrapped_operational'",
        [],
        |r| r.get::<_, i64>(0),
    )? != 0;
    if has_old_columns {
        conn.execute_batch(
            r#"
            BEGIN;
            CREATE TABLE dek_wrap (
              group_id    INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
              dek_version INTEGER NOT NULL,
              recipient   TEXT NOT NULL,
              wrapped     BLOB NOT NULL,
              created_at  INTEGER NOT NULL,
              PRIMARY KEY (group_id, dek_version, recipient)
            );
            INSERT INTO dek_wrap SELECT group_id, version, 'operational', wrapped_operational, created_at FROM group_dek;
            INSERT INTO dek_wrap SELECT group_id, version, 'backup', wrapped_backup, created_at FROM group_dek;
            CREATE TABLE group_dek_v2 (
              group_id   INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
              version    INTEGER NOT NULL,
              created_at INTEGER NOT NULL,
              PRIMARY KEY (group_id, version)
            );
            INSERT INTO group_dek_v2 SELECT group_id, version, created_at FROM group_dek;
            DROP TABLE group_dek;
            ALTER TABLE group_dek_v2 RENAME TO group_dek;
            INSERT INTO meta (key, value) VALUES ('schema_version', '2')
              ON CONFLICT (key) DO UPDATE SET value = '2';
            COMMIT;
            "#,
        )?;
    }
    // Stamp the role on any initialized database that predates roles. A
    // brand-new database (nothing on disk yet, `open`/`open_in_memory`
    // running before `execute_batch(SCHEMA)` has ever run) has no `meta`
    // table at all, so guard the lookup instead of querying it directly.
    let has_meta: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
        [],
        |r| r.get::<_, i64>(0),
    )? != 0;
    if has_meta {
        let initialized: bool = conn
            .query_row(
                "SELECT 1 FROM meta WHERE key = 'operational_pubkey'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if initialized {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('role', 'authoritative') ON CONFLICT (key) DO NOTHING",
                [],
            )?;
        }
    }
    Ok(())
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // The bundled SQLite creates database files 0644; the metadata in
        // here (names, ACLs, EndpointIds, audit log) is not for other local
        // users. Create the file 0600 before SQLite touches it, and repair
        // pre-existing files (the WAL/SHM sidecars inherit the main file's
        // mode, but stale ones from earlier versions need fixing too).
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating database {}", path.display()))?;
        let restrict = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, restrict.clone())?;
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            let sidecar = std::path::PathBuf::from(sidecar);
            if sidecar.exists() {
                std::fs::set_permissions(&sidecar, restrict.clone())?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&conn)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&conn)?;
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
        // ON CONFLICT DO UPDATE: a schema-only v1 database (created but
        // never initialized) already has a `schema_version` row from
        // `migrate()` by the time `init` runs, since `open` always
        // migrates before the caller gets a chance to check
        // `is_initialized`. A plain INSERT would collide on that row and
        // brick the database for every future init attempt.
        tx.execute(
            "INSERT INTO meta (key, value) VALUES
               ('operational_pubkey', ?1), ('backup_pubkey', ?2),
               ('schema_version', '2'), ('role', 'authoritative')
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
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

    /// Set several meta keys in one transaction — all or none, so a
    /// multi-key stamp (like a replica's role bookkeeping) can never be
    /// torn by a crash between the writes.
    pub fn meta_set_many(&mut self, entries: &[(&str, &str)]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for (key, value) in entries {
            tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = ?2",
                params![key, value],
            )?;
        }
        tx.commit()?;
        Ok(())
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

    /// Delete an identity without touching key material. Callers that can
    /// reach the group DEKs should use
    /// [`Store::remove_identity_with_rotations`] instead: a removed reader
    /// keeps every DEK it ever unwrapped, so its groups need rotating.
    pub fn remove_identity(&self, name: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM identity WHERE name = ?1", [name])?;
        Ok(n > 0)
    }

    /// Set or clear the service-admin flag; false when no such identity.
    pub fn set_service_admin(&self, name: &str, service_admin: bool) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE identity SET service_admin = ?2 WHERE name = ?1",
            params![name, service_admin as i64],
        )?;
        Ok(changed > 0)
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

    /// Creates a group, its first wrapped DEK (version 1) with one
    /// `dek_wrap` row per `(recipient, wrapped)` pair, and the creator's
    /// ACL entry, all in one transaction, so a group can never exist
    /// without an admin.
    pub fn create_group(
        &mut self,
        name: &str,
        wraps: &[(String, Vec<u8>)],
        creator_identity_id: i64,
        creator_perms: u8,
    ) -> Result<()> {
        // A DEK nobody can unwrap is a group nobody can ever read; refuse
        // to create one rather than discover it at the first `get`.
        anyhow::ensure!(!wraps.is_empty(), "a group DEK needs at least one wrap");
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO secret_group (name, created_at) VALUES (?1, ?2)",
            params![name, now()],
        )?;
        let group_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO group_dek (group_id, version, created_at) VALUES (?1, 1, ?2)",
            params![group_id, now()],
        )?;
        for (recipient, wrapped) in wraps {
            tx.execute(
                "INSERT INTO dek_wrap (group_id, dek_version, recipient, wrapped, created_at) VALUES (?1, 1, ?2, ?3, ?4)",
                params![group_id, recipient, wrapped, now()],
            )?;
        }
        tx.execute(
            "INSERT INTO group_acl (identity_id, group_id, perms) VALUES (?1, ?2, ?3)",
            params![creator_identity_id, group_id, creator_perms as i64],
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

    /// How many identities hold the admin bit on a group.
    pub fn admin_count(&self, group_id: i64) -> Result<u64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM group_acl WHERE group_id = ?1 AND (perms & ?2) != 0",
            params![group_id, PERM_ADMIN as i64],
            |r| r.get(0),
        )?;
        Ok(n as u64)
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

    /// Groups the identity holds any permission on, with that bitmask.
    pub fn groups_for_identity(&self, identity_id: i64) -> Result<Vec<(String, u8)>> {
        let mut stmt = self.conn.prepare(
            "SELECT g.name, a.perms FROM secret_group g
             JOIN group_acl a ON a.group_id = g.id
             WHERE a.identity_id = ?1 ORDER BY g.name",
        )?;
        let rows = stmt.query_map([identity_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u8))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Every group, with the identity's permission bitmask (0 when none).
    pub fn all_groups_with_perms(&self, identity_id: i64) -> Result<Vec<(String, u8)>> {
        let mut stmt = self.conn.prepare(
            "SELECT g.name, COALESCE(a.perms, 0) FROM secret_group g
             LEFT JOIN group_acl a ON a.group_id = g.id AND a.identity_id = ?1
             ORDER BY g.name",
        )?;
        let rows = stmt.query_map([identity_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u8))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The ACL of a group as (identity name, perms) pairs.
    pub fn group_acl_entries(&self, group_id: i64) -> Result<Vec<(String, u8)>> {
        let mut stmt = self.conn.prepare(
            "SELECT i.name, a.perms FROM group_acl a
             JOIN identity i ON i.id = a.identity_id
             WHERE a.group_id = ?1 ORDER BY i.name",
        )?;
        let rows = stmt.query_map([group_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u8))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The highest DEK version recorded for a group.
    pub fn current_dek_version(&self, group_id: i64) -> Result<u64> {
        Ok(self.conn.query_row(
            "SELECT MAX(version) FROM group_dek WHERE group_id = ?1",
            [group_id],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    /// All DEK versions recorded for a group, ascending.
    pub fn dek_versions(&self, group_id: i64) -> Result<Vec<u64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT version FROM group_dek WHERE group_id = ?1 ORDER BY version")?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, i64>(0).map(|v| v as u64))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The wrapped DEK for one `(group, version, recipient)`, or `None` if
    /// no such wrap has been stored.
    pub fn dek_wrap(
        &self,
        group_id: i64,
        dek_version: u64,
        recipient: &str,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT wrapped FROM dek_wrap WHERE group_id = ?1 AND dek_version = ?2 AND recipient = ?3",
                params![group_id, dek_version as i64, recipient],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Records a new DEK version for a group with a full set of recipient
    /// wraps, in one transaction. Returns the new version number.
    pub fn add_dek(&mut self, group_id: i64, wraps: &[(String, Vec<u8>)]) -> Result<u64> {
        anyhow::ensure!(!wraps.is_empty(), "a DEK version needs at least one wrap");
        let tx = self.conn.transaction()?;
        let next = Self::insert_dek_version(&tx, group_id, wraps)?;
        tx.commit()?;
        Ok(next)
    }

    /// Upserts a single recipient's wrap for an existing DEK version (e.g.
    /// adding or refreshing a reader's wrap without touching the others).
    pub fn add_dek_wrap(
        &self,
        group_id: i64,
        dek_version: u64,
        recipient: &str,
        wrapped: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO dek_wrap (group_id, dek_version, recipient, wrapped, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (group_id, dek_version, recipient) DO UPDATE SET wrapped = ?4",
            params![group_id, dek_version as i64, recipient, wrapped, now()],
        )?;
        Ok(())
    }

    /// A recipient's wraps within one group, as `(dek_version, wrapped)`.
    pub fn wraps_for_recipient(
        &self,
        group_id: i64,
        recipient: &str,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT dek_version, wrapped FROM dek_wrap WHERE group_id = ?1 AND recipient = ?2 ORDER BY dek_version",
        )?;
        let rows = stmt.query_map(params![group_id, recipient], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get(1)?))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// A recipient's wraps across every group, for offline recovery
    /// re-wrapping. `(group_id, dek_version, wrapped)`.
    pub fn all_wraps_for_recipient(&self, recipient: &str) -> Result<Vec<(i64, u64, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, dek_version, wrapped FROM dek_wrap WHERE recipient = ?1 ORDER BY group_id, dek_version",
        )?;
        let rows = stmt.query_map([recipient], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64, r.get(2)?))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Apply an offline recovery in one transaction: replace the wrapped
    /// operational DEK for every listed `(group_id, dek_version, wrapped)`
    /// and record the new operational pubkey. All-or-nothing, so a failure
    /// can never leave the database half re-wrapped.
    pub fn apply_recovery(
        &mut self,
        rewrapped: &[(i64, u64, Vec<u8>)],
        new_operational_pubkey: &str,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for (group_id, version, wrapped_op) in rewrapped {
            let n = tx.execute(
                "UPDATE dek_wrap SET wrapped = ?3 WHERE group_id = ?1 AND dek_version = ?2 AND recipient = 'operational'",
                params![group_id, *version as i64, wrapped_op],
            )?;
            anyhow::ensure!(n == 1, "no DEK row for group {group_id} version {version}");
        }
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('operational_pubkey', ?1)
             ON CONFLICT (key) DO UPDATE SET value = ?1",
            [new_operational_pubkey],
        )?;
        tx.commit()?;
        Ok(())
    }

    // ---- wrap lifecycle ----

    /// Identities holding an explicit READ bit on a group — exactly the
    /// set that gets a `dek_wrap` row per retained DEK version. A service
    /// admin without an ACL row is deliberately not included: it reads
    /// through the operational key, not through a personal wrap.
    pub fn read_granted_identities(&self, group_id: i64) -> Result<Vec<Identity>> {
        let mut stmt = self.conn.prepare(
            "SELECT i.id, i.endpoint_id, i.name, i.service_admin
             FROM group_acl a JOIN identity i ON i.id = a.identity_id
             WHERE a.group_id = ?1 AND (a.perms & ?2) != 0 ORDER BY i.name",
        )?;
        let rows = stmt.query_map(params![group_id, PERM_READ as i64], |r| {
            Ok(Identity {
                id: r.get(0)?,
                endpoint_id: r.get(1)?,
                name: r.get(2)?,
                service_admin: r.get::<_, i64>(3)? != 0,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Ids of the groups the identity holds an explicit READ bit on.
    pub fn groups_with_read(&self, identity_id: i64) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id FROM group_acl
             WHERE identity_id = ?1 AND (perms & ?2) != 0 ORDER BY group_id",
        )?;
        let rows = stmt.query_map(params![identity_id, PERM_READ as i64], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Name of a group by id (the inverse of [`Store::group_id`]).
    pub fn group_name(&self, group_id: i64) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT name FROM secret_group WHERE id = ?1",
                [group_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Grant read (and whatever else is in `perms`) together with the
    /// grantee's `(dek_version, wrapped)` rows, in one transaction: an
    /// identity is never left holding READ without the wraps to use it,
    /// nor wraps without the ACL row that justifies them.
    pub fn grant_with_wraps(
        &mut self,
        identity_id: i64,
        group_id: i64,
        perms: u8,
        wraps: &[(u64, Vec<u8>)],
        recipient: &str,
    ) -> Result<()> {
        anyhow::ensure!(
            perms & PERM_READ != 0,
            "grant_with_wraps is only for grants that include read"
        );
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO group_acl (identity_id, group_id, perms) VALUES (?1, ?2, ?3)
             ON CONFLICT (identity_id, group_id) DO UPDATE SET perms = ?3",
            params![identity_id, group_id, perms as i64],
        )?;
        for (dek_version, wrapped) in wraps {
            tx.execute(
                "INSERT INTO dek_wrap (group_id, dek_version, recipient, wrapped, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (group_id, dek_version, recipient) DO UPDATE SET wrapped = ?4",
                params![group_id, *dek_version as i64, recipient, wrapped, now()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Take read away from one identity and rotate the group DEK in the
    /// same transaction: the ACL change, the deletion of every wrap the
    /// revoked recipient held, and the new DEK version (wrapped to
    /// everyone who remains) either all land or none do. Returns the new
    /// DEK version.
    pub fn revoke_read_and_rotate(
        &mut self,
        group_id: i64,
        target_identity_id: i64,
        new_perms: u8,
        revoked_recipient: &str,
        new_dek_wraps: &[(String, Vec<u8>)],
    ) -> Result<u64> {
        anyhow::ensure!(
            !new_dek_wraps.is_empty(),
            "a DEK version needs at least one wrap"
        );
        anyhow::ensure!(
            new_perms & PERM_READ == 0,
            "revoke_read_and_rotate must not leave the read bit set"
        );
        let tx = self.conn.transaction()?;
        if new_perms == 0 {
            tx.execute(
                "DELETE FROM group_acl WHERE identity_id = ?1 AND group_id = ?2",
                [target_identity_id, group_id],
            )?;
        } else {
            tx.execute(
                "INSERT INTO group_acl (identity_id, group_id, perms) VALUES (?1, ?2, ?3)
                 ON CONFLICT (identity_id, group_id) DO UPDATE SET perms = ?3",
                params![target_identity_id, group_id, new_perms as i64],
            )?;
        }
        tx.execute(
            "DELETE FROM dek_wrap WHERE group_id = ?1 AND recipient = ?2",
            params![group_id, revoked_recipient],
        )?;
        let next = Self::insert_dek_version(&tx, group_id, new_dek_wraps)?;
        tx.commit()?;
        Ok(next)
    }

    /// Delete an identity and rotate the DEK of every group it could
    /// read, in ONE transaction: `(group_id, revoked_recipient, wraps)`
    /// per group. False when there is no such identity (nothing is
    /// rotated in that case). The identity's ACL rows go with it via the
    /// `group_acl` foreign key cascade.
    pub fn remove_identity_with_rotations(
        &mut self,
        name: &str,
        rotations: &[GroupRotation],
    ) -> Result<bool> {
        for (group_id, _, wraps) in rotations {
            anyhow::ensure!(
                !wraps.is_empty(),
                "group {group_id}'s new DEK needs at least one wrap"
            );
        }
        let tx = self.conn.transaction()?;
        let removed = tx.execute("DELETE FROM identity WHERE name = ?1", [name])?;
        if removed == 0 {
            return Ok(false); // dropping `tx` rolls back
        }
        for (group_id, revoked_recipient, wraps) in rotations {
            tx.execute(
                "DELETE FROM dek_wrap WHERE group_id = ?1 AND recipient = ?2",
                params![group_id, revoked_recipient],
            )?;
            Self::insert_dek_version(&tx, *group_id, wraps)?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// Append the next DEK version for a group with its wraps, inside an
    /// existing transaction. Returns the new version number.
    fn insert_dek_version(
        tx: &rusqlite::Transaction<'_>,
        group_id: i64,
        wraps: &[(String, Vec<u8>)],
    ) -> Result<u64> {
        let next: i64 = tx.query_row(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM group_dek WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO group_dek (group_id, version, created_at) VALUES (?1, ?2, ?3)",
            params![group_id, next, now()],
        )?;
        for (recipient, wrapped) in wraps {
            tx.execute(
                "INSERT INTO dek_wrap (group_id, dek_version, recipient, wrapped, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![group_id, next, recipient, wrapped, now()],
            )?;
        }
        Ok(next as u64)
    }

    /// Every `(group_id, dek_version, endpoint_id)` where a read-granted
    /// identity has no wrap for a retained DEK version — the work list
    /// for the startup backfill of grants that predate per-reader wraps.
    pub fn missing_reader_wraps(&self) -> Result<Vec<(i64, u64, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.group_id, d.version, i.endpoint_id
             FROM group_acl a
             JOIN identity i ON i.id = a.identity_id
             JOIN group_dek d ON d.group_id = a.group_id
             LEFT JOIN dek_wrap w ON w.group_id = a.group_id
               AND w.dek_version = d.version AND w.recipient = i.endpoint_id
             WHERE (a.perms & ?1) != 0 AND w.recipient IS NULL
             ORDER BY a.group_id, d.version, i.endpoint_id",
        )?;
        let rows = stmt.query_map([PERM_READ as i64], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64, r.get(2)?))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    // ---- sync manifest queries ----

    /// Groups where the identity holds an EXPLICIT read bit, as
    /// `(group_id, group_name)` ordered by name. This is the whole sync
    /// scope: the service-admin implicit read deliberately does not count
    /// (sync only ever ships wraps addressed to the caller, and implicit
    /// readers have none).
    pub fn read_scope(&self, identity_id: i64) -> Result<Vec<(i64, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT g.id, g.name FROM secret_group g
             JOIN group_acl a ON a.group_id = g.id
             WHERE a.identity_id = ?1 AND (a.perms & ?2) != 0 ORDER BY g.name",
        )?;
        let rows = stmt.query_map(params![identity_id, PERM_READ as i64], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The full ACL of a group as `(identity_name, endpoint_id, perms)`
    /// ordered by identity name — what a replica needs to enforce the ACL
    /// itself.
    pub fn acl_entries_full(&self, group_id: i64) -> Result<Vec<(String, String, u8)>> {
        let mut stmt = self.conn.prepare(
            "SELECT i.name, i.endpoint_id, a.perms FROM group_acl a
             JOIN identity i ON i.id = a.identity_id
             WHERE a.group_id = ?1 ORDER BY i.name",
        )?;
        let rows = stmt.query_map([group_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)? as u8,
            ))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The current version of every secret in a group, as
    /// `(name, current_version, dek_version, nonce)` ordered by name —
    /// the manifest listing (no ciphertext).
    pub fn secret_entries(&self, group_id: i64) -> Result<Vec<SecretEntryRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.name, s.current_version, sv.dek_version, sv.nonce
             FROM secret s JOIN secret_version sv
               ON sv.secret_id = s.id AND sv.version = s.current_version
             WHERE s.group_id = ?1 ORDER BY s.name",
        )?;
        let rows = stmt.query_map([group_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The full current-version row of one secret, as `(version,
    /// dek_version, nonce, ciphertext, created_at, created_by)` — what a
    /// sync fetch ships (still ciphertext; sync never decrypts).
    pub fn secret_data_current(&self, group_id: i64, name: &str) -> Result<Option<SecretDataRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT sv.version, sv.dek_version, sv.nonce, sv.ciphertext,
                        sv.created_at, sv.created_by
                 FROM secret s JOIN secret_version sv
                   ON sv.secret_id = s.id AND sv.version = s.current_version
                 WHERE s.group_id = ?1 AND s.name = ?2",
                params![group_id, name],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)? as u64,
                        r.get::<_, i64>(1)? as u64,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?)
    }

    // ---- replica sync apply (spec 4.4) ----

    /// The names in `state` whose local current version differs in any of
    /// `(current_version, dek_version, nonce)`, plus those absent locally —
    /// exactly the fetch list for [`Store::apply_group_sync`], in the
    /// state's own order. Names whose local state already matches are
    /// omitted, so re-applying an unchanged state fetches nothing.
    ///
    /// The nonce is what makes delete-then-recreate detectable: a
    /// recreated secret can land on the same `(version, dek_version)`
    /// (versions restart at 1 and deletion does not rotate the DEK), but
    /// every encryption draws a fresh random nonce. `created_at` is no
    /// substitute — it has one-second resolution.
    pub fn secrets_needing_fetch(&self, state: &GroupSyncState) -> Result<Vec<String>> {
        let Some(group_id) = self.group_id(&state.name)? else {
            // Nothing of this group is mirrored yet: fetch all of it.
            return Ok(state.secrets.iter().map(|e| e.name.clone()).collect());
        };
        let mut names = Vec::new();
        for entry in &state.secrets {
            let current = self.secret_current(group_id, &entry.name)?;
            let unchanged = current.is_some_and(|local| {
                local.version == entry.current_version
                    && local.dek_version == entry.dek_version
                    && local.nonce == entry.nonce
            });
            if !unchanged {
                names.push(entry.name.clone());
            }
        }
        Ok(names)
    }

    /// `acl` with every name and endpoint-id collision resolved in favour
    /// of the last entry holding it — the list rules 1 and 2 actually
    /// apply.
    ///
    /// An authoritative node cannot emit a collision (both columns are
    /// UNIQUE upstream), but a malformed or hostile state must fail safe.
    /// Applied naively, two entries sharing a name wedge the group
    /// permanently: the second entry's stale-name delete (rule 1) removes
    /// the row the first just upserted, so rule 2's lookup for the first
    /// entry finds nothing, the whole apply rolls back — and every retry
    /// rolls back identically, since the input never changes. Collapsing
    /// the duplicates first makes the apply converge on the last entry,
    /// which is what rule 1's delete already effectively picks.
    fn effective_acl(acl: &[AclEntry]) -> Vec<&AclEntry> {
        let mut names = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        // Last-wins, so scan backwards and keep the first sighting of each
        // key; `&&` short-circuits deliberately — an entry dropped for a
        // duplicate name must not also reserve its endpoint id.
        let mut kept: Vec<&AclEntry> = acl
            .iter()
            .rev()
            .filter(|e| {
                names.insert(e.identity_name.as_str()) && endpoints.insert(e.endpoint_id.as_str())
            })
            .collect();
        kept.reverse();
        kept
    }

    /// Converge the local mirror of one group onto `state` in ONE
    /// transaction — a replica reader never observes a half-applied group.
    /// Implements spec 4.4 rules 1–5 in dependency order and returns the
    /// secret-level changes, for the caller to publish after the commit.
    ///
    /// `own_endpoint` is this replica's own lowercase-hex endpoint id: the
    /// only `dek_wrap` recipient a replica ever holds, since the manifest
    /// only ever carries wraps addressed to the caller.
    ///
    /// Replica-only. It replaces the group's ACL wholesale from `state`
    /// and never sets `service_admin` (a replica authorizes strictly by
    /// explicit ACL rows, spec 5.2); on an authoritative database it would
    /// destroy local truth.
    pub fn apply_group_sync(
        &mut self,
        own_endpoint: &str,
        state: &GroupSyncState,
        fetched: &[FetchedSecret],
    ) -> Result<Vec<AppliedChange>> {
        let ts = now();
        let tx = self.conn.transaction()?;

        // The group row itself: created on first sight, kept afterwards
        // (its id is what every other row here hangs off).
        tx.execute(
            "INSERT INTO secret_group (name, created_at) VALUES (?1, ?2)
             ON CONFLICT (name) DO NOTHING",
            params![state.name, ts],
        )?;
        let group_id: i64 = tx.query_row(
            "SELECT id FROM secret_group WHERE name = ?1",
            [&state.name],
            |r| r.get(0),
        )?;

        // Rules 1 and 2 both walk the ACL, and both must walk the *same*
        // collision-free list (see `effective_acl`).
        let acl = Self::effective_acl(&state.acl);

        // Rule 1: identity rows referenced by the ACL, keyed by endpoint
        // id, taking the authoritative node's names.
        for entry in &acl {
            // Names are unique upstream, so a local row holding this name
            // under a *different* endpoint id is by definition stale — a
            // key replacement (RemoveIdentity + AddIdentity under the same
            // name). Without this delete the group's apply would livelock
            // forever on the UNIQUE(name) constraint.
            //
            // INSERT OR REPLACE must never be used here: its
            // delete-and-reinsert would cascade `group_acl` rows in
            // unrelated groups and reassign `identity.id`.
            tx.execute(
                "DELETE FROM identity WHERE name = ?1 AND endpoint_id <> ?2",
                params![entry.identity_name, entry.endpoint_id],
            )?;
            // `service_admin` is pinned to 0 on both paths: it is never
            // synced (AclEntry carries no such field) and a replica must
            // not honour a stale local flag either.
            tx.execute(
                "INSERT INTO identity (endpoint_id, name, service_admin, created_at)
                 VALUES (?1, ?2, 0, ?3)
                 ON CONFLICT (endpoint_id) DO UPDATE SET name = excluded.name, service_admin = 0",
                params![entry.endpoint_id, entry.identity_name, ts],
            )?;
        }

        // Rule 2: the ACL, wholesale.
        tx.execute("DELETE FROM group_acl WHERE group_id = ?1", [group_id])?;
        for entry in &acl {
            let identity_id: i64 = tx.query_row(
                "SELECT id FROM identity WHERE endpoint_id = ?1",
                [&entry.endpoint_id],
                |r| r.get(0),
            )?;
            // ON CONFLICT is belt and braces: `effective_acl` has already
            // collapsed any repeated endpoint id, so no two entries here
            // can resolve to the same identity row.
            tx.execute(
                "INSERT INTO group_acl (identity_id, group_id, perms) VALUES (?1, ?2, ?3)
                 ON CONFLICT (identity_id, group_id) DO UPDATE SET perms = excluded.perms",
                params![identity_id, group_id, entry.perms as i64],
            )?;
        }

        // Rule 3: DEK version rows and this replica's wraps.
        for dek in &state.deks {
            tx.execute(
                "INSERT INTO group_dek (group_id, version, created_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT (group_id, version) DO NOTHING",
                params![group_id, dek.version as i64, ts],
            )?;
            // Wrap blobs are stable at rest, so a differing blob means the
            // DEK version was reissued upstream (an authoritative restore
            // rewound it) — the local one is the stale copy.
            tx.execute(
                "INSERT INTO dek_wrap (group_id, dek_version, recipient, wrapped, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (group_id, dek_version, recipient)
                   DO UPDATE SET wrapped = excluded.wrapped",
                params![group_id, dek.version as i64, own_endpoint, dek.wrapped, ts],
            )?;
        }
        // Wraps absent from the state go: versions it no longer carries
        // (revoked or forgotten upstream) and anything addressed to
        // another recipient, which a replica has no business holding.
        // `group_dek` rows are left alone — a version we hold no wrap for
        // is a legitimate state (the wrap may come back next round).
        let stale_wraps: Vec<(i64, String)> = {
            let keep: BTreeSet<i64> = state.deks.iter().map(|d| d.version as i64).collect();
            let mut stmt =
                tx.prepare("SELECT dek_version, recipient FROM dek_wrap WHERE group_id = ?1")?;
            let rows = stmt.query_map([group_id], |r| Ok((r.get::<_, i64>(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<Vec<(i64, String)>, _>>()?
                .into_iter()
                .filter(|(version, recipient)| recipient != own_endpoint || !keep.contains(version))
                .collect()
        };
        for (version, recipient) in stale_wraps {
            tx.execute(
                "DELETE FROM dek_wrap WHERE group_id = ?1 AND dek_version = ?2 AND recipient = ?3",
                params![group_id, version, recipient],
            )?;
        }

        // Rule 4: every fetched secret replaces whatever is local. The
        // delete cascades the old version rows, so a recreated secret
        // (whose versions restarted at 1) can never collide with them.
        let mut changes = Vec::new();
        for secret in fetched {
            tx.execute(
                "DELETE FROM secret WHERE group_id = ?1 AND name = ?2",
                params![group_id, secret.name],
            )?;
            tx.execute(
                "INSERT INTO secret (group_id, name, current_version) VALUES (?1, ?2, ?3)",
                params![group_id, secret.name, secret.version as i64],
            )?;
            let secret_id = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO secret_version
                   (secret_id, version, dek_version, nonce, ciphertext, created_at, created_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    secret_id,
                    secret.version as i64,
                    secret.dek_version as i64,
                    secret.nonce,
                    secret.ciphertext,
                    secret.created_at,
                    secret.created_by,
                ],
            )?;
            changes.push(AppliedChange::SecretChanged {
                name: secret.name.clone(),
                version: secret.version,
            });
        }

        // Rule 5: local secrets the state does not list are gone upstream.
        // A listed name that simply was not fetched this round is left
        // alone — it is either already current or waiting for the next.
        let removed: Vec<String> = {
            let listed: BTreeSet<&str> = state.secrets.iter().map(|e| e.name.as_str()).collect();
            let mut stmt =
                tx.prepare("SELECT name FROM secret WHERE group_id = ?1 ORDER BY name")?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            rows.collect::<std::result::Result<Vec<String>, _>>()?
                .into_iter()
                .filter(|name| !listed.contains(name.as_str()))
                .collect()
        };
        for name in removed {
            tx.execute(
                "DELETE FROM secret WHERE group_id = ?1 AND name = ?2",
                params![group_id, name],
            )?;
            changes.push(AppliedChange::SecretDeleted { name });
        }

        tx.commit()?;
        Ok(changes)
    }

    /// Drop a group from the local mirror: its ACL rows, DEK versions,
    /// wraps, secrets and secret versions all go with it through the
    /// foreign-key cascades. False when the group is not mirrored locally.
    /// Identity rows stay (they may be shared with other groups);
    /// [`Store::gc_unreferenced_identities`] sweeps the orphans.
    ///
    /// Replica-only, and only on a *completed* resync: a group missing
    /// from a partial manifest stream has not been revoked, merely not
    /// mentioned yet.
    pub fn drop_group_local(&mut self, name: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM secret_group WHERE name = ?1", [name])?;
        Ok(n > 0)
    }

    /// Delete identity rows no `group_acl` row references, returning how
    /// many went. Run at the end of a full replica resync, where an
    /// identity can lose its last group.
    ///
    /// Replica-only: on an authoritative database identities exist
    /// independently of any ACL row, and this would delete them.
    pub fn gc_unreferenced_identities(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM identity WHERE NOT EXISTS
               (SELECT 1 FROM group_acl WHERE group_acl.identity_id = identity.id)",
            [],
        )?)
    }

    /// Every group name in the local mirror, ascending. On a replica that
    /// is exactly the mirrored scope, so it is also the set to diff a full
    /// manifest against when deciding what [`Store::drop_group_local`]
    /// should remove.
    pub fn replica_group_names(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM secret_group ORDER BY name")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
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

    /// Verify the hash chain. Detects in-place edits, not truncation from
    /// the tail — record the returned head externally to detect that.
    pub fn verify_audit_chain(&self) -> Result<AuditVerification> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, ts, endpoint_id, op, target, outcome, prev_hash, hash FROM audit_log ORDER BY seq",
        )?;
        type AuditRow = (i64, i64, String, String, String, String, Vec<u8>, Vec<u8>);
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
                    r.get(7)?,
                ))
            })?
            .collect::<std::result::Result<_, _>>()?;
        let mut entries = 0u64;
        let mut prev = vec![0u8; 32];
        let mut head = None;
        for (seq, ts, endpoint_id, op, target, outcome, prev_hash, hash) in rows {
            if prev_hash != prev {
                return Ok(AuditVerification::Broken { seq });
            }
            let mut hasher = Sha256::new();
            hasher.update(&prev);
            hasher.update(ts.to_be_bytes());
            for field in [&endpoint_id, &op, &target, &outcome] {
                hasher.update((field.len() as u64).to_be_bytes());
                hasher.update(field.as_bytes());
            }
            if hasher.finalize().as_slice() != hash {
                return Ok(AuditVerification::Broken { seq });
            }
            prev = hash.clone();
            head = Some((seq, hash));
            entries += 1;
        }
        Ok(AuditVerification::Valid { entries, head })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CasOutcome {
    Applied { new_version: u64 },
    Conflict { current: u64 },
}

/// What one [`Store::apply_group_sync`] changed about a group's secrets,
/// for the caller to publish once the transaction has committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppliedChange {
    SecretChanged { name: String, version: u64 },
    SecretDeleted { name: String },
}

/// Result of [`Store::verify_audit_chain`].
#[derive(Debug, PartialEq, Eq)]
pub enum AuditVerification {
    /// Chain is internally consistent; `head` is the last `(seq, hash)`,
    /// suitable for anchoring outside the database.
    Valid {
        entries: u64,
        head: Option<(i64, Vec<u8>)>,
    },
    /// The entry at `seq` does not match the chain.
    Broken { seq: i64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{AclEntry, DekEntry, SecretEntry};

    fn store() -> Store {
        let mut s = Store::open_in_memory().unwrap();
        s.init("age1op", "age1backup", "endpoint-admin", "admin")
            .unwrap();
        s
    }

    /// Create a group with the bootstrap admin as its creator; returns the
    /// group id.
    fn create_group(s: &mut Store, name: &str) -> i64 {
        let admin = s.identity_by_endpoint("endpoint-admin").unwrap().unwrap();
        s.create_group(
            name,
            &[
                (RECIPIENT_OPERATIONAL.into(), b"op".to_vec()),
                (RECIPIENT_BACKUP.into(), b"bk".to_vec()),
            ],
            admin.id,
            PERM_READ | PERM_WRITE | PERM_ADMIN,
        )
        .unwrap();
        s.group_id(name).unwrap().unwrap()
    }

    #[test]
    fn set_service_admin_flips_the_flag() {
        let s = store();
        s.add_identity("bob", "endpoint-bob", false).unwrap();
        assert!(s.set_service_admin("bob", true).unwrap());
        assert!(s.identity_by_name("bob").unwrap().unwrap().service_admin);
        assert!(s.set_service_admin("bob", false).unwrap());
        assert!(!s.identity_by_name("bob").unwrap().unwrap().service_admin);
        assert!(!s.set_service_admin("nope", true).unwrap());
    }

    #[test]
    fn open_creates_database_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bunker.sqlite");
        let _s = Store::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "database must not be world-readable");
        // Pre-existing databases get fixed on open too.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _s = Store::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn init_is_one_shot() {
        let mut s = store();
        assert!(s.is_initialized().unwrap());
        assert!(s.init("x", "y", "z", "w").is_err());
    }

    #[test]
    fn create_group_grants_only_the_creator() {
        let mut s = store();
        assert!(s.identity_by_endpoint("stranger").unwrap().is_none());
        s.add_identity("alice", "endpoint-alice", false).unwrap();
        let gid = create_group(&mut s, "g");
        let admin = s.identity_by_endpoint("endpoint-admin").unwrap().unwrap();
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        // The creator's grant is part of the same transaction as the group;
        // nobody else gets anything (the service-admin flag carries no
        // per-group permissions).
        assert_eq!(
            s.perms(admin.id, gid).unwrap(),
            PERM_READ | PERM_WRITE | PERM_ADMIN
        );
        assert_eq!(s.perms(alice.id, gid).unwrap(), 0);
        assert_eq!(s.admin_count(gid).unwrap(), 1);
    }

    #[test]
    fn acl_grant_and_revoke() {
        let mut s = store();
        s.add_identity("alice", "endpoint-alice", false).unwrap();
        let gid = create_group(&mut s, "g");
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        s.set_perms(alice.id, gid, PERM_READ | PERM_WRITE).unwrap();
        assert_eq!(s.perms(alice.id, gid).unwrap(), PERM_READ | PERM_WRITE);
        s.set_perms(alice.id, gid, 0).unwrap();
        assert_eq!(s.perms(alice.id, gid).unwrap(), 0);
    }

    #[test]
    fn admin_count_tracks_admin_bit_holders() {
        let mut s = store();
        s.add_identity("alice", "endpoint-alice", false).unwrap();
        let gid = create_group(&mut s, "g");
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        assert_eq!(s.admin_count(gid).unwrap(), 1);
        s.set_perms(alice.id, gid, PERM_READ | PERM_ADMIN).unwrap();
        assert_eq!(s.admin_count(gid).unwrap(), 2);
        s.set_perms(alice.id, gid, PERM_READ).unwrap();
        assert_eq!(s.admin_count(gid).unwrap(), 1);
    }

    #[test]
    fn removing_identity_cascades_acl() {
        let mut s = store();
        s.add_identity("alice", "endpoint-alice", false).unwrap();
        let gid = create_group(&mut s, "g");
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        s.set_perms(alice.id, gid, PERM_READ).unwrap();
        assert!(s.remove_identity("alice").unwrap());
        assert!(s.identity_by_endpoint("endpoint-alice").unwrap().is_none());
    }

    #[test]
    fn sync_manifest_queries_reflect_explicit_read_and_current_versions() {
        let mut s = store();
        let gid = create_group(&mut s, "g");
        let gid2 = create_group(&mut s, "h");
        s.add_identity("alice", "endpoint-alice", false).unwrap();
        let admin = s.identity_by_endpoint("endpoint-admin").unwrap().unwrap();
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        s.set_perms(alice.id, gid, PERM_READ | PERM_WRITE).unwrap();
        // read_scope: only groups with the explicit read bit, by name.
        assert_eq!(
            s.read_scope(admin.id).unwrap(),
            vec![(gid, "g".into()), (gid2, "h".into())]
        );
        assert_eq!(s.read_scope(alice.id).unwrap(), vec![(gid, "g".into())]);
        s.set_perms(alice.id, gid, PERM_WRITE).unwrap();
        assert_eq!(s.read_scope(alice.id).unwrap(), vec![]);
        // acl_entries_full: every row, read bit or not, ordered by name.
        assert_eq!(
            s.acl_entries_full(gid).unwrap(),
            vec![
                (
                    "admin".into(),
                    "endpoint-admin".into(),
                    PERM_READ | PERM_WRITE | PERM_ADMIN
                ),
                ("alice".into(), "endpoint-alice".into(), PERM_WRITE),
            ]
        );
        // secret_entries: the current version of each secret, by name.
        s.put_secret(gid, "b", 0, 1, b"nb", b"cb", "admin").unwrap();
        s.put_secret(gid, "a", 0, 1, b"na1", b"ca1", "admin")
            .unwrap();
        s.put_secret(gid, "a", 1, 1, b"na2", b"ca2", "admin")
            .unwrap();
        assert_eq!(
            s.secret_entries(gid).unwrap(),
            vec![
                ("a".into(), 2, 1, b"na2".to_vec()),
                ("b".into(), 1, 1, b"nb".to_vec()),
            ]
        );
        assert_eq!(s.secret_entries(gid2).unwrap(), vec![]);
        // secret_data_current: the full current row, None when missing.
        let (version, dek_version, nonce, ciphertext, created_at, created_by) =
            s.secret_data_current(gid, "a").unwrap().unwrap();
        assert_eq!((version, dek_version), (2, 1));
        assert_eq!(nonce, b"na2");
        assert_eq!(ciphertext, b"ca2");
        assert!(created_at > 0);
        assert_eq!(created_by, "admin");
        assert!(s.secret_data_current(gid, "nope").unwrap().is_none());
    }

    #[test]
    fn put_secret_cas() {
        let mut s = store();
        let gid = create_group(&mut s, "g");
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
        let gid = create_group(&mut s, "g");
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
    fn dek_wrap_rows_roundtrip() {
        let mut s = store();
        let gid = create_group(&mut s, "g");
        assert_eq!(s.current_dek_version(gid).unwrap(), 1);
        assert_eq!(s.dek_versions(gid).unwrap(), vec![1]);
        assert_eq!(
            s.dek_wrap(gid, 1, RECIPIENT_OPERATIONAL).unwrap().unwrap(),
            b"op"
        );
        assert_eq!(
            s.dek_wrap(gid, 1, RECIPIENT_BACKUP).unwrap().unwrap(),
            b"bk"
        );
        assert!(s.dek_wrap(gid, 1, "aabbcc").unwrap().is_none());
        // A reader wrap:
        s.add_dek_wrap(gid, 1, "aabbcc", b"reader-wrap").unwrap();
        assert_eq!(
            s.dek_wrap(gid, 1, "aabbcc").unwrap().unwrap(),
            b"reader-wrap"
        );
        assert_eq!(
            s.wraps_for_recipient(gid, "aabbcc").unwrap(),
            vec![(1, b"reader-wrap".to_vec())]
        );
        // New DEK version with a full wrap set:
        let v = s
            .add_dek(
                gid,
                &[
                    (RECIPIENT_OPERATIONAL.into(), b"op2".to_vec()),
                    (RECIPIENT_BACKUP.into(), b"bk2".to_vec()),
                    ("aabbcc".into(), b"reader2".to_vec()),
                ],
            )
            .unwrap();
        assert_eq!(v, 2);
        assert_eq!(s.current_dek_version(gid).unwrap(), 2);
        assert_eq!(
            s.dek_wrap(gid, 1, RECIPIENT_OPERATIONAL).unwrap().unwrap(),
            b"op"
        );
    }

    #[test]
    fn empty_wrap_sets_are_refused() {
        // A DEK version nobody is wrapped to is unrecoverable ciphertext;
        // every path that mints one refuses an empty wrap set.
        let mut s = store();
        let admin = s.identity_by_endpoint("endpoint-admin").unwrap().unwrap();
        assert!(s.create_group("empty", &[], admin.id, PERM_READ).is_err());
        assert!(s.group_id("empty").unwrap().is_none());
        let gid = create_group(&mut s, "g");
        assert!(s.add_dek(gid, &[]).is_err());
        assert!(
            s.revoke_read_and_rotate(gid, admin.id, 0, "endpoint-admin", &[])
                .is_err()
        );
        assert_eq!(s.current_dek_version(gid).unwrap(), 1);
        assert_eq!(
            s.perms(admin.id, gid).unwrap(),
            PERM_READ | PERM_WRITE | PERM_ADMIN
        );
    }

    #[test]
    fn wrap_lifecycle_grant_revoke_and_remove() {
        let mut s = store();
        let gid = create_group(&mut s, "g");
        s.add_identity("alice", "endpoint-alice", false).unwrap();
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        // The creator's grant came from create_group's ACL row; it is a
        // reader, alice is not yet.
        assert_eq!(
            s.read_granted_identities(gid)
                .unwrap()
                .iter()
                .map(|i| i.name.clone())
                .collect::<Vec<_>>(),
            vec!["admin".to_string()]
        );
        assert!(s.groups_with_read(alice.id).unwrap().is_empty());

        // Granting read carries the wraps in the same transaction.
        s.grant_with_wraps(
            alice.id,
            gid,
            PERM_READ | PERM_WRITE,
            &[(1, b"alice-v1".to_vec())],
            "endpoint-alice",
        )
        .unwrap();
        assert_eq!(s.perms(alice.id, gid).unwrap(), PERM_READ | PERM_WRITE);
        assert_eq!(
            s.dek_wrap(gid, 1, "endpoint-alice").unwrap().unwrap(),
            b"alice-v1"
        );
        assert_eq!(s.groups_with_read(alice.id).unwrap(), vec![gid]);
        // A grant without the read bit is a caller bug, not a silent no-op.
        assert!(
            s.grant_with_wraps(alice.id, gid, PERM_WRITE, &[], "endpoint-alice")
                .is_err()
        );

        // Revoking read down to write-only drops the wraps and rotates.
        let v = s
            .revoke_read_and_rotate(
                gid,
                alice.id,
                PERM_WRITE,
                "endpoint-alice",
                &[
                    (RECIPIENT_OPERATIONAL.into(), b"op2".to_vec()),
                    (RECIPIENT_BACKUP.into(), b"bk2".to_vec()),
                ],
            )
            .unwrap();
        assert_eq!(v, 2);
        assert_eq!(s.perms(alice.id, gid).unwrap(), PERM_WRITE);
        assert!(s.dek_wrap(gid, 1, "endpoint-alice").unwrap().is_none());
        assert!(s.groups_with_read(alice.id).unwrap().is_empty());

        // Every read-granted identity missing a wrap for a retained
        // version shows up in the backfill work list. Alice no longer
        // holds read, so only admin — whose ACL row this test's helper
        // created without any wraps, exactly like a pre-redesign grant —
        // is listed, once per retained version.
        assert_eq!(
            s.missing_reader_wraps().unwrap(),
            vec![
                (gid, 1, "endpoint-admin".to_string()),
                (gid, 2, "endpoint-admin".to_string())
            ]
        );

        // Removing an identity that does not exist rotates nothing.
        assert!(
            !s.remove_identity_with_rotations(
                "nobody",
                &[(
                    gid,
                    "endpoint-admin".into(),
                    vec![("x".into(), b"y".to_vec())]
                )],
            )
            .unwrap()
        );
        assert_eq!(s.current_dek_version(gid).unwrap(), 2);

        // Removing a real one deletes it, its ACL rows, and its wraps,
        // and rotates the groups it could read — all at once.
        assert!(
            s.remove_identity_with_rotations(
                "admin",
                &[(
                    gid,
                    "endpoint-admin".into(),
                    vec![(RECIPIENT_OPERATIONAL.into(), b"op3".to_vec())],
                )],
            )
            .unwrap()
        );
        assert!(s.identity_by_name("admin").unwrap().is_none());
        assert_eq!(s.current_dek_version(gid).unwrap(), 3);
        assert!(s.dek_wrap(gid, 1, "endpoint-admin").unwrap().is_none());
        assert_eq!(s.admin_count(gid).unwrap(), 0);
    }

    #[test]
    fn migration_v1_to_v2_moves_wrap_columns_to_rows() {
        // Build a real v1 database by hand, then open it through Store.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.sqlite");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE identity (id INTEGER PRIMARY KEY, endpoint_id TEXT NOT NULL UNIQUE,
                  name TEXT NOT NULL UNIQUE, service_admin INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
                CREATE TABLE secret_group (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
                CREATE TABLE group_acl (identity_id INTEGER NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
                  group_id INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
                  perms INTEGER NOT NULL, PRIMARY KEY (identity_id, group_id));
                CREATE TABLE group_dek (group_id INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
                  version INTEGER NOT NULL, wrapped_operational BLOB NOT NULL, wrapped_backup BLOB NOT NULL,
                  created_at INTEGER NOT NULL, PRIMARY KEY (group_id, version));
                CREATE TABLE secret (id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
                  name TEXT NOT NULL, current_version INTEGER NOT NULL, UNIQUE (group_id, name));
                CREATE TABLE secret_version (secret_id INTEGER NOT NULL REFERENCES secret(id) ON DELETE CASCADE,
                  version INTEGER NOT NULL, dek_version INTEGER NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
                  created_at INTEGER NOT NULL, created_by TEXT NOT NULL, PRIMARY KEY (secret_id, version));
                CREATE TABLE audit_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
                  endpoint_id TEXT NOT NULL, op TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL,
                  prev_hash BLOB NOT NULL, hash BLOB NOT NULL);
                INSERT INTO meta VALUES ('operational_pubkey','age1op'),('backup_pubkey','age1bk'),('schema_version','1');
                INSERT INTO identity (endpoint_id,name,service_admin,created_at) VALUES ('adminid','admin',1,0);
                INSERT INTO secret_group (name,created_at) VALUES ('g',0);
                INSERT INTO group_dek VALUES (1,1,x'0102',x'0304',0);
                INSERT INTO group_dek VALUES (1,2,x'0506',x'0708',0);
            "#,
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.meta_get("schema_version").unwrap().unwrap(), "2");
        assert_eq!(s.meta_get("role").unwrap().unwrap(), "authoritative");
        let gid = s.group_id("g").unwrap().unwrap();
        assert_eq!(s.dek_versions(gid).unwrap(), vec![1, 2]);
        assert_eq!(
            s.dek_wrap(gid, 1, RECIPIENT_OPERATIONAL).unwrap().unwrap(),
            vec![0x01, 0x02]
        );
        assert_eq!(
            s.dek_wrap(gid, 2, RECIPIENT_BACKUP).unwrap().unwrap(),
            vec![0x07, 0x08]
        );
        // Old columns are gone.
        let cols: Vec<String> = {
            let mut stmt = s
                .conn
                .prepare("SELECT name FROM pragma_table_info('group_dek')")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert!(!cols.contains(&"wrapped_operational".to_string()));
        // Reopening is idempotent.
        drop(s);
        let s = Store::open(&path).unwrap();
        assert_eq!(
            s.dek_versions(s.group_id("g").unwrap().unwrap()).unwrap(),
            vec![1, 2]
        );
    }

    #[test]
    fn init_succeeds_on_schema_only_v1_database_migrated_but_never_initialized() {
        // A v1-shaped database that was created (schema only, empty meta)
        // but never initialized: ordinary v1 usage reaches `Store::open`
        // (which migrates) before the initialized check, e.g. both `serve`
        // and `init` open the store first. Migration must not leave the
        // database unable to complete a subsequent `init`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1-empty.sqlite");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE identity (id INTEGER PRIMARY KEY, endpoint_id TEXT NOT NULL UNIQUE,
                  name TEXT NOT NULL UNIQUE, service_admin INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
                CREATE TABLE secret_group (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
                CREATE TABLE group_acl (identity_id INTEGER NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
                  group_id INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
                  perms INTEGER NOT NULL, PRIMARY KEY (identity_id, group_id));
                CREATE TABLE group_dek (group_id INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
                  version INTEGER NOT NULL, wrapped_operational BLOB NOT NULL, wrapped_backup BLOB NOT NULL,
                  created_at INTEGER NOT NULL, PRIMARY KEY (group_id, version));
                CREATE TABLE secret (id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
                  name TEXT NOT NULL, current_version INTEGER NOT NULL, UNIQUE (group_id, name));
                CREATE TABLE secret_version (secret_id INTEGER NOT NULL REFERENCES secret(id) ON DELETE CASCADE,
                  version INTEGER NOT NULL, dek_version INTEGER NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
                  created_at INTEGER NOT NULL, created_by TEXT NOT NULL, PRIMARY KEY (secret_id, version));
                CREATE TABLE audit_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
                  endpoint_id TEXT NOT NULL, op TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL,
                  prev_hash BLOB NOT NULL, hash BLOB NOT NULL);
            "#,
            )
            .unwrap();
            // meta intentionally left empty: schema created, never initialized.
        }
        let mut s = Store::open(&path).unwrap();
        // The migration ran (it detects the old columns regardless of row
        // count) and already wrote a `schema_version` row into `meta`; the
        // database is still uninitialized (no operational_pubkey).
        assert!(!s.is_initialized().unwrap());
        s.init("age1op", "age1backup", "endpoint-admin", "admin")
            .unwrap();
        assert!(s.is_initialized().unwrap());
        assert_eq!(s.meta_get("schema_version").unwrap().unwrap(), "2");
        assert_eq!(s.meta_get("role").unwrap().unwrap(), "authoritative");
        assert_eq!(s.meta_get("operational_pubkey").unwrap().unwrap(), "age1op");
    }

    #[test]
    fn apply_recovery_updates_operational_wrap_rows_atomically() {
        let mut s = store();
        let g1 = create_group(&mut s, "g1");
        let g2 = create_group(&mut s, "g2");
        s.apply_recovery(
            &[(g1, 1, b"new-op-1".to_vec()), (g2, 1, b"new-op-2".to_vec())],
            "age1new",
        )
        .unwrap();
        assert_eq!(
            s.dek_wrap(g1, 1, RECIPIENT_OPERATIONAL).unwrap().unwrap(),
            b"new-op-1"
        );
        assert_eq!(
            s.dek_wrap(g2, 1, RECIPIENT_OPERATIONAL).unwrap().unwrap(),
            b"new-op-2"
        );
        assert_eq!(s.dek_wrap(g1, 1, RECIPIENT_BACKUP).unwrap().unwrap(), b"bk");
        assert_eq!(
            s.meta_get("operational_pubkey").unwrap().unwrap(),
            "age1new"
        );
        // A bad row (nonexistent version in g2) aborts the whole batch:
        // nothing is applied, not even g1's otherwise-valid update.
        assert!(
            s.apply_recovery(
                &[(g1, 1, b"newer".to_vec()), (g2, 99, b"missing".to_vec())],
                "age1newer",
            )
            .is_err()
        );
        assert_eq!(
            s.dek_wrap(g1, 1, RECIPIENT_OPERATIONAL).unwrap().unwrap(),
            b"new-op-1"
        );
        assert_eq!(
            s.meta_get("operational_pubkey").unwrap().unwrap(),
            "age1new"
        );
    }

    #[test]
    fn audit_chain_verifies_and_detects_tampering() {
        let s = store();
        s.audit("endpoint-a", "get", "g/tok", "ok").unwrap();
        s.audit("endpoint-b", "put", "g/tok", "denied").unwrap();
        let verified = s.verify_audit_chain().unwrap();
        assert!(
            matches!(
                verified,
                AuditVerification::Valid {
                    entries: 2,
                    head: Some((2, _))
                }
            ),
            "unexpected verification: {verified:?}"
        );
        s.conn
            .execute(
                "UPDATE audit_log SET outcome = 'ok' WHERE outcome = 'denied'",
                [],
            )
            .unwrap();
        assert_eq!(
            s.verify_audit_chain().unwrap(),
            AuditVerification::Broken { seq: 2 }
        );
    }

    #[test]
    fn audit_chain_cannot_detect_tail_truncation_hence_head_export() {
        // Pins the documented limitation: deleting from the tail leaves a
        // chain that still verifies, with a different head — which is why
        // the head is surfaced for external anchoring.
        let s = store();
        s.audit("endpoint-a", "get", "g/tok", "ok").unwrap();
        s.audit("endpoint-b", "put", "g/tok", "denied").unwrap();
        let AuditVerification::Valid {
            head: Some((_, full_head)),
            ..
        } = s.verify_audit_chain().unwrap()
        else {
            panic!("chain must verify");
        };
        s.conn
            .execute("DELETE FROM audit_log WHERE seq = 2", [])
            .unwrap();
        let truncated = s.verify_audit_chain().unwrap();
        let AuditVerification::Valid {
            entries: 1,
            head: Some((_, truncated_head)),
        } = truncated
        else {
            panic!("truncated chain still verifies, got {truncated:?}");
        };
        assert_ne!(full_head, truncated_head);
    }

    // ---- replica sync apply (spec 4.4) ----

    /// A replica-shaped store: schema only, never `init`ed — no
    /// operational or backup key, no bootstrap admin identity.
    fn replica() -> Store {
        Store::open_in_memory().unwrap()
    }

    fn sync_state(
        name: &str,
        acl: Vec<(&str, &str, u8)>,
        deks: Vec<(u64, &[u8])>,
        secrets: Vec<(&str, u64, u64, &[u8])>,
    ) -> GroupSyncState {
        GroupSyncState {
            name: name.into(),
            acl: acl
                .into_iter()
                .map(|(identity_name, endpoint_id, perms)| AclEntry {
                    identity_name: identity_name.into(),
                    endpoint_id: endpoint_id.into(),
                    perms,
                })
                .collect(),
            deks: deks
                .into_iter()
                .map(|(version, wrapped)| DekEntry {
                    version,
                    wrapped: wrapped.to_vec(),
                })
                .collect(),
            secrets: secrets
                .into_iter()
                .map(|(name, current_version, dek_version, nonce)| SecretEntry {
                    name: name.into(),
                    current_version,
                    dek_version,
                    nonce: nonce.to_vec(),
                })
                .collect(),
        }
    }

    fn fetched_secret(
        name: &str,
        version: u64,
        dek_version: u64,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> FetchedSecret {
        FetchedSecret {
            name: name.into(),
            version,
            dek_version,
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.to_vec(),
            created_at: 5,
            created_by: "alice".into(),
        }
    }

    /// How many `secret_version` rows one secret has locally — a
    /// delete-and-recreate must not leave the old ones behind.
    fn version_row_count(s: &Store, group_id: i64, name: &str) -> i64 {
        s.conn
            .query_row(
                "SELECT COUNT(*) FROM secret_version sv JOIN secret s ON s.id = sv.secret_id
                 WHERE s.group_id = ?1 AND s.name = ?2",
                params![group_id, name],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn apply_group_sync_creates_and_updates() {
        let mut s = Store::open_in_memory().unwrap(); // replica stores are never `init`ed
        let state = sync_state(
            "g",
            vec![("alice", "eidalice", 1)],
            vec![(1, b"wrapA")],
            vec![("tok", 1, 1, b"nonce1")],
        );
        assert_eq!(
            s.secrets_needing_fetch(&state).unwrap(),
            vec!["tok".to_string()]
        );
        let fetched = vec![FetchedSecret {
            name: "tok".into(),
            version: 1,
            dek_version: 1,
            nonce: b"nonce1".to_vec(),
            ciphertext: b"ct".to_vec(),
            created_at: 5,
            created_by: "alice".into(),
        }];
        let changes = s.apply_group_sync("myid", &state, &fetched).unwrap();
        assert!(
            matches!(changes[..], [AppliedChange::SecretChanged { ref name, version: 1 }] if name == "tok"),
            "unexpected changes: {changes:?}"
        );
        let gid = s.group_id("g").unwrap().unwrap();
        assert_eq!(s.replica_group_names().unwrap(), vec!["g".to_string()]);
        let cur = s.secret_current(gid, "tok").unwrap().unwrap();
        assert_eq!(cur.ciphertext, b"ct");
        assert_eq!((cur.version, cur.dek_version), (1, 1));
        assert_eq!(cur.nonce, b"nonce1");
        // created_at / created_by are mirrored verbatim, not re-stamped.
        let (created_at, created_by): (i64, String) = s
            .conn
            .query_row(
                "SELECT sv.created_at, sv.created_by FROM secret s
                 JOIN secret_version sv ON sv.secret_id = s.id AND sv.version = s.current_version
                 WHERE s.group_id = ?1 AND s.name = ?2",
                params![gid, "tok"],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((created_at, created_by.as_str()), (5, "alice"));
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        assert!(!alice.service_admin);
        assert_eq!(alice.endpoint_id, "eidalice");
        assert_eq!(s.perms(alice.id, gid).unwrap(), 1);
        assert_eq!(s.dek_wrap(gid, 1, "myid").unwrap().unwrap(), b"wrapA");
        // Re-applying the same state fetches nothing and changes nothing.
        assert!(s.secrets_needing_fetch(&state).unwrap().is_empty());
        assert!(s.apply_group_sync("myid", &state, &[]).unwrap().is_empty());
        // ... and leaves the identity row itself in place (same rowid, so
        // no ACL row in any other group was cascaded away).
        assert_eq!(s.identity_by_name("alice").unwrap().unwrap().id, alice.id);
        assert_eq!(s.group_id("g").unwrap().unwrap(), gid);

        // A newer upstream version is fetched and replaces the old one.
        let state2 = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ | PERM_WRITE)],
            vec![(1, b"wrapA")],
            vec![("tok", 2, 1, b"nonce2")],
        );
        assert_eq!(
            s.secrets_needing_fetch(&state2).unwrap(),
            vec!["tok".to_string()]
        );
        let changes = s
            .apply_group_sync(
                "myid",
                &state2,
                &[fetched_secret("tok", 2, 1, b"nonce2", b"ct2")],
            )
            .unwrap();
        assert_eq!(
            changes,
            vec![AppliedChange::SecretChanged {
                name: "tok".into(),
                version: 2
            }]
        );
        let cur = s.secret_current(gid, "tok").unwrap().unwrap();
        assert_eq!((cur.version, cur.ciphertext), (2, b"ct2".to_vec()));
        assert_eq!(version_row_count(&s, gid, "tok"), 1);
        assert_eq!(s.perms(alice.id, gid).unwrap(), PERM_READ | PERM_WRITE);
    }

    /// The ABA case: same (version, dek_version), different nonce ⇒ refetch.
    #[test]
    fn nonce_mismatch_forces_replace() {
        let mut s = replica();
        let state = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w")],
            vec![("tok", 1, 1, b"nonce1")],
        );
        s.apply_group_sync(
            "myid",
            &state,
            &[fetched_secret("tok", 1, 1, b"nonce1", b"ct1")],
        )
        .unwrap();
        let gid = s.group_id("g").unwrap().unwrap();

        // Upstream deleted and recreated "tok": versions restart at 1 and
        // deletion does not rotate the DEK, so only the nonce differs.
        let recreated = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w")],
            vec![("tok", 1, 1, b"nonce2")],
        );
        assert_eq!(
            s.secrets_needing_fetch(&recreated).unwrap(),
            vec!["tok".to_string()]
        );
        let changes = s
            .apply_group_sync(
                "myid",
                &recreated,
                &[fetched_secret("tok", 1, 1, b"nonce2", b"ct2")],
            )
            .unwrap();
        assert_eq!(
            changes,
            vec![AppliedChange::SecretChanged {
                name: "tok".into(),
                version: 1
            }]
        );
        let cur = s.secret_current(gid, "tok").unwrap().unwrap();
        assert_eq!(cur.nonce, b"nonce2");
        assert_eq!(cur.ciphertext, b"ct2");
        // The old row went with its secret (one version row, not two).
        assert_eq!(version_row_count(&s, gid, "tok"), 1);
        assert!(s.secrets_needing_fetch(&recreated).unwrap().is_empty());
    }

    /// Absent-from-manifest secrets are deleted (rule 5).
    #[test]
    fn absent_secret_is_deleted() {
        let mut s = replica();
        let state = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w")],
            vec![("keep", 1, 1, b"n1"), ("gone", 1, 1, b"n2")],
        );
        s.apply_group_sync(
            "myid",
            &state,
            &[
                fetched_secret("keep", 1, 1, b"n1", b"c1"),
                fetched_secret("gone", 1, 1, b"n2", b"c2"),
            ],
        )
        .unwrap();
        let gid = s.group_id("g").unwrap().unwrap();

        let shrunk = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w")],
            vec![("keep", 1, 1, b"n1")],
        );
        assert!(s.secrets_needing_fetch(&shrunk).unwrap().is_empty());
        let changes = s.apply_group_sync("myid", &shrunk, &[]).unwrap();
        assert_eq!(
            changes,
            vec![AppliedChange::SecretDeleted {
                name: "gone".into()
            }]
        );
        assert!(s.secret_current(gid, "gone").unwrap().is_none());
        assert_eq!(version_row_count(&s, gid, "gone"), 0);
        assert!(s.secret_current(gid, "keep").unwrap().is_some());
        // An emptied group keeps the group row itself; only a manifest that
        // drops the group entirely does that (drop_group_local).
        let empty = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w")],
            vec![],
        );
        assert_eq!(
            s.apply_group_sync("myid", &empty, &[]).unwrap(),
            vec![AppliedChange::SecretDeleted {
                name: "keep".into()
            }]
        );
        assert_eq!(s.list_secrets(gid).unwrap(), vec![]);
        assert_eq!(s.replica_group_names().unwrap(), vec!["g".to_string()]);
    }

    /// A state-listed secret that was not fetched this round is left
    /// exactly as it is — rule 5 only deletes names the state omits, so a
    /// name the server did not ship (a mid-race vanish) is treated as
    /// locally unchanged rather than as a deletion.
    #[test]
    fn listed_but_unfetched_secret_is_left_alone() {
        let mut s = replica();
        let state = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w")],
            vec![("tok", 1, 1, b"n1")],
        );
        s.apply_group_sync("myid", &state, &[fetched_secret("tok", 1, 1, b"n1", b"c1")])
            .unwrap();
        let gid = s.group_id("g").unwrap().unwrap();

        let newer = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w")],
            vec![("tok", 2, 1, b"n2")],
        );
        assert_eq!(
            s.secrets_needing_fetch(&newer).unwrap(),
            vec!["tok".to_string()]
        );
        // The fetch came back empty (the server no longer had it).
        assert!(s.apply_group_sync("myid", &newer, &[]).unwrap().is_empty());
        let cur = s.secret_current(gid, "tok").unwrap().unwrap();
        assert_eq!((cur.version, cur.ciphertext), (1, b"c1".to_vec()));
    }

    /// Key replacement: stale local identity row with same name, different
    /// endpoint id, is deleted before upsert (rule 1) — no UNIQUE(name)
    /// livelock.
    #[test]
    fn identity_key_replacement_converges() {
        let mut s = replica();
        let st1 = sync_state("g", vec![("alice", "eid-old", 1)], vec![(1, b"w")], vec![]);
        s.apply_group_sync("myid", &st1, &[]).unwrap();
        let st2 = sync_state("g", vec![("alice", "eid-new", 1)], vec![(1, b"w")], vec![]);
        s.apply_group_sync("myid", &st2, &[]).unwrap();
        assert_eq!(
            s.identity_by_name("alice").unwrap().unwrap().endpoint_id,
            "eid-new"
        );
        assert!(
            s.identity_by_endpoint("eid-old").unwrap().is_none()
                || s.gc_unreferenced_identities().unwrap() >= 1
        );
        // The new key holds the ACL row, and it is the only one.
        let gid = s.group_id("g").unwrap().unwrap();
        let alice = s.identity_by_endpoint("eid-new").unwrap().unwrap();
        assert_eq!(s.perms(alice.id, gid).unwrap(), PERM_READ);
        assert_eq!(
            s.group_acl_entries(gid).unwrap(),
            vec![("alice".to_string(), PERM_READ)]
        );
        assert!(s.identity_by_endpoint("eid-old").unwrap().is_none());
        // A rename in place (same endpoint id, new name) converges too.
        let st3 = sync_state("g", vec![("alicia", "eid-new", 1)], vec![(1, b"w")], vec![]);
        s.apply_group_sync("myid", &st3, &[]).unwrap();
        assert!(s.identity_by_name("alice").unwrap().is_none());
        assert_eq!(
            s.identity_by_name("alicia").unwrap().unwrap().id,
            alice.id,
            "a rename must reuse the row, not reassign identity.id"
        );
    }

    /// A malformed state — one identity name under two endpoint ids —
    /// must converge, not wedge the group. Iterating rule 1 naively, the
    /// second entry's stale-name delete erases the row the first entry
    /// just upserted, and rule 2's lookup for that first entry then finds
    /// nothing: the apply rolls back, and every identical retry rolls back
    /// again. An authoritative node never emits such a state; a
    /// misbehaving or malicious one must not be able to freeze a group.
    #[test]
    fn duplicate_acl_entries_converge_on_the_last_one() {
        let mut s = replica();
        let state = sync_state(
            "g",
            vec![
                ("alice", "eid1", PERM_READ),
                ("alice", "eid2", PERM_READ | PERM_WRITE),
            ],
            vec![(1, b"w")],
            vec![],
        );
        s.apply_group_sync("myid", &state, &[]).unwrap();
        let gid = s.group_id("g").unwrap().unwrap();
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        assert_eq!(alice.endpoint_id, "eid2");
        assert!(s.identity_by_endpoint("eid1").unwrap().is_none());
        assert_eq!(
            s.group_acl_entries(gid).unwrap(),
            vec![("alice".to_string(), PERM_READ | PERM_WRITE)]
        );
        // And it stays converged: a retry is a no-op, not another rollback.
        assert!(s.apply_group_sync("myid", &state, &[]).unwrap().is_empty());
        assert_eq!(s.identity_by_name("alice").unwrap().unwrap().id, alice.id);

        // The mirror image — one endpoint id under two names — converges
        // on the last entry too.
        let two_names = sync_state(
            "g",
            vec![("bob", "eid2", PERM_READ), ("carol", "eid2", PERM_ADMIN)],
            vec![(1, b"w")],
            vec![],
        );
        s.apply_group_sync("myid", &two_names, &[]).unwrap();
        assert_eq!(
            s.group_acl_entries(gid).unwrap(),
            vec![("carol".to_string(), PERM_ADMIN)]
        );
        assert!(s.identity_by_name("bob").unwrap().is_none());
    }

    /// service_admin never set locally even if upstream lies; ACL replaced
    /// wholesale.
    #[test]
    fn acl_replaced_wholesale_and_no_service_admin() {
        let mut s = replica();
        let st1 = sync_state(
            "g",
            vec![
                ("alice", "eidalice", PERM_READ | PERM_WRITE),
                ("bob", "eidbob", PERM_READ),
            ],
            vec![(1, b"w")],
            vec![],
        );
        s.apply_group_sync("myid", &st1, &[]).unwrap();
        let gid = s.group_id("g").unwrap().unwrap();
        assert_eq!(
            s.group_acl_entries(gid).unwrap(),
            vec![
                ("alice".to_string(), PERM_READ | PERM_WRITE),
                ("bob".to_string(), PERM_READ),
            ]
        );
        assert!(!s.identity_by_name("alice").unwrap().unwrap().service_admin);
        assert!(!s.identity_by_name("bob").unwrap().unwrap().service_admin);

        // Even a locally set flag (nothing upstream can set it — AclEntry
        // carries no such field — but a stale row might) is cleared on the
        // next apply: a replica authorizes strictly by explicit ACL rows.
        assert!(s.set_service_admin("bob", true).unwrap());
        let st2 = sync_state(
            "g",
            vec![("bob", "eidbob", PERM_READ | PERM_WRITE | PERM_ADMIN)],
            vec![(1, b"w")],
            vec![],
        );
        s.apply_group_sync("myid", &st2, &[]).unwrap();
        assert_eq!(
            s.group_acl_entries(gid).unwrap(),
            vec![("bob".to_string(), PERM_READ | PERM_WRITE | PERM_ADMIN)]
        );
        let bob = s.identity_by_name("bob").unwrap().unwrap();
        assert!(!bob.service_admin);
        // Alice lost her only ACL row but keeps her identity row until the
        // end-of-resync sweep.
        let alice = s.identity_by_name("alice").unwrap().unwrap();
        assert_eq!(s.perms(alice.id, gid).unwrap(), 0);
        assert_eq!(s.gc_unreferenced_identities().unwrap(), 1);
        assert!(s.identity_by_name("alice").unwrap().is_none());
        assert!(s.identity_by_name("bob").unwrap().is_some());
        assert_eq!(s.gc_unreferenced_identities().unwrap(), 0);
    }

    /// Wrap blob replaced when it differs (restore-rewind), absent wraps
    /// deleted.
    #[test]
    fn wrap_blob_differs_is_replaced() {
        let mut s = replica();
        let st1 = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w1")],
            vec![],
        );
        s.apply_group_sync("myid", &st1, &[]).unwrap();
        let gid = s.group_id("g").unwrap().unwrap();
        assert_eq!(s.dek_wrap(gid, 1, "myid").unwrap().unwrap(), b"w1");

        // Same version, different blob: upstream reissued the DEK version
        // (an authoritative restore rewound it).
        let st2 = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w2"), (2, b"w2b")],
            vec![],
        );
        s.apply_group_sync("myid", &st2, &[]).unwrap();
        assert_eq!(s.dek_wrap(gid, 1, "myid").unwrap().unwrap(), b"w2");
        assert_eq!(s.dek_wrap(gid, 2, "myid").unwrap().unwrap(), b"w2b");
        assert_eq!(s.dek_versions(gid).unwrap(), vec![1, 2]);

        // A version the state no longer carries loses its wrap; the
        // group_dek row stays (the version exists upstream, we just hold
        // no wrap for it any more).
        let st3 = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(2, b"w2b")],
            vec![],
        );
        s.apply_group_sync("myid", &st3, &[]).unwrap();
        assert!(s.dek_wrap(gid, 1, "myid").unwrap().is_none());
        assert_eq!(s.dek_wrap(gid, 2, "myid").unwrap().unwrap(), b"w2b");
        assert_eq!(s.dek_versions(gid).unwrap(), vec![1, 2]);

        // Wraps addressed to anyone but this replica are not ours to keep.
        s.add_dek_wrap(gid, 2, RECIPIENT_OPERATIONAL, b"nope")
            .unwrap();
        s.apply_group_sync("myid", &st3, &[]).unwrap();
        assert!(s.dek_wrap(gid, 2, RECIPIENT_OPERATIONAL).unwrap().is_none());
        assert_eq!(s.dek_wrap(gid, 2, "myid").unwrap().unwrap(), b"w2b");
    }

    #[test]
    fn drop_group_removes_everything() {
        let mut s = replica();
        let state = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w")],
            vec![("tok", 1, 1, b"n1")],
        );
        s.apply_group_sync("myid", &state, &[fetched_secret("tok", 1, 1, b"n1", b"c1")])
            .unwrap();
        let other = sync_state(
            "h",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w")],
            vec![],
        );
        s.apply_group_sync("myid", &other, &[]).unwrap();
        let gid = s.group_id("g").unwrap().unwrap();

        assert!(s.drop_group_local("g").unwrap());
        assert!(s.group_id("g").unwrap().is_none());
        assert_eq!(s.replica_group_names().unwrap(), vec!["h".to_string()]);
        assert_eq!(s.list_secrets(gid).unwrap(), vec![]);
        assert_eq!(version_row_count(&s, gid, "tok"), 0);
        assert!(s.dek_wrap(gid, 1, "myid").unwrap().is_none());
        assert_eq!(s.dek_versions(gid).unwrap(), vec![]);
        assert_eq!(s.group_acl_entries(gid).unwrap(), vec![]);
        // The identity survives: it still holds a row in the other group.
        assert!(s.identity_by_name("alice").unwrap().is_some());
        assert_eq!(s.gc_unreferenced_identities().unwrap(), 0);
        assert!(s.drop_group_local("h").unwrap());
        assert_eq!(s.gc_unreferenced_identities().unwrap(), 1);
        assert!(s.identity_by_name("alice").unwrap().is_none());
        // Dropping a group that is not mirrored locally is not an error.
        assert!(!s.drop_group_local("g").unwrap());
        assert_eq!(s.replica_group_names().unwrap(), Vec::<String>::new());
    }

    /// One transaction per group, proven by fault injection: no legal
    /// input can fail mid-apply (every statement is an upsert or a
    /// delete), so the failure is manufactured with a trigger that aborts
    /// the `secret_version` insert of rule 4 — after rules 1-3 have
    /// already written. None of their writes may survive.
    #[test]
    fn a_failed_apply_rolls_the_whole_group_back() {
        let mut s = replica();
        let st1 = sync_state(
            "g",
            vec![("alice", "eidalice", PERM_READ)],
            vec![(1, b"w1")],
            vec![("tok", 1, 1, b"n1"), ("old", 1, 1, b"n2")],
        );
        s.apply_group_sync(
            "myid",
            &st1,
            &[
                fetched_secret("tok", 1, 1, b"n1", b"c1"),
                fetched_secret("old", 1, 1, b"n2", b"c2"),
            ],
        )
        .unwrap();
        let gid = s.group_id("g").unwrap().unwrap();
        let alice = s.identity_by_name("alice").unwrap().unwrap();

        s.conn
            .execute_batch(
                "CREATE TRIGGER injected BEFORE INSERT ON secret_version
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
            )
            .unwrap();
        // Touches every rule: new ACL member, new DEK version and wrap,
        // a new secret version, and a secret dropped from the listing.
        let st2 = sync_state(
            "g",
            vec![
                ("alice", "eidalice", PERM_READ | PERM_WRITE),
                ("bob", "eidbob", PERM_READ),
            ],
            vec![(2, b"w2")],
            vec![("tok", 2, 2, b"n3")],
        );
        assert!(
            s.apply_group_sync("myid", &st2, &[fetched_secret("tok", 2, 2, b"n3", b"c3")])
                .is_err()
        );

        assert_eq!(
            s.group_acl_entries(gid).unwrap(),
            vec![("alice".to_string(), PERM_READ)]
        );
        assert_eq!(s.perms(alice.id, gid).unwrap(), PERM_READ);
        assert!(s.identity_by_name("bob").unwrap().is_none());
        assert_eq!(s.dek_versions(gid).unwrap(), vec![1]);
        assert_eq!(s.dek_wrap(gid, 1, "myid").unwrap().unwrap(), b"w1");
        assert!(s.dek_wrap(gid, 2, "myid").unwrap().is_none());
        let cur = s.secret_current(gid, "tok").unwrap().unwrap();
        assert_eq!((cur.version, cur.ciphertext), (1, b"c1".to_vec()));
        assert!(s.secret_current(gid, "old").unwrap().is_some());

        // With the fault gone the very same state applies cleanly.
        s.conn.execute_batch("DROP TRIGGER injected").unwrap();
        let changes = s
            .apply_group_sync("myid", &st2, &[fetched_secret("tok", 2, 2, b"n3", b"c3")])
            .unwrap();
        assert_eq!(
            changes,
            vec![
                AppliedChange::SecretChanged {
                    name: "tok".into(),
                    version: 2
                },
                AppliedChange::SecretDeleted { name: "old".into() },
            ]
        );
        assert_eq!(s.dek_wrap(gid, 2, "myid").unwrap().unwrap(), b"w2");
        assert!(s.identity_by_name("bob").unwrap().is_some());
    }
}
