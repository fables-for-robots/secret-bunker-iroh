# SOPS-Style DEK Wrapping and Read-Only Replicas — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wrap every group DEK to each explicitly-read-granted identity (age recipient derived from its iroh EndpointId), auto-rotate on read revocation, and add read-only replicas that sync over a new `secret-bunker-sync/1` ALPN and serve reads while the authoritative node is down — embeddable as a library (`Replica`).

**Architecture:** Spec at `docs/superpowers/specs/2026-08-11-sops-replication-design.md` — read it before any task; it is normative. Three phases: (1) schema v2 + wrap lifecycle, (2) sync protocol + replica engine + replica serving, (3) CLI/library polish + docs. Serving on `secret-bunker/1` is unchanged except one additive `ReadOnlyReplica` response variant.

**Tech Stack:** Rust edition 2024, iroh 1.x (QUIC), age 0.11 (X25519), rusqlite (bundled SQLite), ciborium (CBOR), tokio. New deps: `ed25519-dalek = "3"`, `bech32 = "0.9"` (both already in the transitive tree).

## Global Constraints

- Workspace: `/Users/dragan/fables-for-robots/secret-bunker-iroh`, branch `sops-replication`. If `cargo` is missing from PATH, run commands inside `nix develop -c <cmd>`.
- `cargo test` must pass at the end of every task; `cargo fmt` and `cargo clippy --all-targets` clean before every commit.
- WIRE CONTRACT: never rename an existing `Request`/`Response` variant or field (`src/proto.rs:18-21`). Adding variants is fine. Any new wire type gets a golden CBOR vector test.
- The existing CLI test suite (`tests/cli.rs`) must pass **unchanged** — it is the regression net. `tests/e2e.rs` may be updated only where this plan says so.
- Never use `INSERT OR REPLACE` on the `identity` table (delete-and-reinsert cascades `group_acl` rows).
- Recipient strings in `dek_wrap`: `"operational"`, `"backup"`, or an EndpointId in lowercase hex exactly as stored in `identity.endpoint_id`.
- Commit after every task with a conventional message; end commit messages with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- The spec file is the tie-breaker for any ambiguity in this plan.

---

### Task 1: `agebridge` — derive age recipients/identities from iroh keys

**Files:**
- Create: `src/agebridge.rs`
- Modify: `src/lib.rs` (add `pub mod agebridge;`)
- Modify: `Cargo.toml` (add `bech32 = "0.9"`, `ed25519-dalek = "3"`)

**Interfaces:**
- Consumes: nothing project-internal.
- Produces:
  - `pub fn recipient_for_endpoint(id: &iroh::EndpointId) -> anyhow::Result<age::x25519::Recipient>`
  - `pub fn recipient_for_endpoint_hex(hex: &str) -> anyhow::Result<age::x25519::Recipient>` (parses the lowercase-hex form stored in `identity.endpoint_id`)
  - `pub fn identity_from_secret(secret: &iroh::SecretKey) -> anyhow::Result<age::x25519::Identity>`

- [ ] **Step 1: Add dependencies**

In `Cargo.toml` `[dependencies]` add:

```toml
bech32 = "0.9"
ed25519-dalek = "3"
```

- [ ] **Step 2: Write the failing tests**

Create `src/agebridge.rs` with module doc + tests (implementation stubs `todo!()` for now):

```rust
//! Ed25519 → X25519 bridge: every iroh EndpointId doubles as an age
//! recipient, and the corresponding iroh secret key yields the matching
//! age identity. No second keypair, no registration.
//!
//! The conversion is the birational Edwards→Montgomery map (public side)
//! and the SHA-512 scalar clamp (secret side) — the same construction as
//! ssh-to-age and libsodium's crypto_sign_ed25519_*_to_curve25519. Joint
//! security of signing + X25519 ECDH under one key is analyzed in
//! Thormarker, "On using the same key pair for Ed25519 and an X25519
//! based KEM", ePrint 2021/509. age 0.11 exposes only Bech32-string
//! constructors for x25519 types, hence the bech32 round-trips.
//! Deliberately NOT age's `ssh` feature: its ssh-ed25519 stanzas add an
//! HKDF tweak and would not interoperate with this native derivation.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn derived_identity_matches_derived_recipient() {
        let secret = iroh::SecretKey::generate();
        let recipient = recipient_for_endpoint(&secret.public()).unwrap();
        let identity = identity_from_secret(&secret).unwrap();
        assert_eq!(identity.to_public().to_string(), recipient.to_string());
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let secret = iroh::SecretKey::generate();
        let recipient = recipient_for_endpoint(&secret.public()).unwrap();
        let identity = identity_from_secret(&secret).unwrap();
        let ct = crate::crypto::age_encrypt(&recipient, b"payload").unwrap();
        let pt = crate::crypto::age_decrypt(&identity, &ct).unwrap();
        assert_eq!(pt, b"payload");
    }

    #[test]
    fn hex_form_matches_endpoint_form() {
        let secret = iroh::SecretKey::generate();
        let id = secret.public();
        let via_hex = recipient_for_endpoint_hex(&id.to_string()).unwrap();
        let via_id = recipient_for_endpoint(&id).unwrap();
        assert_eq!(via_hex.to_string(), via_id.to_string());
    }

    /// Golden vector: pins the derivation so it can never silently change.
    /// The recipient string below was produced by this very code at
    /// implementation time from the fixed seed; a mismatch later means the
    /// derivation changed and every stored wrap is unreadable.
    #[test]
    fn derivation_golden_vector() {
        let secret = iroh::SecretKey::from_bytes(&[7u8; 32]);
        let recipient = recipient_for_endpoint(&secret.public()).unwrap();
        // Filled in at implementation time (see Step 4).
        assert_eq!(recipient.to_string(), "GOLDEN");
        let identity = identity_from_secret(&secret).unwrap();
        assert_eq!(identity.to_public().to_string(), recipient.to_string());
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test agebridge`
Expected: compile error (functions missing) — add `todo!()` stubs first so it compiles, then FAIL.

- [ ] **Step 4: Implement**

```rust
use std::str::FromStr;

use age::secrecy::ExposeSecret as _;
use anyhow::{Context, Result};
use bech32::{ToBase32, Variant};

/// Anyone can compute this from a public EndpointId.
pub fn recipient_for_endpoint(id: &iroh::EndpointId) -> Result<age::x25519::Recipient> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(id.as_bytes())
        .context("EndpointId is not a valid ed25519 point")?;
    let montgomery = vk.to_montgomery();
    let encoded = bech32::encode("age", montgomery.as_bytes().to_base32(), Variant::Bech32)
        .context("bech32-encoding derived recipient")?;
    age::x25519::Recipient::from_str(&encoded).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn recipient_for_endpoint_hex(hex: &str) -> Result<age::x25519::Recipient> {
    let id: iroh::EndpointId = hex.parse().context("parsing endpoint id")?;
    recipient_for_endpoint(&id)
}

/// Only the holder of the iroh secret key can compute this.
pub fn identity_from_secret(secret: &iroh::SecretKey) -> Result<age::x25519::Identity> {
    let signing = ed25519_dalek::SigningKey::from_bytes(&secret.to_bytes());
    // The SHA-512-expanded scalar half; dalek documents it as the valid
    // X25519 StaticSecret for the converted public key (x25519 clamps
    // during ECDH).
    let scalar = signing.to_scalar_bytes();
    let encoded = bech32::encode("age-secret-key-", scalar.to_base32(), Variant::Bech32)
        .context("bech32-encoding derived identity")?
        .to_uppercase();
    age::x25519::Identity::from_str(&encoded).map_err(|e| anyhow::anyhow!("{e}"))
}
```

Notes for the implementer:
- `iroh::SecretKey::from_bytes(&[u8; 32])` and `EndpointId::as_bytes() -> &[u8; 32]` exist in iroh 1.x. If `VerifyingKey::to_montgomery()` returns a `MontgomeryPoint` without `as_bytes()`, use `.to_bytes()`.
- If the two dalek versions collide at compile time, remember: only byte arrays cross this module's boundary; use fully-qualified paths.
- For the golden vector: temporarily `eprintln!` the derived recipient for seed `[7u8; 32]` in the test, run `cargo test derivation_golden_vector -- --nocapture`, paste the printed `age1…` string over `"GOLDEN"`, re-run to green. The literal MUST be committed.

- [ ] **Step 5: Register module, run all tests**

Add `pub mod agebridge;` to `src/lib.rs` (alphabetical order). Run: `cargo test`
Expected: PASS (all pre-existing tests too).

- [ ] **Step 6: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets
git add -A && git commit -m "feat: derive age recipients/identities from iroh ed25519 keys"
```

---

### Task 2: Schema v2 — migration machinery + `dek_wrap` table

**Files:**
- Modify: `src/store.rs` (SCHEMA constant, `open`, `open_in_memory`, `init`; new migration fn; new/changed DEK accessors; delete old two-column accessors)
- Modify: `src/server.rs`, `src/main.rs` — only as far as needed to keep compiling (see Step 5)

**Interfaces:**
- Consumes: nothing new.
- Produces (all on `Store`):
  - `pub const RECIPIENT_OPERATIONAL: &str = "operational";` / `pub const RECIPIENT_BACKUP: &str = "backup";` (module-level consts in `store.rs`)
  - `pub fn current_dek_version(&self, group_id: i64) -> Result<u64>`
  - `pub fn dek_versions(&self, group_id: i64) -> Result<Vec<u64>>`
  - `pub fn dek_wrap(&self, group_id: i64, dek_version: u64, recipient: &str) -> Result<Option<Vec<u8>>>`
  - `pub fn add_dek(&mut self, group_id: i64, wraps: &[(String, Vec<u8>)]) -> Result<u64>` (one tx: next version row + all wrap rows)
  - `pub fn add_dek_wrap(&self, group_id: i64, dek_version: u64, recipient: &str, wrapped: &[u8]) -> Result<()>` (upsert)
  - `pub fn wraps_for_recipient(&self, group_id: i64, recipient: &str) -> Result<Vec<(u64, Vec<u8>)>>`
  - `pub fn all_wraps_for_recipient(&self, recipient: &str) -> Result<Vec<(i64, u64, Vec<u8>)>>` (`(group_id, dek_version, wrapped)`; recovery uses it with `"backup"`)
  - `pub fn create_group(&mut self, name: &str, wraps: &[(String, Vec<u8>)], creator_identity_id: i64, creator_perms: u8) -> Result<()>` (CHANGED signature)
  - `pub fn apply_recovery(&mut self, rewrapped: &[(i64, u64, Vec<u8>)], new_operational_pubkey: &str) -> Result<()>` (same signature, now updates `dek_wrap` rows with `recipient='operational'`)
  - The old `WrappedDek` struct, `current_dek`, `dek`, `all_deks` are **deleted**.

- [ ] **Step 1: Write failing store tests**

Append to `src/store.rs` tests (the existing `create_group` test helper changes in Step 4):

```rust
#[test]
fn dek_wrap_rows_roundtrip() {
    let mut s = store();
    let gid = create_group(&mut s, "g");
    assert_eq!(s.current_dek_version(gid).unwrap(), 1);
    assert_eq!(s.dek_versions(gid).unwrap(), vec![1]);
    assert_eq!(s.dek_wrap(gid, 1, RECIPIENT_OPERATIONAL).unwrap().unwrap(), b"op");
    assert_eq!(s.dek_wrap(gid, 1, RECIPIENT_BACKUP).unwrap().unwrap(), b"bk");
    assert!(s.dek_wrap(gid, 1, "aabbcc").unwrap().is_none());
    // A reader wrap:
    s.add_dek_wrap(gid, 1, "aabbcc", b"reader-wrap").unwrap();
    assert_eq!(s.dek_wrap(gid, 1, "aabbcc").unwrap().unwrap(), b"reader-wrap");
    assert_eq!(s.wraps_for_recipient(gid, "aabbcc").unwrap(), vec![(1, b"reader-wrap".to_vec())]);
    // New DEK version with a full wrap set:
    let v = s.add_dek(gid, &[
        (RECIPIENT_OPERATIONAL.into(), b"op2".to_vec()),
        (RECIPIENT_BACKUP.into(), b"bk2".to_vec()),
        ("aabbcc".into(), b"reader2".to_vec()),
    ]).unwrap();
    assert_eq!(v, 2);
    assert_eq!(s.current_dek_version(gid).unwrap(), 2);
    assert_eq!(s.dek_wrap(gid, 1, RECIPIENT_OPERATIONAL).unwrap().unwrap(), b"op");
}

#[test]
fn migration_v1_to_v2_moves_wrap_columns_to_rows() {
    // Build a real v1 database by hand, then open it through Store.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.sqlite");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(r#"
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
        "#).unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert_eq!(s.meta_get("schema_version").unwrap().unwrap(), "2");
    assert_eq!(s.meta_get("role").unwrap().unwrap(), "authoritative");
    let gid = s.group_id("g").unwrap().unwrap();
    assert_eq!(s.dek_versions(gid).unwrap(), vec![1, 2]);
    assert_eq!(s.dek_wrap(gid, 1, RECIPIENT_OPERATIONAL).unwrap().unwrap(), vec![0x01, 0x02]);
    assert_eq!(s.dek_wrap(gid, 2, RECIPIENT_BACKUP).unwrap().unwrap(), vec![0x07, 0x08]);
    // Old columns are gone.
    let cols: Vec<String> = {
        let mut stmt = s.conn.prepare("SELECT name FROM pragma_table_info('group_dek')").unwrap();
        stmt.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    assert!(!cols.contains(&"wrapped_operational".to_string()));
    // Reopening is idempotent.
    drop(s);
    let s = Store::open(&path).unwrap();
    assert_eq!(s.dek_versions(s.group_id("g").unwrap().unwrap()).unwrap(), vec![1, 2]);
}

#[test]
fn apply_recovery_updates_operational_wrap_rows() {
    let mut s = store();
    let g1 = create_group(&mut s, "g1");
    s.apply_recovery(&[(g1, 1, b"new-op".to_vec())], "age1new").unwrap();
    assert_eq!(s.dek_wrap(g1, 1, RECIPIENT_OPERATIONAL).unwrap().unwrap(), b"new-op");
    assert_eq!(s.dek_wrap(g1, 1, RECIPIENT_BACKUP).unwrap().unwrap(), b"bk");
    assert_eq!(s.meta_get("operational_pubkey").unwrap().unwrap(), "age1new");
    assert!(s.apply_recovery(&[(g1, 99, b"x".to_vec())], "age1x").is_err());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib store`  — Expected: compile errors (new API absent).

- [ ] **Step 3: New SCHEMA + migration**

Replace the `group_dek` block in `SCHEMA` and add `dek_wrap`:

```sql
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
```

(The spec sketches an FK to `group_dek`; the `secret_group` FK gives the same cascade-on-group-delete with a far simpler migration — DEK version rows are only ever deleted with their group. Deviation is deliberate.)

Add a migration step, called from `open` and `open_in_memory` **before** `execute_batch(SCHEMA)` (the old table must be detected before `IF NOT EXISTS` sees a same-named new one):

```rust
/// v1 → v2: group_dek's two wrap columns become dek_wrap rows.
fn migrate(conn: &Connection) -> Result<()> {
    let has_old_columns: bool = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('group_dek') WHERE name = 'wrapped_operational'",
        [], |r| r.get::<_, i64>(0),
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
    // Stamp the role on any initialized database that predates roles.
    let initialized: bool = conn
        .query_row("SELECT 1 FROM meta WHERE key = 'operational_pubkey'", [], |r| r.get::<_, i64>(0))
        .optional()?
        .is_some();
    if initialized {
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('role', 'authoritative') ON CONFLICT (key) DO NOTHING",
            [],
        )?;
    }
    Ok(())
}
```

In `open`/`open_in_memory`: run `migrate(&conn)?` **after** `foreign_keys=ON` but note the table-rebuild needs `PRAGMA foreign_keys=OFF` around it (SQLite forbids dropping a referenced parent otherwise); wrap: set `foreign_keys=OFF`, migrate, set `foreign_keys=ON`, then `execute_batch(SCHEMA)`. In `init`, write `('schema_version','2')` and `('role','authoritative')` instead of `'1'`.

- [ ] **Step 4: Replace the DEK accessors**

Delete `WrappedDek`, `current_dek`, `dek`, `all_deks`. Implement the accessors from the Interfaces block. Representative implementations:

```rust
pub const RECIPIENT_OPERATIONAL: &str = "operational";
pub const RECIPIENT_BACKUP: &str = "backup";

pub fn current_dek_version(&self, group_id: i64) -> Result<u64> {
    Ok(self.conn.query_row(
        "SELECT MAX(version) FROM group_dek WHERE group_id = ?1",
        [group_id], |r| r.get::<_, i64>(0),
    )? as u64)
}

pub fn dek_wrap(&self, group_id: i64, dek_version: u64, recipient: &str) -> Result<Option<Vec<u8>>> {
    Ok(self.conn.query_row(
        "SELECT wrapped FROM dek_wrap WHERE group_id = ?1 AND dek_version = ?2 AND recipient = ?3",
        params![group_id, dek_version as i64, recipient], |r| r.get(0),
    ).optional()?)
}

pub fn add_dek(&mut self, group_id: i64, wraps: &[(String, Vec<u8>)]) -> Result<u64> {
    let tx = self.conn.transaction()?;
    let next: i64 = tx.query_row(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM group_dek WHERE group_id = ?1",
        [group_id], |r| r.get(0),
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
    tx.commit()?;
    Ok(next as u64)
}
```

`add_dek_wrap` uses `INSERT … ON CONFLICT (group_id, dek_version, recipient) DO UPDATE SET wrapped = ?4`. `create_group` takes `wraps: &[(String, Vec<u8>)]` and inserts the version-1 row plus one `dek_wrap` row per entry inside its existing transaction. `apply_recovery` runs `UPDATE dek_wrap SET wrapped = ?3 WHERE group_id = ?1 AND dek_version = ?2 AND recipient = 'operational'` with the same `ensure!(n == 1)` per row.

- [ ] **Step 5: Mend the callers minimally**

Compilation fix-ups only (real lifecycle changes are Task 3):
- `src/server.rs` `unwrap_dek`: fetch `store.dek_wrap(group_id, version, store::RECIPIENT_OPERATIONAL)?` (treat `None` as error) and unwrap that.
- `src/server.rs` `put`: `let dek_version = store.current_dek_version(group_id)`; fetch the operational wrap for it.
- `src/server.rs` `create_group` / `rotate_dek`: build `wraps` vectors `[(RECIPIENT_OPERATIONAL, op_wrap), (RECIPIENT_BACKUP, bk_wrap)]` for now.
- `src/main.rs` `Recover`: iterate `store.all_wraps_for_recipient(store::RECIPIENT_BACKUP)?`, unwrap each with the backup identity, re-wrap to the new op recipient, call `apply_recovery` unchanged.
- `src/store.rs` test helper `create_group`: pass `&[(RECIPIENT_OPERATIONAL.into(), b"op".to_vec()), (RECIPIENT_BACKUP.into(), b"bk".to_vec())]`.
- `tests/e2e.rs` `recovery_rewraps_deks`: adjust to the new accessors (`all_wraps_for_recipient(RECIPIENT_BACKUP)`, `dek_wrap`). Keep its assertions' spirit identical.

- [ ] **Step 6: Run the full suite**

Run: `cargo test`
Expected: PASS, including the new migration test and the untouched `tests/cli.rs`.

- [ ] **Step 7: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets
git add -A && git commit -m "feat: schema v2 - per-recipient dek_wrap rows + migration machinery"
```

---

### Task 3: Wrap lifecycle — grant wraps, revoke auto-rotates, rotate wraps to readers

**Files:**
- Modify: `src/store.rs` (lifecycle helpers), `src/server.rs` (grant/rotate/create/remove paths, backfill)

**Interfaces:**
- Consumes: Task 1 (`agebridge::recipient_for_endpoint_hex`), Task 2 accessors.
- Produces (on `Store`):
  - `pub fn read_granted_identities(&self, group_id: i64) -> Result<Vec<Identity>>` (explicit READ bit holders)
  - `pub fn groups_with_read(&self, identity_id: i64) -> Result<Vec<i64>>`
  - `pub fn grant_with_wraps(&self, identity_id: i64, group_id: i64, perms: u8, wraps: &[(u64, Vec<u8>)], recipient: &str) -> Result<()>` — ACL upsert + wrap upserts, one tx (use an explicit `BEGIN`/`COMMIT` via `unchecked_transaction` since `&self`)
  - `pub fn revoke_read_and_rotate(&mut self, group_id: i64, target_identity_id: i64, new_perms: u8, revoked_recipient: &str, new_dek_wraps: &[(String, Vec<u8>)]) -> Result<u64>` — one tx: perms update/delete, `DELETE FROM dek_wrap WHERE group_id=? AND recipient=?`, new DEK version + wraps; returns the new version
  - `pub fn remove_identity_with_rotations(&mut self, name: &str, rotations: &[(i64, String, Vec<(String, Vec<u8>)>)]) -> Result<bool>` — `(group_id, revoked_recipient, new_wraps)` per group; identity delete + all rotations in ONE tx
  - `pub fn missing_reader_wraps(&self) -> Result<Vec<(i64, u64, String)>>` — `(group_id, dek_version, endpoint_id)` for every read-granted identity × retained DEK version lacking a wrap row
- Produces (on `Bunker`): `pub fn backfill_reader_wraps(&self) -> Result<usize>`

- [ ] **Step 1: Write failing server-level tests** (in `src/server.rs` `mod tests`; `test_bunker()` already exists)

```rust
/// Grant of read wraps every retained DEK version to the grantee's
/// derived recipient; revoke deletes them and rotates.
#[test]
fn grant_read_wraps_and_revoke_rotates() {
    let (bunker, admin) = test_bunker();
    assert_eq!(bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }), Response::Ok);
    // Two retained DEK versions before bob arrives.
    assert_eq!(bunker.handle(&admin, &Request::RotateDek { group: "g".into() }), Response::Ok);
    let bob_secret = iroh::SecretKey::generate();
    let bob = bob_secret.public().to_string();
    assert_eq!(bunker.handle(&admin, &Request::AddIdentity {
        name: "bob".into(), endpoint_id: bob.clone(), service_admin: false,
    }), Response::Ok);
    assert_eq!(bunker.handle(&admin, &Request::Grant {
        group: "g".into(), identity: "bob".into(), perms: crate::store::PERM_READ,
    }), Response::Ok);
    // Both versions wrapped to bob, and bob's derived identity can unwrap.
    let bob_identity = crate::agebridge::identity_from_secret(&bob_secret).unwrap();
    {
        let store = bunker.lock_store();
        let gid = store.group_id("g").unwrap().unwrap();
        for v in [1u64, 2] {
            let wrapped = store.dek_wrap(gid, v, &bob).unwrap().expect("wrap row exists");
            crate::crypto::unwrap_dek(&wrapped, &bob_identity).expect("bob can unwrap");
        }
        assert_eq!(store.current_dek_version(gid).unwrap(), 2);
    }
    // Revoke read: wraps deleted, DEK auto-rotated to version 3 without bob.
    assert_eq!(bunker.handle(&admin, &Request::Grant {
        group: "g".into(), identity: "bob".into(), perms: 0,
    }), Response::Ok);
    {
        let store = bunker.lock_store();
        let gid = store.group_id("g").unwrap().unwrap();
        assert_eq!(store.current_dek_version(gid).unwrap(), 3);
        for v in [1u64, 2, 3] {
            assert!(store.dek_wrap(gid, v, &bob).unwrap().is_none(), "v{v} wrap must be gone");
        }
        assert!(store.dek_wrap(gid, 3, crate::store::RECIPIENT_OPERATIONAL).unwrap().is_some());
        assert!(store.dek_wrap(gid, 3, crate::store::RECIPIENT_BACKUP).unwrap().is_some());
    }
}

/// A write-only grant creates no wraps; upgrading to rw does.
#[test]
fn write_only_grant_creates_no_wraps() { /* same skeleton: grant w, assert no wrap row; grant rw, assert wrap rows */ }

/// RemoveIdentity rotates every group the identity could read, atomically.
#[test]
fn remove_identity_rotates_all_readable_groups() { /* create two groups, grant bob read on both, RemoveIdentity, assert both rotated + wraps gone */ }

/// CreateGroup wraps to operational + backup + creator.
#[test]
fn create_group_wraps_to_creator() {
    let (bunker, admin) = test_bunker();
    assert_eq!(bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }), Response::Ok);
    let store = bunker.lock_store();
    let gid = store.group_id("g").unwrap().unwrap();
    assert!(store.dek_wrap(gid, 1, &admin).unwrap().is_some());
}

/// Manual RotateDek wraps the new version to every current reader.
#[test]
fn rotate_dek_wraps_to_readers() { /* grant bob read, RotateDek, assert v2 wrapped to bob + op + backup */ }

/// Backfill creates missing reader wraps idempotently.
#[test]
fn backfill_creates_missing_wraps() {
    let (bunker, admin) = test_bunker();
    assert_eq!(bunker.handle(&admin, &Request::CreateGroup { name: "g".into() }), Response::Ok);
    // Simulate a pre-redesign grant: ACL row without wraps.
    {
        let store = bunker.lock_store();
        let gid = store.group_id("g").unwrap().unwrap();
        let admin_ident = store.identity_by_endpoint(&admin).unwrap().unwrap();
        // admin (creator) already has wraps; add a raw ACL row for a fresh identity
        store.add_identity("carol", &iroh::SecretKey::generate().public().to_string(), false).unwrap();
        let carol = store.identity_by_name("carol").unwrap().unwrap();
        store.set_perms(carol.id, gid, crate::store::PERM_READ).unwrap();
        let _ = admin_ident;
    }
    let n = bunker.backfill_reader_wraps().unwrap();
    assert_eq!(n, 1);
    assert_eq!(bunker.backfill_reader_wraps().unwrap(), 0, "idempotent");
}
```

Make `lock_store` `pub(crate)` so tests can inspect. Fill the two skeleton tests with the same explicit style as the first.

- [ ] **Step 2: Run to verify failure** — `cargo test --lib server` → FAIL/compile error.

- [ ] **Step 3: Implement the server lifecycle**

- Helper on `Bunker` (associated fn in `server.rs`):

```rust
/// Wrap `dek` to operational + backup + every explicit reader of the group.
fn wrap_set_for_group(inner: &Inner, store: &Store, group_id: i64, dek: &crypto::Dek,
                      exclude_endpoint: Option<&str>) -> Result<Vec<(String, Vec<u8>)>> {
    let mut wraps = vec![
        (crate::store::RECIPIENT_OPERATIONAL.to_string(), crypto::wrap_dek(dek, &inner.op_recipient)?),
        (crate::store::RECIPIENT_BACKUP.to_string(), crypto::wrap_dek(dek, &inner.backup_recipient)?),
    ];
    for reader in store.read_granted_identities(group_id)? {
        if Some(reader.endpoint_id.as_str()) == exclude_endpoint { continue; }
        let recipient = crate::agebridge::recipient_for_endpoint_hex(&reader.endpoint_id)?;
        wraps.push((reader.endpoint_id, crypto::wrap_dek(dek, &recipient)?));
    }
    Ok(wraps)
}
```

- `create_group`: generate DEK, `wrap_set_for_group` won't work pre-creation — build the three wraps directly (op, backup, creator via `recipient_for_endpoint_hex(&ident.endpoint_id)`); pass to the new `store.create_group(name, &wraps, ident.id, PERM_RWA)`.
- `grant`: after the existing guards, branch on read-bit transitions (`had = current & PERM_READ`, `wants = perms & PERM_READ`):
  - gaining read: for every `store.dek_versions(group_id)?` version, fetch op wrap, `crypto::unwrap_dek`, `crypto::wrap_dek` to the target's derived recipient, collect `(version, wrapped)`; call `store.grant_with_wraps(target.id, group_id, perms, &wraps, &target.endpoint_id)`.
  - losing read (including `perms == 0`): generate new DEK, `wrap_set_for_group(…, exclude_endpoint: Some(&target.endpoint_id))`, call `store.revoke_read_and_rotate(group_id, target.id, perms, &target.endpoint_id, &new_wraps)`; append an extra audit entry `(remote, "rotate-dek", group, "ok")` after the main one (do it inside `grant` via a second `store.audit` call — acceptable, mirrors how `handle` audits).
  - neither: plain `store.set_perms` as today.
- `rotate_dek`: generate DEK, `wrap_set_for_group(…, None)`, `store.add_dek(group_id, &wraps)`.
- `remove_identity`: before deleting, collect `store.groups_with_read(target.id)`; for each, generate a DEK + `wrap_set_for_group(…, exclude Some(target.endpoint_id))`; call `store.remove_identity_with_rotations(name, &rotations)`.
- `backfill_reader_wraps`: loop `store.missing_reader_wraps()?`; for each `(gid, ver, endpoint)`: unwrap op wrap of that version, wrap to derived recipient, `store.add_dek_wrap`. Return count.
- Store lifecycle helpers per the Interfaces block. `missing_reader_wraps` SQL:

```sql
SELECT a.group_id, d.version, i.endpoint_id
FROM group_acl a
JOIN identity i ON i.id = a.identity_id
JOIN group_dek d ON d.group_id = a.group_id
LEFT JOIN dek_wrap w ON w.group_id = a.group_id AND w.dek_version = d.version AND w.recipient = i.endpoint_id
WHERE (a.perms & 1) != 0 AND w.recipient IS NULL
```

- [ ] **Step 4: Run the full suite** — `cargo test` → PASS (existing e2e revocation tests still pass: revocation is still ACL-instant).

- [ ] **Step 5: Wire backfill into serve + `db grant`**

In `src/main.rs` `Cmd::Serve` (authoritative path): after `Bunker::new`, before `Router::builder`: `let n = bunker.backfill_reader_wraps()?; if n > 0 { eprintln!("backfilled {n} reader DEK wrap(s)"); }`.
In `DbCmd::Grant`: add `#[arg(long)] operational_key: Option<PathBuf>` to the `Grant` variant. After parsing perms, branch exactly like the server: gaining read → resolve op key via `resolve_operational_key(operational_key)?`, verify it against `meta operational_pubkey`, build wraps, `grant_with_wraps`; losing read → generate DEK + wrap set (public keys only — parse `operational_pubkey`/`backup_pubkey` from meta with `keys::parse_age_recipient`, derive reader recipients) + `revoke_read_and_rotate`; audit `db-grant` (and `rotate-dek` when rotating) as today.

- [ ] **Step 6: fmt, clippy, full test, commit**

```bash
cargo fmt && cargo clippy --all-targets && cargo test
git add -A && git commit -m "feat: SOPS-style wrap lifecycle - grant wraps, revoke auto-rotates"
```

---

### Task 4: `ReadOnlyReplica` response variant + exit code 4

**Files:**
- Modify: `src/proto.rs` (variant + golden vector), `src/main.rs` (exit code; find the match on `Response` in the client-command runner that exits 2 on `VersionConflict` and 3 on `Denied`), `src/tui.rs` (`show_response` match)

**Interfaces:**
- Produces: `Response::ReadOnlyReplica { authoritative: String }` (EndpointId hex of the authoritative node). CLI exit code **4**; message `read-only replica; write to <authoritative>` on stderr.

- [ ] **Step 1: Failing golden-vector test** — add to `wire_format_is_stable` cases:

```rust
(
    encode(&Response::ReadOnlyReplica { authoritative: "ab".into() }).unwrap(),
    "GOLDEN_HEX",
),
```

Compute the hex the same way as the derivation golden vector: temporarily print, paste, re-run. (It is deterministic CBOR: map { "ReadOnlyReplica": { "authoritative": "ab" } }.)

- [ ] **Step 2: Implement** — add the variant after `Failed` in `Response` with doc comment `/// The node is a read-only replica; mutations must go to the authoritative bunker. Sent only to registered identities.`; handle it in `src/main.rs`'s response handling (`eprintln!` + `std::process::exit(4)`) and in `src/tui.rs`'s `show_response` (status line `read-only replica — write to {authoritative}`).

- [ ] **Step 3: Test, fmt, clippy, commit**

```bash
cargo test && cargo fmt && cargo clippy --all-targets
git add -A && git commit -m "feat: additive ReadOnlyReplica response variant, CLI exit code 4"
```

---

### Task 5: Sync wire protocol module

**Files:**
- Create: `src/sync.rs`
- Modify: `src/lib.rs` (add `pub mod sync;`)

**Interfaces:**
- Consumes: nothing project-internal (pure types + framing).
- Produces:

```rust
pub const SYNC_ALPN: &[u8] = b"secret-bunker-sync/1";
/// Strictly above the client protocol's 4 MiB MAX_MSG so any legal secret
/// fits one SecretData frame (ciphertext = plaintext + 16B tag + metadata).
pub const SYNC_MAX_MSG: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncRequest {
    Hello,
    FetchGroup { group: String },
    FetchSecrets { group: String, names: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncMessage {
    /// Uniform denial: unregistered peer, unauthorized or unknown group.
    SyncDenied,
    Group { name: String, acl: Vec<AclEntry>, deks: Vec<DekEntry> },
    GroupSecrets { group: String, secrets: Vec<SecretEntry> },
    ManifestDone,
    FetchDone,
    Changed { group: String },
    ScopeChanged,
    SecretData {
        name: String,
        version: u64,
        dek_version: u64,
        #[serde(with = "serde_bytes")] nonce: Vec<u8>,
        #[serde(with = "serde_bytes")] ciphertext: Vec<u8>,
        created_at: i64,
        created_by: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AclEntry { pub identity_name: String, pub endpoint_id: String, pub perms: u8 }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DekEntry { pub version: u64, #[serde(with = "serde_bytes")] pub wrapped: Vec<u8> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEntry { pub name: String, pub current_version: u64, pub dek_version: u64, #[serde(with = "serde_bytes")] pub nonce: Vec<u8> }

pub async fn write_msg<T: serde::Serialize>(send: &mut iroh::endpoint::SendStream, msg: &T) -> anyhow::Result<()>;
/// Ok(None) on clean end-of-stream before a length prefix.
pub async fn read_msg<T: serde::de::DeserializeOwned>(recv: &mut iroh::endpoint::RecvStream) -> anyhow::Result<Option<T>>;
```

- [ ] **Step 1: Failing tests** — module tests: (a) encode/decode roundtrip for every variant; (b) golden vectors for `SyncRequest::Hello`, `FetchGroup{group:"g"}`, `SyncMessage::SyncDenied`, `Changed{group:"g"}`, and a `SecretEntry`-bearing `GroupSecrets` (compute-print-paste as in Task 4); (c) framing: `write_msg` then `read_msg` over an in-memory buffer — since iroh streams aren't unit-testable, split framing into sync helpers `frame(msg) -> Vec<u8>` (4-byte BE length + CBOR) and `deframe(&[u8]) -> (T, rest)` used by the async fns, and test those: length prefix correct, oversize (> SYNC_MAX_MSG) rejected with an error mentioning "frame".

- [ ] **Step 2: Implement.** `write_msg`: `let body = proto::encode(msg)?; anyhow::ensure!(body.len() <= SYNC_MAX_MSG, "sync frame {} exceeds cap", body.len()); send.write_all(&(body.len() as u32).to_be_bytes()).await?; send.write_all(&body).await?;`. `read_msg`: read exactly 4 bytes (a clean EOF on the first byte → `Ok(None)`; use `recv.read_exact` and match its error), validate length ≤ SYNC_MAX_MSG, read exactly that many, decode.

- [ ] **Step 3: Test, fmt, clippy, commit**

```bash
cargo test sync && cargo test && cargo fmt && cargo clippy --all-targets
git add -A && git commit -m "feat: secret-bunker-sync/1 wire protocol - framed CBOR messages"
```

---

### Task 6: Authoritative sync handler — manifest, fetch, push

**Files:**
- Modify: `src/server.rs` (broadcast infra + `SyncServer` handler + snapshot helpers), `src/store.rs` (manifest queries), `src/main.rs` (mount the ALPN)

**Interfaces:**
- Consumes: Task 5 types/framing; Task 2/3 store accessors.
- Produces:
  - `Store::read_scope(&self, identity_id: i64) -> Result<Vec<(i64, String)>>` — `(group_id, group_name)` with explicit READ
  - `Store::acl_entries_full(&self, group_id: i64) -> Result<Vec<(String, String, u8)>>` — `(identity_name, endpoint_id, perms)`
  - `Store::secret_entries(&self, group_id: i64) -> Result<Vec<(String, u64, u64, Vec<u8>)>>` — `(name, current_version, dek_version, nonce)` of current versions
  - `Store::secret_data_current(&self, group_id: i64, name: &str) -> Result<Option<(u64, u64, Vec<u8>, Vec<u8>, i64, String)>>` — `(version, dek_version, nonce, ciphertext, created_at, created_by)`
  - `Bunker::sync_handler(&self) -> SyncServer` — `SyncServer` is `Clone + ProtocolHandler`, shares the Bunker's `Inner`
  - `Bunker` publishes to `tokio::sync::broadcast::Sender<String>` (group name) after every successful mutation; capacity 1024.

- [ ] **Step 1: Add the broadcast sender.** `Inner` gains `events: tokio::sync::broadcast::Sender<String>` (created in `Bunker::new` via `broadcast::channel(1024).0`). In `handle`, after a non-`Denied`/non-`Failed`/non-conflict outcome, publish the touched group(s): `Get`/`List`/list-ops publish nothing; `Put`/`Delete`/`RotateDek`/`CreateGroup`/`Grant` publish their group; `RemoveIdentity` publishes every group it rotated (collect the names in `remove_identity`'s path — return them via a thread-local is ugly; instead move the publish INTO the mutating handlers by passing `&Inner` where needed, or simplest: recompute in `handle` via a `fn touched_groups(req: &Request) -> Option<String>` for the single-group ops and give `remove_identity` + `set_service_admin` a conservative broadcast of a scope-recheck marker — send the literal group name for single-group ops; for `RemoveIdentity`/`SetServiceAdmin`/`AddIdentity` send one event per group in the store (cheap: names only) so sessions re-diff their scope). Keep it simple and correct: over-notification is only wasted work, under-notification is a bug.

- [ ] **Step 2: Failing e2e test scaffolding.** In `tests/e2e.rs`, add a two-node helper next to the existing single-node one (follow the file's existing endpoint/Router pattern, Minimal preset):

```rust
/// Authoritative router serving both ALPNs.
async fn spawn_authoritative(store: Store, op: age::x25519::Identity) -> (Router, EndpointAddr) {
    let bunker = Bunker::new(store, op).unwrap();
    let endpoint = /* same builder as existing tests */;
    let router = Router::builder(endpoint)
        .accept(secret_bunker_iroh::proto::ALPN, bunker.clone())
        .accept(secret_bunker_iroh::sync::SYNC_ALPN, bunker.sync_handler())
        .spawn();
    /* return router + its EndpointAddr as the existing helper does */
}
```

First test drives the sync protocol RAW (no replica engine yet): connect with a granted reader's key on `SYNC_ALPN`, open a bi stream, `write_msg(Hello)`, read messages until `ManifestDone`, assert one `Group{name:"g", ..}` with the caller's wrap in `deks` and one `GroupSecrets` listing the secret put beforehand; then on a second stream `FetchSecrets{group:"g", names:[the name]}` → one `SecretData` (decrypt it with the reader's derived identity + `crypto::secret_aad` to prove end-to-end correctness) + `FetchDone`. Also: unregistered key → `Hello` answered by `SyncDenied`; registered-no-grants → immediate `ManifestDone` (empty manifest); write-only identity → `SyncDenied` on `FetchGroup`. Then a push test: keep the session stream open, `Put` a new secret via the client ALPN, expect `Changed{group:"g"}` within a timeout; `Grant` the reader a second group → expect `ScopeChanged`.

- [ ] **Step 3: Implement `SyncServer`.**

```rust
#[derive(Clone)]
pub struct SyncServer(Arc<Inner>);
impl Bunker { pub fn sync_handler(&self) -> SyncServer { SyncServer(self.0.clone()) } }

impl ProtocolHandler for SyncServer {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id().to_string();
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await { Ok(p) => p, Err(_) => break };
            let inner = self.0.clone();
            let remote = remote.clone();
            // One task per stream so a long-lived session doesn't block fetches.
            tokio::spawn(async move {
                let _ = handle_sync_stream(inner, remote, &mut send, &mut recv).await;
                let _ = send.finish();
            });
        }
        Ok(())
    }
}
```

`handle_sync_stream`: `read_msg::<SyncRequest>` then match:
- `Hello`: **subscribe first** (`let mut rx = inner.events.subscribe();`), then resolve identity (unknown → `write_msg(SyncDenied)`, return). Snapshot scope + each group's manifest **one lock acquisition per group** (lock, read `acl_entries_full` + `dek_versions` + per-version `dek_wrap(gid, v, &remote)` + `secret_entries`, unlock, send `Group` then `GroupSecrets` chunks of ≤ 1000 entries). `ManifestDone`. Then the push loop: `rx.recv().await`; debounce by draining further events for 200 ms (`tokio::time::timeout` on subsequent `recv`); recompute scope under the lock; if the scope's group-name set changed vs the cached one (or `RecvError::Lagged`) → `write_msg(ScopeChanged)` and continue with the new cache; else for each drained event group in scope → `write_msg(Changed{group})` (dedup within the batch). Exit on any write error (stream closed).
- `FetchGroup { group }`: resolve identity + explicit READ on that group (NO service-admin bypass — call `store.perms` directly, not `authorize_group`) else `SyncDenied`. Snapshot as above; send `Group`, `GroupSecrets`*, `FetchDone`.
- `FetchSecrets { group, names }`: authorize the same way; for each name, `secret_data_current` — existing → `SecretData`, missing → silently skip; `FetchDone`.
- Audit each sync stream once: op `"sync-hello"` / `"sync-fetch-group"` / `"sync-fetch-secrets"`, target group name (empty for Hello), outcome `"ok"`/`"denied"`.

- [ ] **Step 4: Mount in `main.rs` serve** — `.accept(secret_bunker_iroh::sync::SYNC_ALPN, bunker.sync_handler())` on the Router builder (after backfill, which already runs before the router spawns).

- [ ] **Step 5: Run, fmt, clippy, commit**

```bash
cargo test && cargo fmt && cargo clippy --all-targets
git add -A && git commit -m "feat: authoritative sync handler - manifest, fetch, live push"
```

---

### Task 7: Replica store — apply rules

**Files:**
- Modify: `src/store.rs` (replica apply + role helpers)

**Interfaces:**
- Consumes: Task 5 types (`AclEntry`, `DekEntry`, `SecretEntry`, `SecretData` fields).
- Produces (on `Store`):
  - `pub struct GroupSyncState { pub name: String, pub acl: Vec<crate::sync::AclEntry>, pub deks: Vec<crate::sync::DekEntry>, pub secrets: Vec<crate::sync::SecretEntry> }` (defined in `store.rs` or `sync.rs`; pick `sync.rs`)
  - `pub struct FetchedSecret { pub name: String, pub version: u64, pub dek_version: u64, pub nonce: Vec<u8>, pub ciphertext: Vec<u8>, pub created_at: i64, pub created_by: String }`
  - `pub fn secrets_needing_fetch(&self, state: &GroupSyncState) -> Result<Vec<String>>` — names whose local `(current_version, dek_version, nonce)` differs or that are absent locally
  - `pub fn apply_group_sync(&mut self, own_endpoint: &str, state: &GroupSyncState, fetched: &[FetchedSecret]) -> Result<Vec<AppliedChange>>` — ONE transaction implementing spec 4.4 rules 1–5; `AppliedChange` is `pub enum AppliedChange { SecretChanged { name: String, version: u64 }, SecretDeleted { name: String } }`
  - `pub fn drop_group_local(&mut self, name: &str) -> Result<bool>`
  - `pub fn gc_unreferenced_identities(&self) -> Result<usize>`
  - `pub fn replica_group_names(&self) -> Result<Vec<String>>`

- [ ] **Step 1: Failing tests** — direct store tests (no network):

```rust
fn sync_state(name: &str, acl: Vec<(&str, &str, u8)>, deks: Vec<(u64, &[u8])>,
              secrets: Vec<(&str, u64, u64, &[u8])>) -> GroupSyncState { /* build the struct */ }

#[test]
fn apply_group_sync_creates_and_updates() {
    let mut s = Store::open_in_memory().unwrap(); // replica stores are never `init`ed
    let state = sync_state("g", vec![("alice", "eidalice", 1)], vec![(1, b"wrapA")],
                           vec![("tok", 1, 1, b"nonce1")]);
    assert_eq!(s.secrets_needing_fetch(&state).unwrap(), vec!["tok".to_string()]);
    let fetched = vec![FetchedSecret { name: "tok".into(), version: 1, dek_version: 1,
        nonce: b"nonce1".to_vec(), ciphertext: b"ct".to_vec(), created_at: 5, created_by: "alice".into() }];
    let changes = s.apply_group_sync("myid", &state, &fetched).unwrap();
    assert!(matches!(changes[..], [AppliedChange::SecretChanged { ref name, version: 1 }] if name == "tok"));
    let gid = s.group_id("g").unwrap().unwrap();
    assert_eq!(s.secret_current(gid, "tok").unwrap().unwrap().ciphertext, b"ct");
    let alice = s.identity_by_name("alice").unwrap().unwrap();
    assert!(!alice.service_admin);
    assert_eq!(s.perms(alice.id, gid).unwrap(), 1);
    assert_eq!(s.dek_wrap(gid, 1, "myid").unwrap().unwrap(), b"wrapA");
    // Re-applying the same state fetches nothing and changes nothing.
    assert!(s.secrets_needing_fetch(&state).unwrap().is_empty());
    assert!(s.apply_group_sync("myid", &state, &[]).unwrap().is_empty());
}

/// The ABA case: same (version, dek_version), different nonce ⇒ refetch.
#[test]
fn nonce_mismatch_forces_replace() { /* apply v1 nonce1, then state with nonce2: secrets_needing_fetch = [name]; apply with new ciphertext; assert replaced */ }

/// Absent-from-manifest secrets are deleted (rule 5).
#[test]
fn absent_secret_is_deleted() { /* apply with secret, apply again with empty secrets vec, expect SecretDeleted + gone */ }

/// Key replacement: stale local identity row with same name, different
/// endpoint id, is deleted before upsert (rule 1) — no UNIQUE(name) livelock.
#[test]
fn identity_key_replacement_converges() {
    let mut s = Store::open_in_memory().unwrap();
    let st1 = sync_state("g", vec![("alice", "eid-old", 1)], vec![(1, b"w")], vec![]);
    s.apply_group_sync("myid", &st1, &[]).unwrap();
    let st2 = sync_state("g", vec![("alice", "eid-new", 1)], vec![(1, b"w")], vec![]);
    s.apply_group_sync("myid", &st2, &[]).unwrap();
    assert_eq!(s.identity_by_name("alice").unwrap().unwrap().endpoint_id, "eid-new");
    assert!(s.identity_by_endpoint("eid-old").unwrap().is_none()
        || s.gc_unreferenced_identities().unwrap() >= 1);
}

/// service_admin never set locally even if upstream lies; ACL replaced wholesale.
#[test]
fn acl_replaced_wholesale_and_no_service_admin() { /* two applies with different ACLs; assert exact rows; assert service_admin false always */ }

/// Wrap blob replaced when it differs (restore-rewind), absent wraps deleted.
#[test]
fn wrap_blob_differs_is_replaced() { /* apply (1, b"w1"), re-apply (1, b"w2"): dek_wrap == b"w2" */ }

#[test]
fn drop_group_removes_everything() { /* apply, drop_group_local("g"), assert group/secret/wrap gone */ }
```

- [ ] **Step 2: Run to fail**, **Step 3: Implement.** `apply_group_sync` outline (one `self.conn.transaction()`):
1. Upsert group row by name (INSERT if absent).
2. Rule 1 identities: for each `AclEntry`: `DELETE FROM identity WHERE name = ?1 AND endpoint_id <> ?2`; then `INSERT INTO identity (endpoint_id, name, service_admin, created_at) VALUES (?, ?, 0, now) ON CONFLICT (endpoint_id) DO UPDATE SET name = excluded.name` (service_admin stays 0 — never copied).
3. Rule 2: `DELETE FROM group_acl WHERE group_id = ?`; insert rows from the state.
4. Rule 3: upsert `group_dek` version rows; upsert `dek_wrap (group_id, v, own_endpoint, wrapped)` replacing differing blobs; `DELETE FROM dek_wrap WHERE group_id = ? AND dek_version NOT IN (state versions)`.
5. Rule 4: for each `FetchedSecret`: `DELETE FROM secret WHERE group_id = ? AND name = ?` (cascade), insert `secret` with `current_version = version` and one `secret_version` row with the exact fetched fields; record `SecretChanged`.
6. Rule 5: `DELETE` local secrets whose names are absent from `state.secrets` (collect names first for `SecretDeleted` events).
Commit, return changes.

- [ ] **Step 4: `cargo test`, fmt, clippy, commit**

```bash
git add -A && git commit -m "feat: replica-side sync apply rules"
```

---

### Task 8: Replica engine + library API (`Replica`)

**Files:**
- Create: `src/replica.rs`
- Modify: `src/lib.rs` (add `pub mod replica;`)

**Interfaces:**
- Consumes: Tasks 1, 5, 7; `agebridge::identity_from_secret`; `Client`-style endpoint building (`src/client.rs:20-28` pattern).
- Produces:

```rust
pub struct Replica { /* Arc<ReplicaInner> */ }
pub struct ReplicaBuilder { /* store_path, secret_key, authoritative, endpoint */ }

#[derive(Debug, Clone)]
pub enum ReplicaEvent {
    SecretChanged { group: String, name: String, version: u64 },
    SecretDeleted { group: String, name: String },
    GroupAdded { group: String },
    GroupRemoved { group: String },
    Connected,
    Disconnected,
}

#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub connected: bool,
    pub last_synced: Option<std::time::SystemTime>,
    pub groups: Vec<String>,
    pub authoritative: iroh::EndpointId,
}

impl Replica {
    pub fn builder() -> ReplicaBuilder;
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ReplicaEvent>;
    pub fn get(&self, group: &str, name: &str) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>>;
    pub fn list(&self, group: &str) -> anyhow::Result<Vec<(String, u64)>>;
    pub fn groups(&self) -> anyhow::Result<Vec<String>>;
    pub fn status(&self) -> SyncStatus;
    pub fn protocol_handler(&self) -> ReplicaServer;   // Task 9 fills this in
    pub async fn shutdown(self);
}
impl ReplicaBuilder {
    pub fn store_path(self, p: impl Into<std::path::PathBuf>) -> Self;
    pub fn secret_key(self, k: iroh::SecretKey) -> Self;
    pub fn authoritative(self, id: iroh::EndpointId) -> Self;
    pub fn endpoint(self, ep: iroh::Endpoint) -> Self;    // optional; else binds its own (N0 + mdns resolve)
    pub async fn spawn(self) -> anyhow::Result<Replica>;
}
```

- [ ] **Step 1: Failing e2e test** (in `tests/e2e.rs`, using Task 6's `spawn_authoritative`): create groups `g1`,`g2`; register replica identity, grant read on `g1` only; put `s1` in `g1`, `sx` in `g2`; `Replica::builder()…spawn()`; subscribe; await `GroupAdded{g1}` + `SecretChanged{g1,s1,1}` (with timeout); assert `replica.get("g1","s1")` == plaintext, `replica.get("g2","sx")` errors, `replica.groups() == ["g1"]`, `status().connected`. Then live push: `Put` `s2` on the authoritative node → await `SecretChanged{g1,s2,1}` → `get` returns it. Then revoke `g1` → await `GroupRemoved{g1}` → `groups()` empty. Then delete/recreate ABA: put `aba` v1, wait for the event, kill nothing but `Delete` + re-`Put` (same version 1, same DEK) quickly, await the second `SecretChanged` and assert `get` returns the NEW value (nonce discriminator at work; a mutation-while-streaming case is covered implicitly by the event-after-commit contract). Finally `shutdown()`.

- [ ] **Step 2: Implement.** `spawn()`:
1. Open `Store` at `store_path` (runs migration). Role checks: `meta role` absent → stamp `role=replica`, `authoritative=<id>`, `replica_endpoint_id=<secret.public()>`; present as `authoritative` → bail `"this is an authoritative database"`; `authoritative` meta mismatch → bail; `replica_endpoint_id` mismatch → bail `"replica database belongs to endpoint …"`.
2. Derive `age_identity = agebridge::identity_from_secret(&secret)?`.
3. Endpoint: use the supplied one or bind (`presets::N0` + `MdnsAddressLookup::builder().advertise(false)`, same as `Client::connect`).
4. `let (events, _) = broadcast::channel(1024);` Shared state: `Arc<ReplicaInner { store: Mutex<Store>, age_identity, events, status: Mutex<StatusInner>, authoritative, endpoint, shutdown: CancellationToken-or-watch }>`.
5. Spawn the sync task:

```text
loop {
  connect(authoritative, SYNC_ALPN)          — on error: Disconnected status, backoff (1s doubling to 60s), continue
  open_bi session; write Hello
  emit Connected; reset backoff
  'session: loop reading msgs:
    Group{..}        → stash per-group partial (merge repeated same-name Group chunks)
    GroupSecrets{..} → extend the stash's secrets
    ManifestDone     → full resync: for each stashed group: sync_one_group(); then
                       drop local groups not in the manifest (drop_group_local → GroupRemoved);
                       gc_unreferenced_identities(); set last_synced
    Changed{group}   → sync_one_group_via_fetch(group)  (open bi stream: FetchGroup; read Group+GroupSecrets+FetchDone;
                       SyncDenied on a held group → drop_group_local + GroupRemoved)
    ScopeChanged     → break 'session (cycle the stream: reopen bi + Hello on the SAME connection; on error, full reconnect)
    read error/None  → emit Disconnected; break to reconnect
}
```

`sync_one_group(state)`: `secrets_needing_fetch` → if non-empty, `FetchSecrets` on a fresh bi stream, collect `SecretData` until `FetchDone` (skip entries whose `dek_version` has no wrap in `state.deks` — and if any were skipped, schedule one immediate re-`FetchGroup` retry); `apply_group_sync(own_endpoint_hex, state, fetched)`; emit `GroupAdded` if the group was new locally, then each `AppliedChange` as its event — all AFTER the transaction commits (apply returns, then send).
6. `get()`: lock store; resolve group/secret; `dek_wrap(gid, sv.dek_version, own_endpoint_hex)` → unwrap with own age identity → `crypto::decrypt_secret` with `crypto::secret_aad(group, name, sv.version, sv.dek_version)` → `Zeroizing`.
7. `shutdown()`: cancel token, await task, close endpoint if owned.

- [ ] **Step 3: Also add the offline test**: after the first sync completes, `router.shutdown()` the authoritative node, assert `replica.get("g1","s1")` still returns the plaintext (this is issue #1's headline scenario).

- [ ] **Step 4: `cargo test` (allow generous timeouts), fmt, clippy, commit**

```bash
git add -A && git commit -m "feat: Replica - embeddable sync engine with change events"
```

---

### Task 9: Replica serving on `secret-bunker/1`

**Files:**
- Modify: `src/server.rs` (parameterize the authorize/read helpers), `src/replica.rs` (`ReplicaServer`)

**Interfaces:**
- Consumes: Tasks 4, 8.
- Produces:
  - In `server.rs`: `authorize_group` gains an `implicit_admin: bool` parameter (authoritative callers pass `ident.service_admin`; replica passes `false`); the read helpers (`get`-equivalent decrypt logic, `list`, `group_acl`, `list_identity_names`) refactored into `pub(crate) fn`s taking `(store: &Store, ident: &Identity, …, dek_identity: &age::x25519::Identity, implicit_admin: bool)` so both handlers share them. Get's DEK unwrap becomes: `store.dek_wrap(gid, v, recipient_key)` where the authoritative caller passes `RECIPIENT_OPERATIONAL` + op identity and the replica passes its own endpoint hex + derived identity.
  - `ReplicaServer` (in `replica.rs`): `Clone + ProtocolHandler` on `proto::ALPN`, sharing `ReplicaInner`.

- [ ] **Step 1: Failing e2e tests** (extend Task 8's replica test file): connect a `Client` (existing helper) to the **replica's** endpoint (mount `protocol_handler()` on a Router in the test):
  - reader identity (present in synced ACL): `Get` returns plaintext identical to authoritative; `List`/`ListGroups` (assert `service_admin: false` and only explicit grants)/`GroupAcl` (for a group-admin identity) work.
  - unregistered key: every request (including `Put`) → `Denied`.
  - registered reader: `Put`/`Grant`/`RotateDek`/`CreateGroup` → `ReadOnlyReplica { authoritative }` with the right id.
  - unsynced group (`g2`): `Get` → `Denied` (uniform).
  - `ListIdentities` from anyone → `Denied`.

- [ ] **Step 2: Implement.** `ReplicaServer::accept` mirrors `Bunker`'s accept loop (frame-per-stream, `MAX_MSG`, zeroize). Dispatch:

```rust
fn dispatch(inner: &ReplicaInner, store: &Store, remote: &str, req: &Request) -> Response {
    let Ok(Some(ident)) = store.identity_by_endpoint(remote) else { return Response::Denied; };
    let own = inner.endpoint_hex.as_str();
    match req {
        Request::Get { group, name } =>
            server::read_secret(store, &ident, group, name, own, &inner.age_identity, false),
        Request::List { group } => server::list(store, &ident, group, false),
        Request::ListGroups => server::list_groups_explicit(store, &ident),
        Request::GroupAcl { group } => server::group_acl(store, &ident, group, false),
        Request::ListIdentityNames { group } => server::list_identity_names(store, &ident, group, false),
        Request::ListIdentities => Response::Denied, // service-admin-gated; replicas have none
        _ => Response::ReadOnlyReplica { authoritative: inner.authoritative.to_string() },
    }
}
```

`list_groups_explicit` = explicit rows only, `service_admin: false`, raw stored perms. Audit every request into the replica's local chain exactly as `Bunker::handle` does.

- [ ] **Step 3: `cargo test`, fmt, clippy, commit**

```bash
git add -A && git commit -m "feat: replicas serve secret-bunker/1 reads, ReadOnlyReplica for writes"
```

---

### Task 10: `serve --replica-of` + CLI wiring

**Files:**
- Modify: `src/main.rs` (`Cmd::Serve` gains `--replica-of`; replica serve path)

**Interfaces:**
- Consumes: Tasks 8–9, `servers::resolve` (`src/servers.rs`), `resolve_endpoint_key(…, KeyRole::Server)`.
- Produces: `serve --db <path> --replica-of <endpoint-id-or-alias> [--endpoint-key …] [--no-relay] [--no-mdns]`. Errors if `--operational-key` is combined with `--replica-of`.

- [ ] **Step 1: Implement** (CLI paths are covered by `tests/cli.rs` in Task 11; no unit test here):

```rust
// In Cmd::Serve fields:
/// Run as a read-only replica of this authoritative bunker
/// (EndpointId hex or a server alias). No operational key needed.
#[arg(long)]
replica_of: Option<String>,
```

In the `Cmd::Serve` arm, branch first:

```rust
if let Some(target) = replica_of {
    anyhow::ensure!(operational_key.is_none(), "--operational-key is meaningless with --replica-of");
    let authoritative = secret_bunker_iroh::servers::resolve(Some(&target))?; // match existing resolve call-shape
    let secret = resolve_endpoint_key(endpoint_key, KeyRole::Server)?;
    let endpoint = /* same builder as the authoritative path (presets, mdns flags) */;
    eprintln!("replica endpoint id: {}", endpoint.id());
    for addr in endpoint.bound_sockets() { eprintln!("bound: {addr}"); }
    let replica = secret_bunker_iroh::replica::Replica::builder()
        .store_path(&db)
        .secret_key(secret)
        .authoritative(authoritative)
        .endpoint(endpoint.clone())
        .spawn()
        .await?;
    let router = Router::builder(endpoint)
        .accept(secret_bunker_iroh::proto::ALPN, replica.protocol_handler())
        .spawn();
    tokio::signal::ctrl_c().await?;
    eprintln!("shutting down");
    router.shutdown().await.map_err(|e| anyhow::anyhow!("router shutdown: {e}"))?;
    replica.shutdown().await;
    return Ok(());
}
```

Also: the authoritative path must refuse a replica DB — `Bunker::new` gains at its top: `anyhow::ensure!(store.meta_get("role")?.as_deref() != Some("replica"), "this database is a replica (serve it with --replica-of)")`.

- [ ] **Step 2: `cargo build`, run `cargo test`, fmt, clippy, commit**

```bash
git add -A && git commit -m "feat: serve --replica-of"
```

---

### Task 11: CLI process-level replica test + remaining e2e coverage

**Files:**
- Modify: `tests/cli.rs` (one new test; NOTHING existing changes), `tests/e2e.rs` (remaining spec-section-7 cases)

- [ ] **Step 1: CLI test** — reuse the `Actor`/`spawn_server`/`ServerGuard` harness (`tests/cli.rs:21-121`): init + serve authoritative; admin creates group, puts secret; register the replica actor's **server** key id as an identity, grant read; spawn `serve --db replica.sqlite --replica-of <authoritative id>` as a second `ServerGuard` (readiness-gate on its stderr like `spawn_server` does); a third actor with read grant does `client get` **against the replica id** and sees the plaintext on stdout; `client put` against the replica exits with code **4**; kill the authoritative guard; `client get` against the replica still succeeds.

- [ ] **Step 2: Remaining e2e cases** (each is listed in spec §7; skip any already covered by Tasks 6/8/9 — verify before writing):
  - revoked reader's previously-fetched wrapped DEK cannot decrypt post-revocation writes: fetch bob's wrap for v_current, revoke bob, put a new secret value, assert the new `secret_version.dek_version` > old and `crypto::unwrap_dek(old_wrap, bob_identity)` + `decrypt_secret` on the new ciphertext fails.
  - max-size secret syncs: put a secret of `proto::MAX_MSG - 4096` bytes (just under the client cap with CBOR overhead), assert the replica syncs and serves it (pins `SYNC_MAX_MSG` headroom).
  - mutation committed while the manifest is streaming surfaces without reconnect (subscribe-then-snapshot): hard to force deterministically — approximate by putting a secret immediately after `spawn()` returns (before the first `SecretChanged` for the pre-existing secret arrives) and asserting BOTH secrets eventually appear without any reconnect having occurred (assert no `Disconnected` event was received).
  - unregistered peer on the sync ALPN gets `SyncDenied` (done in Task 6 — verify, don't duplicate).
  - revocation-lag semantics: revoke a THIRD-party reader (not the replica), do NOT let the replica sync (kill the authoritative node first), assert that reader still `Get`s from the replica; restart the authoritative node, wait for the replica to resync, assert the reader is now denied.

- [ ] **Step 3: Full suite, fmt, clippy, commit**

```bash
cargo test && cargo fmt && cargo clippy --all-targets
git add -A && git commit -m "test: replica CLI flow + spec section-7 e2e coverage"
```

---

### Task 12: Documentation

**Files:**
- Create: `docs/sync-protocol.md`
- Modify: `docs/protocol.md`, `design/crypto-design.md`, `README.md`

- [ ] **Step 1: `docs/sync-protocol.md`** — normative spec of `secret-bunker-sync/1`, structured like `docs/protocol.md`: ALPN, framing (4-byte BE length + CBOR, 8 MiB cap, cap invariant vs the client protocol's 4 MiB), authorization (explicit read only, uniform `SyncDenied`, empty-manifest rule), every message with field tables, session lifecycle (subscribe-then-snapshot, per-group lock-consistent snapshots, chunking rules, push semantics, replica reactions incl. the FetchGroup path and the ScopeChanged stream-cycle), fetch semantics (silent omission of vanished names), apply rules 1–5 verbatim from the design spec §4.4 (nonce discriminator prominently), versioning (ALPN bump). Reference the golden vectors in `src/sync.rs`.

- [ ] **Step 2: `docs/protocol.md`** — add `ReadOnlyReplica` to the Response table (registration-gated; exit code 4), a "Replicas" subsection in the semantics section: replicas serve read-path requests, authorize by explicit ACL rows only, `Groups.service_admin` is always `false` on a replica and the "service admins see every group" note holds on the authoritative node only.

- [ ] **Step 3: `design/crypto-design.md`** — apply the section-8 list from the design spec: derived recipients + Thormarker citation in §3 (Identities); `dek_wrap` recipient set in §4; §7 revocation rewrite (auto-rotate; ACL-instant at the authoritative node; replica revocation lag; synced copies not claw-backable); sync metadata-disclosure and stolen-replica-DB notes in §2 (threat model) and §12 (non-goals: replica chaining, staleness bounds); §8/§9 recover-flow update (operational rows in `dek_wrap`); §10/k8s: operator pod needs only its endpoint key.

- [ ] **Step 4: `README.md`** — "Read-only replicas" section: the two-command operator flow, `serve --replica-of`, exit code table, and a ~20-line library example using `Replica::builder`/`subscribe`/`get` (compile-check it with `cargo build --examples` if made an example file, else mark it `no_run` text).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "docs: sync protocol spec, replica docs, crypto-design update"
```

---

### Task 13: Final verification + PR

- [ ] **Step 1:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` — all green.
- [ ] **Step 2:** Reread the design spec top to bottom; check every requirement has landed (especially spec §7 test list and §10 success criteria). Fix anything missed.
- [ ] **Step 3:** Push and open a **draft** PR:

```bash
git push -u origin sops-replication
gh pr create --draft --title "SOPS-style DEK wrapping + read-only replicas" --body "$(cat <<'EOF'
Implements docs/superpowers/specs/2026-08-11-sops-replication-design.md — resolves #1.

- Group DEKs wrapped to every explicitly-read-granted identity (age recipients derived from iroh EndpointIds, no second keypair)
- Read revocation auto-rotates the group DEK
- New secret-bunker-sync/1 ALPN: manifest resync on connect + live push
- serve --replica-of: read-only replicas serving secret-bunker/1 while the authoritative node is down
- Replica embeddable as a library (k8s-operator ready)
- Schema v2 migration (dek_wrap rows); existing CLI test suite passes unchanged

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review Notes (already applied)

- Spec §3.1–§3.3 → Tasks 1–3; §4 → Tasks 5–7; §5.1–5.2 → Tasks 9–10; §5.3 → Task 8; §6 → Task 2 (+backfill in 3); §7 → Tasks 3, 6, 8, 9, 11; §8 → Task 12.
- Deviation from spec noted in Task 2: `dek_wrap` FKs `secret_group`, not `group_dek` (equivalent cascade, simpler migration).
- Type consistency: `dek_wrap`/`add_dek`/`wrap_set_for_group` signatures are referenced identically in Tasks 2, 3, 6, 7; `GroupSyncState`/`FetchedSecret` cross Tasks 7–8; `ReplicaEvent` crosses 8–9.
