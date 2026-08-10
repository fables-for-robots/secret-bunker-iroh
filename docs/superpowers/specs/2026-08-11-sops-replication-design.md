# SOPS-Style DEK Wrapping and Read-Only Replicas

**Date:** 2026-08-11
**Status:** Approved design, pending implementation plan
**Resolves:** [#1 — Read-only replicas](https://github.com/fables-for-robots/secret-bunker-iroh/issues/1)

## 1. Summary

Group DEKs are currently age-wrapped to exactly two recipients: the server's
operational key and the offline backup key. This design adds every
read-granted identity as a wrap recipient, SOPS-style. Serving is unchanged —
reads still return server-decrypted plaintext over the encrypted transport —
but any reader can now mirror the groups its key can read and serve them
while the authoritative node is down.

Concretely:

- Every identity becomes an age recipient **derived from the iroh EndpointId
  it already has** — no second keypair, no registration step.
- DEK wraps move from two hard-coded columns to a `(group, dek_version,
  recipient)` table.
- Revoking read **auto-rotates** the group DEK.
- A new `secret-bunker-sync/1` ALPN carries replication: stateless full
  resync on connect, live push while connected.
- A replica is the same binary (`serve --replica-of`) or an embeddable
  library component (`Replica`), designed to host a future Kubernetes
  operator.
- Clients are untouched: a replica answers the ordinary `secret-bunker/1`
  protocol for reads, so pointing `--server` at `127.0.0.1` just works.

## 2. Decisions taken (with alternatives rejected)

| Decision | Chosen | Rejected |
|---|---|---|
| Trust model | Unchanged: server keeps the operational key, decrypts reads, encrypts writes. Wrapping to readers exists to enable replicas. | Full E2E (clients en/decrypt, no op key); hybrid (E2E reads only). |
| Wrap recipients | **All identities with explicit read** on a group, plus `operational` and `backup`. | Only replica-designated identities (new ACL bit or identity flag). |
| Recipient keys | **Derived** ed25519→X25519 from the EndpointId (proven feasible against locked crate versions). | Registered per-identity age keys. |
| Replica writes | **Denied** with a distinct `ReadOnlyReplica` response. | Proxying writes to the authoritative node. |
| Revoking read | **Auto-rotate** the group DEK in the same operation. | SOPS-style lazy manual rotation; rotate + re-encrypt current versions. |
| Sync transport | **Dedicated `secret-bunker-sync/1` ALPN**, length-prefixed framing, server push. | Additive request variants in `secret-bunker/1` with polling. |

Consequences accepted:

- A stolen SQLite file is no longer opaque to everyone but the op/backup key
  holders: it is decryptable by **any read-granted identity's key**. This is
  the cost of "any reader can be a replica" and must be documented in the
  threat model.
- Revocation is no longer purely instant: the ACL denial is still instant on
  the next request, but ciphertext + wraps a reader already synced cannot be
  clawed back. Auto-rotation protects all post-revocation writes.

## 3. Identities and at-rest cryptography

### 3.1 Derived age recipients (`src/agebridge.rs`)

New module, two pure functions:

- **Recipient (public):** EndpointId bytes → `ed25519_dalek::VerifyingKey::from_bytes`
  → `.to_montgomery()` → bech32-encode (`"age"`, Bech32 variant) →
  `age::x25519::Recipient::from_str`. Computable by anyone from the
  EndpointId stored in the `identity` table.
- **Identity (secret):** iroh `SecretKey::to_bytes()` →
  `ed25519_dalek::SigningKey::from_bytes` → `.to_scalar_bytes()` →
  bech32-encode (`"age-secret-key-"`, uppercased) →
  `age::x25519::Identity::from_str`. Only the key holder can derive it.

Notes pinned by feasibility research (verified by a compiled roundtrip test
against the locked versions age 0.11.5, iroh 1.0.3, ed25519-dalek 3.0.0,
bech32 0.9.1):

- age 0.11.5 exposes only Bech32-string constructors for x25519 types; the
  bech32 bridge is mandatory and bech32 0.9.1 is already in the dependency
  tree (via age).
- `identity.to_public()` equals the publicly derived recipient; encrypt/
  decrypt roundtrips.
- Do **not** use age's `ssh` feature: its ssh-ed25519 stanzas add an HKDF
  tweak and are not interoperable with the native derivation.
- Ed25519→X25519 key reuse is established practice (age ssh-ed25519,
  ssh-to-age/sops-nix, libsodium) with a formal joint-security analysis:
  Thormarker, *On using the same key pair for Ed25519 and an X25519 based
  KEM*, ePrint 2021/509. Cite it in the module and in
  `design/crypto-design.md`. The iroh key's existing TLS signing use stays
  inside the analyzed signing+ECDH model.
- The two dalek stacks in the tree (curve25519-dalek 4.x via age, 5.x via
  iroh) never exchange types — only `[u8; 32]`/Bech32 strings cross the
  bridge.

### 3.2 Wrap storage (schema v2)

`group_dek` loses its `wrapped_operational`/`wrapped_backup` columns and
becomes the DEK-version registry. New table:

```
group_dek(group_id, version, created_at, PK(group_id, version))
dek_wrap(group_id, dek_version, recipient TEXT, wrapped BLOB, created_at,
         PK(group_id, dek_version, recipient),
         FK(group_id, dek_version) REFERENCES group_dek ON DELETE CASCADE)
```

`recipient` is `'operational'`, `'backup'`, or a reader's EndpointId
(lowercase hex, same encoding as `identity.endpoint_id`). Reader wrap rows
are deleted explicitly in the transactions that mutate ACLs (no FK to
`identity`, since op/backup are not identities).

### 3.3 Wrap lifecycle

- **CreateGroup:** DEK v1 wrapped to operational + backup + creator, in the
  existing single transaction.
- **Grant read:** in the same transaction as the ACL write, unwrap **every
  retained DEK version** with the operational identity and wrap to the
  grantee's derived recipient. Every version, because rotation does not
  re-encrypt: current ciphertexts may reference old DEK versions.
- **Revoke read** (Grant clearing the read bit, or RemoveIdentity): in one
  transaction per affected group — delete that identity's wrap rows (all
  versions) and **auto-rotate**: append a new DEK version wrapped to
  operational + backup + remaining readers. Both the ACL change and the
  rotation get audit entries.
- **RotateDek (manual):** unchanged semantics, but the new version wraps to
  operational + backup + all current readers.
- **Service admins:** the implicit read of the service-admin flag remains an
  authorization rule only — it never creates wraps. (Otherwise revoking a
  service admin would force rotating every group.) A service admin that
  should run a replica gets explicit read grants.
- **recover:** same flow as today; `apply_recovery` now updates the
  `'operational'` recipient rows per DEK version. Reader and backup wraps
  are untouched by operational-key rotation.
- **`db grant`:** granting read offline now also produces wrap rows, so the
  command resolves the operational key (same defaulting as `serve`). It
  already requires stopped-service access on the server machine, so no new
  trust is introduced. Revoking read offline performs the same
  delete-wraps + auto-rotate as the online path.
- **Backfill:** at `serve` startup (authoritative role only), create any
  missing `(group, dek_version, read-granted identity)` wrap rows
  idempotently. A pre-existing database becomes fully wrapped on first boot
  of the new binary.

## 4. Sync protocol — `secret-bunker-sync/1`

### 4.1 Transport and framing

- Second ALPN on the same iroh endpoint, its own `ProtocolHandler`
  registered alongside `secret-bunker/1`.
- Framing: **4-byte big-endian length prefix + CBOR body**, 4 MiB cap per
  message. This enables multi-message streams and server push; it is
  deliberately different from the client protocol's one-blob-until-EOF
  framing.
- Message enums use the same serde externally-tagged CBOR conventions and
  compatibility rules as the client protocol; breaking changes bump the ALPN
  to `secret-bunker-sync/2`. Golden-vector tests pin the wire bytes.
  Normative spec: new `docs/sync-protocol.md`.

### 4.2 Authentication, authorization, secrecy

- The iroh handshake authenticates the peer; there is no in-band identity.
- Sync scope = groups where the caller holds an **explicit read** grant.
  Service-admin implicit read does not extend to sync (it has no wraps).
- Unregistered peer → a single uniform `SyncDenied` message, stream closed.
- Registered identity with zero readable groups → empty manifest
  (`ManifestDone` immediately). This mirrors the `ListGroups` precedent: a
  key holder may confirm its own registration, nothing else.
- Sync never carries plaintext, unwrapped DEKs, or wraps addressed to anyone
  but the caller: ciphertext, the caller's own wraps, and metadata only.

### 4.3 Messages and lifecycle

Session stream (one long-lived bidi stream, opened by the replica):

- Replica sends `Hello{}`.
- Server streams the manifest, then holds the stream open for push:
  - `Group{name, acl: [AclEntry{identity_name, endpoint_id, perms,
    service_admin}], deks: [DekEntry{version, wrapped}]}` — `wrapped` is the
    caller's own wrap; blobs are small (~200 B) and inline.
  - `GroupSecrets{group, secrets: [SecretEntry{name, current_version,
    dek_version}]}` — repeated/chunked to stay under the message cap.
  - `ManifestDone{}` after the last group.
  - Push events, debounced: `Changed{group}` when any successful mutation
    touches a group in the caller's scope; `ScopeChanged{}` when the
    caller's own readable set changes, or when the server's broadcast
    channel overflowed (full resync is always the safety net).

Fetch streams (one bidi stream per request, opened by the replica):

- `FetchSecrets{group, names: [String]}` → stream of
  `SecretData{name, version, dek_version, nonce, ciphertext, created_at,
  created_by}`, then `FetchDone{}`. Unauthorized or unknown group → uniform
  `SyncDenied`.

Server-side push infrastructure: `Bunker` publishes `(group)` events to a
tokio broadcast channel after each successful mutation; each sync session
filters by its caller's scope and debounces.

Reconnect: drop → retry with backoff → full resync on connect. Missed
events are recovered by the resync, never lost silently.

### 4.4 Replica-side apply rules

Per group, in **one local transaction** (replica readers always see atomic
group states), applied in dependency order:

1. Upsert identity rows referenced by the group's ACL (by `endpoint_id`,
   taking the authoritative node's names and flags).
2. Replace the group's ACL rows wholesale.
3. Insert missing `group_dek` version rows and the caller's `dek_wrap` rows;
   delete local wraps absent from the manifest.
4. Fetch and replace secrets whose `(current_version, dek_version)` differ
   from the manifest; **any mismatch means replace** — this single rule also
   handles delete-then-recreate version resets (versions restart at 1).
5. Delete local secrets absent from the manifest.

Groups absent from the manifest (revoked or deleted upstream) are dropped
locally. Only **current** secret versions are synced in v1; history
mirroring can be added later without protocol surgery (new fetch variant).

## 5. Replica operation and serving

### 5.1 Running one

- `serve --replica-of <endpoint-id-or-alias>` (alias resolved via the
  existing `servers.rs` book). Same binary, its own SQLite file.
- Key material: exactly one — the replica's own iroh endpoint key
  (auto-generated as today). The age identity is derived. No `init`, no
  operational key, no backup key.
- First start records `meta.role = replica` and
  `meta.authoritative = <endpoint-id>`. An authoritative `serve` refuses a
  replica DB and vice versa; `--replica-of` pointing at a different
  authoritative id than recorded is an error.
- Operator flow: `key show server` on the replica host → `client
  add-identity` + grants with read on the authoritative node → start the
  replica.

### 5.2 Serving

- The replica mounts `secret-bunker/1` and answers read-path requests from
  its mirror: `Get`, `List`, `ListGroups`, `GroupAcl`, `ListIdentityNames` —
  same authorization code, same uniform `Denied` for strangers, missing
  permissions, and unsynced groups.
- `Get` unwraps the DEK with the replica's derived identity and returns
  plaintext. Clients are byte-for-byte oblivious to whether they talk to a
  replica or the authoritative node.
- **Divergence (documented):** replicas authorize by explicit ACL rows only;
  the service-admin implicit-read bypass does not apply (only the identity
  subset referenced by synced ACLs exists locally, and a partial
  implicit-root rule would be inconsistent).
- Every mutating request (`Put`, `Delete`, `CreateGroup`, `Grant`,
  `RotateDek`, `AddIdentity`, `RemoveIdentity`, `SetServiceAdmin`) receives
  the new additive response variant `ReadOnlyReplica{authoritative:
  <endpoint-id>}`. This is the **only** change to the client protocol. The
  CLI prints it and exits with a new dedicated exit code (2 = CAS conflict
  and 3 = denied are taken; use the next free code); the TUI renders it as a
  status message. Old clients hit a decode error (generic failure) rather
  than a misleading `Denied`.
- Staleness is absorbed by the existing CAS flow: an edit based on a stale
  replica read hits `VersionConflict` at the authoritative node and
  refreshes.
- The replica keeps its own local hash-chained audit log covering requests
  it serves and sync applications. Audit chains stay single-database; the
  "anchor the head externally" advice applies per node.

### 5.3 Library API (`src/replica.rs`)

The replica is a first-class library component; the CLI is a thin consumer.
The module depends only on `store`, `crypto`, `agebridge`, and `proto` — no
CLI or TUI imports. Intended host: a future Kubernetes operator.

```rust
let replica = Replica::builder()
    .store_path(path)                 // its own SQLite mirror
    .secret_key(iroh_secret)          // identity; age identity derived internally
    .authoritative(endpoint_id)
    .endpoint(existing_endpoint)      // optional: embed into caller's Endpoint/Router
    .spawn().await?;                  // owns the sync task: connect, resync, follow, reconnect
```

Handle surface:

- `subscribe() → Receiver<ReplicaEvent>` — `SecretChanged{group, name,
  version}`, `SecretDeleted{group, name}`, `GroupAdded{group}`,
  `GroupRemoved{group}`, `Connected`, `Disconnected`. Events are emitted
  **after** the local transaction commits, so reading on-event always sees
  the new state. This is the hook a k8s operator's reconcile loop hangs off.
- `get(group, name) → Zeroizing<Vec<u8>>`, plus `list(group)` and
  `groups()` — plaintext from the local mirror, decrypted in-process, no
  network. In-process callers are trusted (they hold the key); ACL
  enforcement applies only to the iroh-served surface.
- `status() → SyncStatus{connected, last_synced, groups, authoritative}` —
  feeds liveness/readiness probes.
- `protocol_handler()` — the read-only `secret-bunker/1` handler as an
  optional composable piece. An embedder that only materializes secrets
  (e.g. into k8s `Secret` objects) does not mount it.

`serve --replica-of` = `spawn()` + mount `protocol_handler()` + mount the
sync handler, so the CLI and library paths cannot drift.

Kubernetes consequence worth documenting: an operator pod needs only its own
endpoint key as a mounted Secret; what it can mirror is enforced
cryptographically by the authoritative node's ACL, not by anything in the
cluster.

## 6. Migration

- Add minimal migration machinery: `meta.schema_version` is read on open;
  migrations apply stepwise, each in one transaction.
- v1→v2 is pure SQL: rebuild `group_dek` as the version registry; move the
  two wrap columns into `dek_wrap` rows (`'operational'`, `'backup'`).
- Reader wraps need the operational key, so they are backfilled at
  authoritative `serve` startup (idempotent), not in the SQL migration.
- No client migration. Old clients work against new servers unchanged.

## 7. Testing

- **Unit (`agebridge`):** roundtrip encrypt-to-derived-recipient /
  decrypt-with-derived-identity; `identity.to_public()` equals derived
  recipient; golden vector pinning a fixed iroh key to its exact `age1…`
  string.
- **Store:** v1-fixture migration test; `dek_wrap` accessors; backfill
  idempotence; revoke deletes wraps + auto-rotates in one transaction.
- **e2e (in-process, existing two-router pattern):** grant → wraps exist for
  all retained DEK versions; revoke → auto-rotate and a previously-fetched
  wrapped DEK cannot decrypt post-rotation writes; full replica flow — sync
  a subset of groups, serve plaintext reads, authoritative down → replica
  still serves, mutation → `ReadOnlyReplica`, revoke the replica's read →
  group dropped locally + rotation upstream, delete/recreate propagation,
  uniform denial on the replica; library API — event-after-commit ordering,
  `get`, `status`.
- **CLI:** two-process `serve --replica-of` test reusing the `ServerGuard`
  harness; the new exit code. The existing CLI suite (plaintext stdout
  contract, exit codes 2/3, stdin puts, aliases, `db grant`, audit-verify)
  must pass unchanged — it is the migration regression net.
- **Reworked pinned tests:** `recovery_rewraps_deks` (new
  `all_deks`/`apply_recovery` shapes); instant-revocation tests now assert
  ACL-instant denial **plus** rotation.

## 8. Documentation

- `design/crypto-design.md`: identities as derived recipients (Thormarker
  citation); `dek_wrap` model; revocation semantics (auto-rotate;
  already-synced copies cannot be clawed back — explicit non-goal); stolen-
  database guarantee now includes reader keys in the recipient set; replica
  trust model (a replica is a reader: compromising it compromises exactly
  the groups it can read); updated recover flow; k8s guidance (operator pod
  needs only its endpoint key).
- `docs/sync-protocol.md`: new, normative — framing, every message,
  versioning-by-ALPN, golden vectors.
- `docs/protocol.md`: the `ReadOnlyReplica` response variant.
- `README.md`: replica quickstart and a library-embedding example.

## 9. Explicitly out of scope / unchanged

- Client protocol and client-side crypto: reads return plaintext, writes
  send plaintext, both inside the encrypted transport. CLI/TUI behavior is
  unchanged except rendering `ReadOnlyReplica`.
- CAS semantics, uniform denial on the authoritative node, service-admin
  semantics on the authoritative node, last-admin guards.
- `keys.rs` file hygiene, key roles, backup story (backup becomes one
  recipient row among many, conceptually identical).
- Write proxying from replicas, multi-master, history mirroring, durable
  sync cursors/oplog, client-side failover across multiple servers
  (`servers.rs` stays 1:1 alias→id; issue #1's model is a local replica per
  node).

## 10. Success criteria

1. A node running `serve --replica-of` with read grants on some groups
   serves correct plaintext reads for exactly those groups from
   `127.0.0.1`, including while the authoritative node is down (issue #1).
2. An existing v1 database migrates in place and all existing CLI tests
   pass unchanged.
3. Revoking a replica's read: the replica's next sync drops the group, and
   post-revocation writes are encrypted under a DEK the revoked key cannot
   unwrap.
4. A library consumer can embed `Replica`, receive change events after
   commit, and read plaintext locally — with no operational or backup key
   anywhere in its deployment.
