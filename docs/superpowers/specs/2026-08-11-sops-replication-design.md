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
- Revocation semantics split by node. At the **authoritative node** the ACL
  denial is still instant on the next request, but ciphertext + wraps a
  reader already synced cannot be clawed back; auto-rotation protects all
  post-revocation writes. A **replica** enforces a revocation only after it
  applies the sync carrying the ACL change — which cannot happen while the
  authoritative node is down or the replica is partitioned. Until then a
  revoked identity can still read its formerly-granted groups through any
  replica granted on them. There is no staleness bound; this goes in the
  threat model.
- Sync widens metadata visibility. A sync-capable read grant delivers, per
  readable group, the full ACL roster — identity names, endpoint ids, and
  permission bits — data that on the client protocol is admin-gated
  (`GroupAcl`, `ListIdentityNames`) or service-admin-gated (endpoint ids
  via `ListIdentities`). A stolen replica database exposes the mirrored
  rosters without any key. The replica needs this data to authorize its
  own clients; the disclosure is accepted and documented.

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
         FK(group_id) REFERENCES secret_group(id) ON DELETE CASCADE)
```

FK to `secret_group`: equivalent cascade, simpler migration; no code path
deletes individual `group_dek` rows.

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
- **Revoke read** (Grant clearing the read bit, or RemoveIdentity): in
  **one transaction covering the ACL change and every affected group** —
  delete that identity's wrap rows (all versions) and **auto-rotate**:
  append a new DEK version wrapped to operational + backup + remaining
  readers. RemoveIdentity touching several groups rotates them all in that
  same transaction (single-connection SQLite makes this cheap), so a crash
  can never leave a revocation half-applied. Both the ACL change and each
  rotation get audit entries. Note rotation needs **no private key**: a new
  DEK is generated and wrapped to public recipients only.
- **RotateDek (manual):** unchanged semantics, but the new version wraps to
  operational + backup + all current readers.
- **Service admins:** the implicit read of the service-admin flag remains an
  authorization rule only — it never creates wraps. (Otherwise revoking a
  service admin would force rotating every group.) A service admin that
  should run a replica gets explicit read grants.
- **recover:** same flow as today; `apply_recovery` now updates the
  `'operational'` recipient rows per DEK version. Reader and backup wraps
  are untouched by operational-key rotation.
- **`db grant`:** granting read offline now also produces wrap rows, and
  unwrapping existing DEKs requires the operational key, so the command
  resolves it (same defaulting as `serve`) **for read grants only**. It
  already requires stopped-service access on the server machine, so no new
  trust is introduced. Revoking read offline performs the same delete-wraps
  + auto-rotate as the online path and needs no key material at all
  (rotation wraps to public recipients).
- **Backfill:** at `serve` startup (authoritative role only), create any
  missing `(group, dek_version, read-granted identity)` wrap rows
  idempotently, **before the sync ALPN starts accepting sessions** — a
  replica must never receive a manifest with its own wraps still missing.
  A pre-existing database becomes fully wrapped on first boot of the new
  binary.

## 4. Sync protocol — `secret-bunker-sync/1`

### 4.1 Transport and framing

- Second ALPN on the same iroh endpoint, its own `ProtocolHandler`
  registered alongside `secret-bunker/1`.
- Framing: **4-byte big-endian length prefix + CBOR body**, **8 MiB cap
  per message** — deliberately larger than the client protocol's 4 MiB
  `MAX_MSG`, preserving the invariant that *every secret writable via
  `secret-bunker/1` fits in one `SecretData` frame* (ciphertext = plaintext
  + 16-byte AEAD tag, plus nonce and metadata). A frame that would exceed
  the cap is a protocol error, never a silent omission. The framing enables
  multi-message streams and server push; it is deliberately different from
  the client protocol's one-blob-until-EOF framing.
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
- Sync never carries plaintext, unwrapped DEKs, or wraps addressed to
  anyone but the caller: ciphertext, the caller's own wraps, and metadata
  only. "Metadata" is spelled out because it exceeds what the same identity
  can query on the client protocol: for every group in the caller's read
  scope, sync delivers the full ACL roster (identity names, endpoint ids,
  permission bits). See the accepted consequence in section 2.

### 4.3 Messages and lifecycle

Session stream (one long-lived bidi stream, opened by the replica):

- Replica sends `Hello{}`.
- The server **subscribes to the change broadcast before taking the
  manifest snapshot** (subscribe-then-snapshot), so every mutation
  committed after the snapshot begins is observed either in the manifest
  or as a buffered push event. Events arriving while the manifest streams
  are held by the session's debouncer and delivered after `ManifestDone`.
- Server streams the manifest, then holds the stream open for push:
  - `Group{name, acl: [AclEntry{identity_name, endpoint_id, perms}],
    deks: [DekEntry{version, wrapped}]}` — `wrapped` is the caller's own
    wrap; blobs are small (~200 B) and inline. Like `GroupSecrets`, the
    `acl` and `deks` lists may be split across continuation frames to stay
    under the message cap (the `deks` list grows monotonically with every
    rotation). `AclEntry` deliberately carries **no service-admin flag**:
    the replica never consults it (section 5.2), and no replica-local
    identity row ever has it set.
  - `GroupSecrets{group, secrets: [SecretEntry{name, current_version,
    dek_version, nonce}]}` — repeated/chunked to stay under the message
    cap. `nonce` is the current version's encryption nonce and serves as
    the change discriminator (see 4.4).
  - `ManifestDone{}` after the last group.
  - Push events, debounced: `Changed{group}` when any successful mutation
    touches a group in the caller's scope; `ScopeChanged{}` when the
    caller's own readable set changes, or when the server's broadcast
    channel overflowed.
- Each group's `Group` + `GroupSecrets` records are read under a **single
  store-lock acquisition** (read into memory, release, then send), so every
  per-group snapshot is internally consistent. The lock is never held
  across sends.

Fetch streams (one bidi stream per request, opened by the replica):

- `FetchGroup{group}` → the same `Group` + `GroupSecrets` records as the
  manifest, then `FetchDone{}`. This is how a live session refreshes one
  group. Unauthorized or unknown group → uniform `SyncDenied`.
- `FetchSecrets{group, names: [String]}` → stream of
  `SecretData{name, version, dek_version, nonce, ciphertext, created_at,
  created_by}`, then `FetchDone{}`. Unauthorized or unknown group → uniform
  `SyncDenied`. A requested name that no longer exists is **silently
  omitted** (`FetchDone` still terminates the stream); the replica treats
  an omitted name as locally unchanged — the deletion propagates via the
  next `Changed`-driven group sync or full resync.

Replica reactions (normative):

- On `Changed{group}`: issue `FetchGroup{group}` (+ `FetchSecrets` for the
  differing names) and run the apply rules of 4.4 for that group in one
  local transaction. If `FetchGroup` returns `SyncDenied` for a group the
  replica currently holds (the change raced with group deletion or the
  replica's own revocation), drop the group locally — mirroring the
  absent-from-manifest rule.
- On `ScopeChanged{}` (including the broadcast-overflow case): close the
  session stream and open a fresh one (`Hello` → full manifest → apply),
  preferably on the same QUIC connection, reconnect with backoff as the
  fallback. **"Full resync" means exactly this session-stream cycle.**
  Fetch streams belonging to the previous session generation are abandoned.

Server-side push infrastructure: `Bunker` publishes `(group)` events to a
tokio broadcast channel after each successful mutation; each sync session
filters by its caller's scope (recomputed per event, so grants/revocations
of the caller itself surface as `ScopeChanged`) and debounces.

Reconnect: drop → retry with backoff → full resync on connect. Missed
events are recovered by the resync, never lost silently.

### 4.4 Replica-side apply rules

Per group, in **one local transaction** (replica readers always see atomic
group states), against the **latest received manifest state for that
group** (from the connect-time manifest or a later `FetchGroup`), applied
in dependency order:

1. Upsert identity rows referenced by the group's ACL, keyed by
   `endpoint_id` and taking the authoritative node's names. Before each
   upsert, delete any local identity row holding the incoming *name* with
   a **different** endpoint id — names are unique upstream, so a local
   collision is by definition stale, and without this delete a key
   replacement (RemoveIdentity + AddIdentity under the same name)
   livelocks the group's apply forever on the `UNIQUE(name)` constraint.
   Plain `INSERT OR REPLACE` must **not** be used (its delete-and-reinsert
   would cascade `group_acl` rows in unrelated groups and reassign
   `identity.id`). Replica-local identity rows never have `service_admin`
   set. Identity rows unreferenced by any `group_acl` are garbage-collected
   at the end of each full resync.
2. Replace the group's ACL rows wholesale.
3. Insert missing `group_dek` version rows and the caller's `dek_wrap`
   rows; replace a local wrap whose blob differs from the manifest's
   (wrap blobs are stable at rest, so a difference means the DEK version
   was reissued, e.g. after an authoritative restore); delete local wraps
   absent from the manifest.
4. Fetch and replace secrets for which **any of `(current_version,
   dek_version, nonce)` differs** from the manifest. The nonce is the
   discriminator that makes delete-then-recreate detectable: a recreated
   secret can land on the same `(version, dek_version)` tuple (versions
   restart at 1 and deletion does not rotate), but every encryption draws
   a fresh random nonce. (`created_at` is not a substitute — it has
   one-second resolution.)
5. Delete local secrets absent from the manifest.

A fetched `SecretData` referencing a `dek_version` the replica holds no
wrap for (a rotation raced the fetch) is **not applied**; the replica
re-runs that group's sync (`FetchGroup` again), which converges once the
group state settles. Groups absent from the manifest (revoked or deleted
upstream) are dropped locally — but only on a **completed** full resync
(`ManifestDone` received), never on a partial stream. Only **current**
secret versions are synced in v1; history mirroring can be added later
without protocol surgery (new fetch variant).

## 5. Replica operation and serving

### 5.1 Running one

- `serve --replica-of <endpoint-id-or-alias>` (alias resolved via the
  existing `servers.rs` book). Same binary, its own SQLite file.
- Key material: exactly one — the replica's own iroh endpoint key
  (auto-generated as today). The age identity is derived. No `init`, no
  operational key, no backup key.
- First start records `meta.role = replica`, `meta.authoritative =
  <endpoint-id>`, and `meta.replica_endpoint_id = <own endpoint id>`. An
  authoritative `serve` refuses a replica DB and vice versa (the v2
  migration and `init` stamp `meta.role = authoritative` on authoritative
  databases, so the mutual refusal is well-defined for pre-existing DBs);
  `--replica-of` pointing at a different authoritative id than recorded is
  an error; starting a replica with an endpoint key that does not match
  the recorded `replica_endpoint_id` is an error (the mirror's wraps are
  useless to any other key).
- Operator flow: `key generate server` (or a first `serve --replica-of`
  run, which auto-generates it) then `key show server` on the replica
  host → `client add-identity` + grants with read on the authoritative
  node → start the replica. One identity key per replica instance:
  sharing a key across replicas confuses audit attribution and is
  unsupported.

### 5.2 Serving

- The replica mounts `secret-bunker/1` and answers read-path requests from
  its mirror: `Get`, `List`, `ListGroups`, `GroupAcl`, `ListIdentityNames` —
  with the same uniform `Denied` for strangers, missing permissions, and
  unsynced groups.
- **Authorization mechanism.** The explicit-ACL permission check is
  extracted into a shared function; the service-admin implicit bypass
  becomes a caller decision. The authoritative handler passes it; the
  replica handler authorizes **strictly by explicit ACL rows** and never
  consults `service_admin` (no replica-local identity row has it set —
  section 4.4). Consequences, all documented: the replica's `ListGroups`
  reply reports only explicitly granted groups with their explicit perms
  and always `service_admin: false` (the authoritative `ListGroups` has
  its own service-admin branch that does not apply here);
  `ListIdentities`, being service-admin-gated, uniformly yields `Denied`
  on a replica. `docs/protocol.md`'s note that "service admins see every
  group, always with the full implicit 7" gets a replica carve-out.
- `Get` unwraps the DEK with the replica's derived identity and returns
  plaintext. Clients are byte-for-byte oblivious to whether they talk to a
  replica or the authoritative node.
- **Mutating requests — check order matters.** The replica runs the same
  identity-resolution-first dispatch as the authoritative node: an
  **unregistered** peer receives the uniform `Denied` for *every* request,
  mutations included (it must not learn the node's role or the
  authoritative id). Only **registered** identities receive the new
  additive response variant `ReadOnlyReplica{authoritative: <endpoint-id>}`
  for mutating requests (`Put`, `Delete`, `CreateGroup`, `Grant`,
  `RotateDek`, `AddIdentity`, `RemoveIdentity`, `SetServiceAdmin`) —
  registration-gated, mirroring the `ListGroups` precedent that a
  registered key may learn about its own server. This is the **only**
  change to the client protocol. The CLI prints it and exits with code
  **4** (1 = generic error, 2 = CAS conflict, 3 = denied are taken); the
  TUI renders it as a status message. Old clients hit a decode error
  (generic failure) rather than a misleading `Denied`.
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

`serve --replica-of` = `spawn()` + mount `protocol_handler()`, so the CLI
and library paths cannot drift. The replica's sync role is purely
client-side inside `spawn()` — dialing needs no accept handler, and the
replica does **not** mount `secret-bunker-sync/1`: an inbound sync
connection to a replica fails at ALPN negotiation (replica chaining is out
of scope; it cannot work with the v1 mirror, which holds only the
replica's own DEK wraps).

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
- The migration also stamps `meta.role = authoritative` so the
  replica/authoritative mutual-refusal check is defined for existing DBs.
- No client migration. Old clients work against new servers unchanged.
- Implementation should land in three phases, each keeping the full test
  suite green: (1) migration machinery + `dek_wrap` + wrap lifecycle +
  `agebridge`; (2) sync protocol + replica engine + replica serving;
  (3) library API surface + CLI (`--replica-of`, exit code 4) + docs.

## 7. Testing

- **Unit (`agebridge`):** roundtrip encrypt-to-derived-recipient /
  decrypt-with-derived-identity; `identity.to_public()` equals derived
  recipient; golden vector pinning a fixed iroh key to its exact `age1…`
  string.
- **Store:** v1-fixture migration test; `dek_wrap` accessors; backfill
  idempotence; revoke deletes wraps + auto-rotates in one transaction.
- **e2e (in-process, extending the existing single-Router harness to two
  nodes):** grant → wraps exist for all retained DEK versions; revoke →
  auto-rotate and a previously-fetched wrapped DEK cannot decrypt
  post-rotation writes; full replica flow — sync a subset of groups, serve
  plaintext reads, authoritative down → replica still serves, mutation →
  `ReadOnlyReplica` (and, from an **unregistered** peer, plain `Denied`),
  revoke the replica's read → group dropped locally + rotation upstream,
  uniform denial on the replica; **delete/recreate ABA** — delete and
  recreate a version-1 secret under the same DEK while the replica is
  disconnected (or within one debounce window), then assert the replica
  serves the new value after resync (this pins the nonce discriminator);
  a mutation committed **while the initial manifest is streaming**
  surfaces on the replica without a reconnect (pins
  subscribe-then-snapshot); a secret at the client protocol's exact
  maximum size syncs successfully (pins the 8 MiB sync cap invariant);
  key replacement (RemoveIdentity + AddIdentity reusing the name)
  converges on the replica (pins apply rule 1's stale-name delete);
  revoked third-party client still reads from a partitioned replica until
  it syncs (pins the documented revocation-lag semantics); library API —
  event-after-commit ordering, `get`, `status`.
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
  already-synced copies cannot be clawed back — explicit non-goal; the
  existing "loses access immediately via ACL change" threat-model entry is
  re-scoped to the authoritative node, with replica revocation lag called
  out); stolen-database guarantee now includes reader keys in the
  recipient set; sync's metadata-disclosure delta (a read grant reveals
  the group's full roster — names, endpoint ids, perms — and a stolen
  replica DB exposes mirrored rosters keylessly); replica trust model (a
  replica is a reader: compromising it compromises exactly the groups it
  can read); updated recover flow; k8s guidance (operator pod needs only
  its endpoint key).
- `docs/sync-protocol.md`: new, normative — framing, every message,
  versioning-by-ALPN, golden vectors.
- `docs/protocol.md`: the `ReadOnlyReplica` response variant (registration-
  gated), the new exit code 4, and replica carve-outs for the `Groups`
  response notes (service admins see every group on the authoritative node
  only; replicas report explicit grants with `service_admin: false`).
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
- Replica chaining: a replica does not mount `secret-bunker-sync/1`, and a
  v1 mirror could not serve it anyway (it holds only its own DEK wraps).

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
