# The secret-bunker Sync Protocol

This document specifies how a read-only **replica** mirrors groups from an
**authoritative** `secret-bunker-iroh` node: the transport, the framing,
every message, the session lifecycle, and the rules a replica applies to
its local mirror. It is the companion of [`protocol.md`](protocol.md),
which specifies the client-facing protocol; a replica speaks *this*
protocol upwards and the *client* protocol downwards.

The reference implementation is the Rust crate in this repository:
`src/sync.rs` (wire types and framing), `src/server.rs` (`SyncServer`, the
authoritative side), `src/replica.rs` (`Replica`, the mirroring side), and
`src/store.rs` (`apply_group_sync`, the apply rules of section 8).

## 1. Transport

Replication runs over an [iroh](https://www.iroh.computer) connection —
the same QUIC with TLS 1.3 Raw Public Keys as the client protocol — under
its own ALPN:

```
secret-bunker-sync/1
```

The authoritative node mounts this ALPN alongside `secret-bunker/1` on the
**same** endpoint, so a replica dials one EndpointId for both roles. There
is no application-layer authentication: the QUIC handshake proves
possession of the replica's ed25519 secret key, and that EndpointId is the
identity whose ACL rows decide what the session may mirror.

A replica **does not** mount `secret-bunker-sync/1`. An inbound sync
connection to a replica fails at ALPN negotiation: chaining replicas is out
of scope, and a v1 mirror could not serve it anyway — it holds only the
DEK wraps addressed to its own key.

Anyone may connect. A peer whose EndpointId is unknown to the authoritative
node can open streams and send requests, but every one of them is answered
with the uniform `"SyncDenied"` message (section 4).

## 2. Framing

Unlike the client protocol, where one stream carries exactly one message in
each direction and EOF is the delimiter, a sync stream carries a
**sequence** of independent messages. Each is length-prefixed:

```
+--------+--------+--------+--------+----------------------+
|              u32 big-endian length | CBOR body (length B) |
+--------+--------+--------+--------+----------------------+
```

- The prefix counts the CBOR body only; a whole frame is `4 + length`
  bytes.
- Either side rejects a frame whose body exceeds **8 MiB**
  (`SYNC_MAX_MSG`). The cap is checked on the encoded body *before any
  byte is written*, and on the declared length *before a receive buffer is
  allocated*. A frame that would exceed it is a protocol error that ends
  the stream — never a silent omission.
- A clean end-of-stream where the next length prefix would have started is
  a normal stream termination, not an error. A prefix or body cut short is
  an error.

**Why 8 MiB and not the client protocol's 4 MiB (`MAX_MSG`).** The cap is
deliberately strictly larger, so the invariant *every secret writable
through `secret-bunker/1` fits into one `SecretData` frame* holds with room
to spare: a maximal `Put` carries a value just under 4 MiB, its ciphertext
adds a 16-byte AEAD tag, and `SecretData` adds the name, nonce, timestamps
and author on top. Sync therefore never has to split a secret's value, and
no legal write can produce a secret that replication cannot carry.

Streams are independent and multiplexed on one connection: the long-lived
session stream and any number of short-lived fetch streams run
concurrently, each handled by its own task on the authoritative node.

## 3. Message encoding

Bodies are [CBOR](https://www.rfc-editor.org/rfc/rfc8949) documents in
serde's **externally-tagged enum representation**, exactly as in the client
protocol (see [`protocol.md`](protocol.md) section 3):

- A variant without fields is a bare text string: `"Hello"`,
  `"SyncDenied"`, `"ManifestDone"`, `"FetchDone"`, `"ScopeChanged"`.
- A variant with fields is a single-entry map keyed by the variant name,
  whose value is a map of the fields:

  ```
  {"FetchGroup": {"group": "prod"}}
  ```

- `nonce`, `ciphertext`, and `wrapped` are CBOR **byte strings** (major
  type 2). Versions and timestamps are integers, permission bitmasks are
  unsigned integers, everything else is a text string.

**Variant and field names are the wire contract.** Decoders match them as
strings; unknown variants are an error, unknown fields inside a known
variant should be ignored. See section 10.

## 4. Authorization and disclosure

Sync scope is the set of groups on which the calling EndpointId holds an
**explicit `read` ACL row**. Nothing else grants scope:

- The **service-admin implicit read does not extend to sync.** A service
  admin reads through the operational key, not through a personal DEK
  wrap, and sync only ever ships wraps addressed to the caller — so an
  implicit reader would receive groups it could not decrypt. A service
  admin that should run a replica is given explicit read grants.
- Unknown identity, unknown group, and missing `read` are answered with the
  same `SyncDenied` and are indistinguishable, exactly like `Denied` on the
  client protocol.
- A **registered identity with zero readable groups** is not denied: it
  receives an empty manifest (`ManifestDone` immediately). This mirrors the
  `ListGroups` precedent — a key holder may confirm its own registration,
  and nothing else.

Sync never carries plaintext, never carries an unwrapped DEK, and never
carries a wrap addressed to anyone but the caller. What it does carry, per
group in scope, is ciphertext, the caller's own wraps, and metadata — and
"metadata" here is wider than what the same identity can ask for over the
client protocol:

| Data | Client protocol | Sync |
|---|---|---|
| Secret names + current versions | `read` on the group | in scope |
| Ciphertext, nonce, `dek_version` | never (server decrypts) | in scope |
| The group's full ACL roster: identity names, endpoint ids, permission bits | `admin` on the group (`GroupAcl`, names only via `ListIdentityNames`); endpoint ids are service-admin-only (`ListIdentities`) | in scope |

A read grant that is used for replication therefore discloses the group's
roster to the grantee, and a stolen replica database exposes the mirrored
rosters without any key at all. This is an accepted, documented
consequence — the replica needs the roster to authorize its own clients.
See [`../design/crypto-design.md`](../design/crypto-design.md) sections 2
and 7.

## 5. Messages

### Requests (replica → authoritative)

| Request | Opened on | → |
|---|---|---|
| `Hello` | the session stream | the manifest, then push events, until the connection ends |
| `FetchGroup` | a fetch stream | `Group`, `GroupSecrets`…, `FetchDone` |
| `FetchSecrets` | a fetch stream | `SecretData`…, `FetchDone` |

```
"Hello"
{"FetchGroup":   {"group": "prod"}}
{"FetchSecrets": {"group": "prod", "names": ["db-password", "api-token"]}}
```

Exactly **one** request is read per stream. Any of the three can also be
answered with `SyncDenied` (section 4).

| Field | Type | Meaning |
|---|---|---|
| `group` | text | group name |
| `names` | array of text | secret names to fetch; order is preserved in the reply |

### Messages (authoritative → replica)

| Message | Sent |
|---|---|
| `SyncDenied` | as the only answer to an unauthorized request |
| `Group` | first record of a group's manifest or `FetchGroup` reply |
| `GroupSecrets` | the group's secret listing, one or more per `Group` |
| `ManifestDone` | after the last group of a `Hello` manifest |
| `FetchDone` | after the last record of a fetch reply |
| `Changed` | push: a mutation touched a group in the caller's scope |
| `ScopeChanged` | push: the caller's readable set moved, or events were dropped |
| `SecretData` | one secret's current version, in a `FetchSecrets` reply |

```
{"Group":        {"name": "prod",
                  "acl":  [{"identity_name": "ci", "endpoint_id": "1a98…", "perms": 1}],
                  "deks": [{"version": 1, "wrapped": h'6167…'}]}}
{"GroupSecrets": {"group": "prod",
                  "secrets": [{"name": "db-password", "current_version": 4,
                               "dek_version": 2, "nonce": h'0a1b…'}]}}
"ManifestDone"
{"Changed":      {"group": "prod"}}
"ScopeChanged"
{"SecretData":   {"name": "db-password", "version": 4, "dek_version": 2,
                  "nonce": h'0a1b…', "ciphertext": h'…',
                  "created_at": 1770000000, "created_by": "admin"}}
"FetchDone"
```

**`Group`**

| Field | Type | Meaning |
|---|---|---|
| `name` | text | group name |
| `acl` | array of `AclEntry` | the group's full ACL |
| `deks` | array of `DekEntry` | retained DEK versions, wrapped to the caller |

**`AclEntry`**

| Field | Type | Meaning |
|---|---|---|
| `identity_name` | text | the authoritative node's name for the identity |
| `endpoint_id` | text | 64-char lowercase hex EndpointId |
| `perms` | uint | permission bitmask: `read` 1, `write` 2, `admin` 4 |

`AclEntry` deliberately carries **no service-admin field**. A replica
authorizes strictly by explicit ACL rows, so the flag would be dead weight
at best and a privilege-escalation vector at worst; no identity row in a
mirror ever has it set (section 8, rule 1).

**`DekEntry`**

| Field | Type | Meaning |
|---|---|---|
| `version` | uint | DEK version, matching `SecretEntry.dek_version` |
| `wrapped` | bytes | the DEK wrapped to the **caller's own** derived age recipient |

Only the caller's wrap is ever sent. A DEK version for which the caller
holds no wrap — a revocation interleaved with the snapshot, say — is
omitted from the list rather than sent addressed to someone else. Wrap
blobs are small (~200 bytes) and travel inline.

**`GroupSecrets`**

| Field | Type | Meaning |
|---|---|---|
| `group` | text | group name |
| `secrets` | array of `SecretEntry` | listing chunk (see section 6) |

**`SecretEntry`**

| Field | Type | Meaning |
|---|---|---|
| `name` | text | secret name |
| `current_version` | uint | the version a `Get` would return |
| `dek_version` | uint | which DEK version encrypts it |
| `nonce` | bytes | that version's encryption nonce |

The **nonce is the change discriminator**. A replica refetches a secret
when *any* of `(current_version, dek_version, nonce)` differs from its
local copy. The nonce is what makes delete-then-recreate (an "ABA" change)
detectable: a recreated secret can land on exactly the same
`(current_version, dek_version)` — versions restart at 1 and deletion does
not rotate the DEK — but every encryption draws a fresh random nonce.
`created_at` is no substitute; it has one-second resolution.

**`SecretData`**

| Field | Type | Meaning |
|---|---|---|
| `name` | text | secret name |
| `version` | uint | the current version being shipped |
| `dek_version` | uint | which DEK version encrypts it |
| `nonce` | bytes | encryption nonce |
| `ciphertext` | bytes | ChaCha20-Poly1305 ciphertext, still encrypted |
| `created_at` | int | unix seconds |
| `created_by` | text | identity **name** of the writer, mirrored verbatim (not re-stamped by the replica) |

**`Changed`**

| Field | Type | Meaning |
|---|---|---|
| `group` | text | group name, always inside the caller's current scope |

## 6. The session stream

One long-lived bidirectional stream, opened by the replica, carries the
manifest and then live push events. The replica writes `Hello` and leaves
its send half open for the life of the session; the authoritative node
never reads anything else from it.

1. Replica opens a bi stream and writes `Hello`.
2. The server **subscribes to the change broadcast before taking the
   manifest snapshot**. Every mutation committed from that moment on is
   therefore observed either inside the manifest or as a buffered push
   event — never in neither. Events that arrive while the manifest is
   still streaming queue up in the session's broadcast subscription; the
   debouncer only starts draining them once the push phase begins, so they
   surface right after `ManifestDone` (or, if enough of them accumulated to
   overflow the channel, as a single `ScopeChanged`).
3. If the caller is unregistered, the server writes `SyncDenied` and closes
   the stream. Otherwise it streams the scope's groups ordered by name.
4. For each group: one `Group`, then one or more `GroupSecrets`.
5. `ManifestDone`.
6. Push phase, until the connection ends.

**Per-group snapshot consistency.** Each group's `Group` and `GroupSecrets`
records are read under a **single store-lock acquisition** — read into
memory, release the lock, then send — so every per-group snapshot is
internally consistent. The lock is never held across a send. Consistency is
per group, not across the manifest as a whole; cross-group atomicity is
neither offered nor needed, because the apply rules are per group too.

**Chunking.** A group's secret listing is split into `GroupSecrets`
messages of at most 1000 `SecretEntry` rows to stay under the frame cap,
and there is **always at least one** `GroupSecrets` per group — an empty
group sends an empty listing rather than nothing, so absence and emptiness
never look alike. Receivers merge by name: repeated `GroupSecrets` for the
same group append to its listing, and repeated `Group` messages for the
same name append to `acl` and `deks`. The current server emits exactly one
`Group` per group (`acl` and `deks` are not chunked today, the `deks` list
being ~200 bytes per retained version); the merge rule is the contract, so
a later server may split them without a protocol break. Until it does, a
`Group` record that would exceed the cap — an ACL or a rotation history of
tens of thousands of rows — is not truncated or partially sent: framing
fails before a byte leaves, the stream dies, and the replica falls into the
reconnect loop, where it fails identically. Splitting `Group` is the fix
should such a group ever exist.

**Push events, debounced.** After `ManifestDone` the server forwards
mutations as they commit. Events are batched: the first event opens a
200 ms window, the window is extended for as long as further events keep
arriving, and the deduplicated batch is then emitted. Per batch the server
recomputes the caller's scope and sends either:

- `ScopeChanged` — if the caller's readable set differs from what this
  session last knew, **or** if the server's broadcast channel overflowed
  (events were dropped, so only a full recheck is sound); or
- one `Changed{group}` per group in the batch that is still in scope.

Mutations that touch no group data (`AddIdentity`, `SetServiceAdmin`,
`ListIdentities`, and every read) publish nothing. `RemoveIdentity`
publishes every group the removed identity held any ACL row on — the
read-granted ones rotated, and even a write-only row is part of a mirrored
ACL. Over-notification only costs a session one scope recheck;
under-notification would be a correctness bug.

### Replica reactions (normative)

| Received | Reaction |
|---|---|
| `SyncDenied` as the first reply to `Hello` | the session fails; reconnect with backoff (the replica's identity is not registered upstream; a *registered* identity with no read grants receives an empty manifest instead — see section 4) |
| `Changed{group}` | issue `FetchGroup{group}`, then apply section 8 for that group in one local transaction |
| `SyncDenied` to that `FetchGroup` | the group was deleted upstream or this replica's read was revoked: drop the group locally |
| `ScopeChanged` | **full resync**: end this session stream and open a fresh one (`Hello` → manifest → apply), preferably on the same QUIC connection |
| stream or connection failure | reconnect with exponential backoff (1 s doubling to a 60 s cap, reset once a `Hello` is answered), then full resync |

**"Full resync" means exactly that session-stream cycle.** Fetch streams
belonging to the previous session generation are abandoned. Missed events
are recovered by the resync; they are never lost silently.

The two ways a replica can lose everything are deliberately different:

- **Its identity is removed upstream.** Its scope goes empty, the server
  sends `ScopeChanged`, the replica cycles the stream, and the fresh
  `Hello` is answered with `SyncDenied` — after which it retries with
  backoff, **holding its last mirror** until an operator intervenes.
- **Its last read grant is revoked, the identity surviving.** The session
  is not denied: the next `Hello` is answered with an immediate,
  *empty* manifest, and the completed-resync rule of section 8 then drops
  every local group. The mirror empties itself and the replica keeps
  following, ready for a future grant.

## 7. Fetch streams

One request per bidirectional stream, opened by the replica, which finishes
its send half immediately after writing the request.

**`FetchGroup{group}`** → the same records as one group of the manifest —
`Group`, one or more `GroupSecrets` — terminated by `FetchDone`. This is
how a live session refreshes a single group. Unauthorized or unknown group
→ `SyncDenied` and nothing else.

**`FetchSecrets{group, names}`** → one `SecretData` per requested name, in
request order, terminated by `FetchDone`. Unauthorized or unknown group →
`SyncDenied` and nothing else.

A requested name that **no longer exists is silently omitted**;
`FetchDone` still terminates the stream. The replica treats an omitted name
as locally unchanged: the deletion propagates through the listing in the
next `Changed`-driven group sync or full resync (section 8, rule 5), not
through the absence of a `SecretData`. The peer asked from a listing that
may already be stale, which is precisely what the push channel exists to
correct.

## 8. Replica apply rules

Everything below happens **per group, in one local transaction**, against
the latest received state of that group — the connect-time manifest or a
later `FetchGroup` — so a replica's own readers never observe a
half-applied group. Change events are emitted strictly **after** the
transaction commits, which makes an event a promise that a subsequent read
sees the new state.

Before rules 1 and 2, the received ACL is collapsed to an **effective ACL**:
duplicate `identity_name`s and duplicate `endpoint_id`s are resolved
last-wins. An authoritative node cannot emit a collision (both columns are
`UNIQUE` upstream), but a malformed or hostile state must fail safe:
applied naively, two entries sharing a name would wedge the group forever —
the second entry's stale-name delete (rule 1) removes the row the first just
inserted, rule 2 then finds nothing, the transaction rolls back, and every
retry rolls back identically because the input never changes.

1. **Identities.** Upsert the identity rows referenced by the effective
   ACL, keyed by `endpoint_id`, taking the authoritative node's names.
   Before each upsert, delete any local identity row holding the incoming
   *name* under a **different** endpoint id: names are unique upstream, so
   a local collision is by definition stale (a key replacement —
   `RemoveIdentity` + `AddIdentity` under the same name), and without the
   delete that group's apply would livelock forever on the `UNIQUE(name)`
   constraint. `INSERT OR REPLACE` must **not** be used: its
   delete-and-reinsert would cascade `group_acl` rows in unrelated groups
   and reassign `identity.id`. `service_admin` is pinned to 0 on both the
   insert and the conflict-update paths — it is never synced, and a
   replica must not honour a stale local flag either.
2. **ACL.** Replace the group's ACL rows wholesale from the effective ACL.
3. **DEK versions and wraps.** Insert the `group_dek` version rows the
   state carries and this replica's own `dek_wrap` rows. Replace a local
   wrap whose blob differs from the state's: wrap blobs are stable at rest,
   so a difference means the DEK version was reissued upstream (an
   authoritative restore rewound it) and the local copy is the stale one.
   Delete local wraps the state does not carry — versions it no longer
   lists, and anything addressed to another recipient, which a mirror has
   no business holding. `group_dek` rows themselves are left alone: a
   version held without a wrap is a legitimate transient state.
4. **Secrets.** Fetch and replace every secret for which **any of
   `(current_version, dek_version, nonce)` differs** from the state, plus
   every listed secret absent locally. A name whose local row already
   matches is not fetched at all, so re-applying an unchanged state costs
   nothing.
5. **Deletions.** Delete local secrets the state does not list. A listed
   name that merely was not fetched this round is left alone — it is either
   already current or waiting for the next round.

Three rules govern what happens when the state and the fetch disagree:

- A fetched `SecretData` whose `dek_version` has no wrap in the state (a
  rotation raced the fetch) is **filtered out before the apply, not
  applied**. Applying it would wedge the secret: once a local row matches
  the state's `(current_version, dek_version, nonce)` triple it is never
  refetched, so an applied-but-undecryptable row would persist until the
  next upstream write. Instead the replica re-runs the group **once**
  (a fresh `FetchGroup` + apply); if that still skips, the group is left
  short and the next `Changed` push heals it.
- Groups **absent from the manifest** (revoked or deleted upstream) are
  dropped locally — but only on a **completed** resync, i.e. after
  `ManifestDone`. A torn stream proves nothing about absence.
- After a completed full resync (and after any group drop outside one),
  identity rows referenced by no remaining `group_acl` row are
  garbage-collected.

Only **current** secret versions are mirrored in v1. History mirroring can
be added later without protocol surgery, as a new fetch variant.

## 9. Audit

Both ends keep their own hash-chained audit log; chains are per database
(see [`../design/crypto-design.md`](../design/crypto-design.md) section
12).

The authoritative node records one entry per sync request, attributed to
the replica's EndpointId:

| `op` | `target` | `outcome` |
|---|---|---|
| `sync-hello` | (empty) | `ok` / `denied` |
| `sync-fetch-group` | group name | `ok` / `denied` |
| `sync-fetch-secrets` | group name | `ok` / `denied` |

The replica records one entry per applied group state, attributed to the
pseudo-endpoint `(sync)`:

| `op` | `target` | `outcome` |
|---|---|---|
| `sync-apply` | group name | `ok` |

Requests the replica *serves* to its own clients are audited with the
client protocol's ordinary vocabulary, with one addition: a mutation
answered by `ReadOnlyReplica` records the outcome `readonly` (see
[`protocol.md`](protocol.md) section 7).

## 10. Compatibility

- Variant and field **names are the contract** — never rename them. Adding
  new variants or fields is backwards-compatible; decoders must treat an
  unknown message variant as an error and should ignore unknown fields
  within known variants.
- The encoding is pinned by golden vectors in
  `sync::tests::wire_format_is_stable` (`src/sync.rs`). A failure there
  means the wire format changed and every non-Rust implementation breaks.
  The vectors are self-contained: unlike the client protocol's, they have
  no counterpart in another language yet, and should gain one in lockstep
  when a non-Rust replica appears.
- Protocol revisions that break these rules must bump the ALPN
  (`secret-bunker-sync/2`), not mutate `secret-bunker-sync/1`. Version
  negotiation is ALPN negotiation and nothing else: there is no in-band
  version field, and a peer that speaks only the other version fails to
  connect rather than half-speaking this one.

## 11. What sync does *not* do

- It does not carry plaintext, unwrapped DEKs, or wraps addressed to
  another recipient.
- It does not proxy writes. A replica answers mutations from its own
  clients with `ReadOnlyReplica` ([`protocol.md`](protocol.md) section 7).
- It does not chain: replicas do not mount this ALPN (section 1).
- It does not mirror history, only current versions (section 8).
- It offers **no staleness bound**. A partitioned replica keeps serving its
  last mirror — that is the point — which also means an ACL revocation is
  enforced there only once the replica applies the sync that carries it.
  See [`../design/crypto-design.md`](../design/crypto-design.md) sections
  2, 7 and 12.
