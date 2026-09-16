# Epoch records for secret-bunker-iroh: a systems-integration design

This document lands the signed, self-verifying **epoch record** in the codebase as
it exists today (schema v2, `secret-bunker/1`, `secret-bunker-sync/1`, the Go
client, the k8s operator embedding `Replica`). It is written to be planned from:
every table, wire name, verifier rule and transaction is named.

Reading guide: sections 1–3 are the crypto and the rules (brief items 1, 2);
section 4 is what a kick does to ciphertext (item 3); section 5 is roles and
modes (item 4); sections 6–11 are storage, protocol, sync, migration, operator,
CLI (item 5); section 12 is the trade-off against age-wraps-plus-signature
(item 6); 13–15 are threat-model delta, delivery phases and tests.

## 0. Summary of what changes

- A group's key management becomes a hash chain of **epoch records** stored
  verbatim in a new `epoch` table. Each record carries the full ACL, the
  multi-recipient ElGamal wraps of the current DEK generation, a batched
  Chaum-Pedersen proof, a key-check value, a digest of the secret versions that
  were re-encrypted, and the author's Ed25519 signature (the author's iroh key).
- `group_dek` stays as the generation registry and gains an `epoch` column;
  `secret_version.dek_version` and the AAD function are **unchanged**. Legacy
  age-wrapped generations stay in `dek_wrap` for cold history; hot generations
  live in epoch records. Reader age wraps disappear.
- The server verifies and serializes records (CAS on `prev`), applies each in
  one SQLite transaction together with the re-encrypted current versions, and
  publishes the chain to replicas over `secret-bunker-sync/2`. Replicas verify
  the chain themselves and authorize from the verified head, not the roster.
- Existing client requests keep their names and, in the default
  "server-recipient" mode, their behavior: the server authors the epochs those
  requests imply, signed with its endpoint key. New additive requests let a
  group admin author epochs client-side (kick, rotate, grant) with their own
  key, which is the attributable path the CLI/TUI use.
- The backup key stays the existing age X25519 key, re-interpreted as an
  Edwards ElGamal recipient. No key ceremony at migration.

## 1. Wrapping and proof scheme

### 1.1 Groups, points, keys

Everything is on the Ed25519 twisted Edwards curve, prime-order subgroup of
order `l`, basepoint `B` (`curve25519_dalek::constants::ED25519_BASEPOINT_POINT`).
`curve25519-dalek` 5 is added as a direct dependency (it is already in the tree
via `ed25519-dalek` 3).

| Party | Public point | Secret scalar | How obtained |
|---|---|---|---|
| Registered identity (reader) | `A_i = VerifyingKey::from_bytes(endpoint_id).to_edwards()` | `a_i = SigningKey::from_bytes(iroh secret).to_scalar()` (clamped) | from the iroh key it already has |
| Backup (pinned) | `A_bk = MontgomeryPoint(u_bk).to_edwards(0)` where `u_bk` is the 32-byte body of the `age1…` recipient | `a_bk = clamp(bech32-decode(AGE-SECRET-KEY-…))`; sign fixed at use (1.4) | the existing backup age key |
| Operational (pinned, mode A only) | as backup, from `operational.age`'s recipient | as backup | the existing operational age key |
| Authoritative server (author only, never a recipient) | its EndpointId | its endpoint secret key | the key replicas already dial |

`A_i = a_i·B` holds for Ed25519 keys because the public key *is* the clamped
scalar times `B`. Point encodings are 32-byte compressed Edwards Y. Every point a
verifier reads is decoded with `CompressedEdwardsY::decompress`, then
**re-compressed and byte-compared** (canonical encoding) and checked with
`is_torsion_free()`. `AddIdentity` additionally rejects an endpoint id whose
point is not torsion-free, so a non-conforming key never becomes a recipient.

### 1.2 Wrap (author side)

Input: the set of recipients `R = readers(acl) ∪ pinned` (sorted by 32-byte
public key, no duplicates), and either a fresh generation or the current one.

```
mint:     m ← Scalar::random;  M = m·B                    (new DEK generation)
rewrap:   M = value recovered from the author's own wrap in the head record
r ← Scalar::random;  c0 = r·B
for each recipient i:  c_i = M + r·A_i
PRK  = HKDF-Extract(salt = group_genesis (32 B, all-zero for epoch 1), IKM = M.compress())
DEK  = HKDF-Expand(PRK, "secret-bunker-iroh/dek/1",    32)
KCV  = HKDF-Expand(PRK, "secret-bunker-iroh/commit/1", 32)      -- published as `commit`
```

HKDF is HKDF-SHA256 (`hkdf` 0.12 is already in the tree via age). `DEK` feeds
the existing `crypto::encrypt_secret` unchanged. Binding the salt to the group's
genesis hash makes a DEK unusable across groups without touching the AAD.

For epoch 1 the salt is 32 zero bytes: the genesis hash is not known until the
record is built, and the record embeds the wraps.

### 1.3 Proof (batched Chaum-Pedersen / Schnorr for a linear map)

Statement: there exists `r` with `c0 = r·B` and, for every `i ≥ 2`,
`c_i − c_1 = r·(A_i − A_1)`. Recipients are indexed in their sorted order.

```
k ← Scalar::random
T_0 = k·B;   T_i = k·(A_i − A_1)   for i = 2..n
e   = Scalar::from_hash(SHA-512(
        "secret-bunker-iroh/dleq/1" || genesis || epoch(u64 BE) || c0 ||
        for i=1..n: A_i || c_i   ||   T_0 || T_2 || … || T_n ))
s   = k − e·r
proof = e.to_bytes() || s.to_bytes()      (64 bytes, fixed, independent of n)
```

Verification (anyone, no key):

```
T_0' = vartime_double_scalar_mul_basepoint(e, c0, s)        -- e·c0 + s·B
T_i' = s·(A_i − A_1) + e·(c_i − c_1)                        -- vartime_multiscalar_mul
e'   = hash as above with T'_* ;   accept iff e' == e
```

Cost: prover `2n+2` scalar mults, verifier `2n` double-scalar mults, ~100 µs
per recipient on commodity hardware. A 50-reader epoch verifies in ~5 ms.

### 1.4 Decrypt (recipient side)

```
verify the record first (section 3) — never open an unverified record
reader i:  M = c_i − a_i·c0
backup:    A = a_bk·B;  if A == A_bk: M = c_bk − a_bk·c0  else (A == −A_bk): M = c_bk + a_bk·c0
derive DEK, KCV;  require KCV == record.commit   (wrong key fails loudly)
```

The backup sign rule exists because an age recipient carries only the
Montgomery `u`, which determines the Edwards point up to sign; the record pins
the sign-0 candidate and the key holder, who has the scalar, resolves it. The
same rule applies to the operational age key.

### 1.5 What is and is not proven

Proven, to a verifier with no key, under discrete log in the prime-order
subgroup with SHA-512 as a random oracle (Fiat-Shamir Schnorr, soundness by
rewinding): the author knows one `r` such that `c0 = r·B` and
`c_i − r·A_i = c_1 − r·A_1` for all `i`. Hence every recipient recovers the same
`M`, the same `DEK`, and the same `KCV`. With the torsion-free and canonical
checks there is no small-subgroup component for `M` to differ by. The explicit
recipient list plus rule V5 (recipients == readers ∪ pinned) means **there is no
hidden recipient**: a wrap to an unlisted key would be a visible, rejected entry.

Confidentiality: multi-recipient ElGamal with shared randomness is IND-CPA under
DDH in the prime-order subgroup; the DEK is a PRF of `M`, so publishing `KCV`
leaks nothing about `DEK`. The scheme is not CCA-secure on its own; it does not
need to be, because recipients only decrypt records that carry a valid signature
by an authorized author and pass verification. Joint use of one Ed25519 key for
TLS signing and DH-style decryption is the same setting as today's age bridge
(the Edwards and Montgomery forms are isomorphic groups; the analysis cited in
`design/crypto-design.md` section 3 applies unchanged).

Not proven, and stated so:

- That `M` in a non-minting epoch equals the previous generation's `M`. The
  verifier checks `commit == prev.commit`; a recipient detects a mismatch on
  decrypt (KCV). In mode A the server detects it at submission (it is a
  recipient). In mode B a lying admin makes the group unreadable until another
  admin mints — a denial an admin could cause anyway.
- That the re-encrypted ciphertexts decrypt to the same plaintext as before.
  The signed `reencrypted` digest makes the author accountable for exactly
  those bytes; the AEAD guarantees they were produced under the claimed DEK
  only if they decrypt at all. In mode A the server trial-decrypts every staged
  version before committing; in mode B a garbage re-encryption is detectable
  only by someone who knew the old plaintext.
- That the author did not leak `M` out of band. No scheme can.

## 2. The epoch record

### 2.1 Encoding

A record on the wire and on disk is the CBOR map `{"body": bytes, "sig": bytes}`.
`body` is a CBOR byte string whose content is the author's serialization of the
fields below; `sig` is 64 bytes. Verifiers **hash and verify the `body` bytes
exactly as received and store them verbatim**; nothing is ever re-serialized.
This avoids any canonical-CBOR requirement: the author only has to be
deterministic with itself. The parser is strict: duplicate keys, unknown keys,
wrong types and trailing bytes are rejected; a future field bumps `v`.

`body` fields (a CBOR map with text keys, written in this order):

| key | type | meaning |
|---|---|---|
| `v` | uint | `1` |
| `group` | text | group name |
| `epoch` | uint | `1` for genesis, then `+1` |
| `prev` | bytes(32) | hash of the previous record; 32 zero bytes at genesis |
| `genesis` | bytes(32) | hash of record 1; 32 zero bytes at genesis |
| `at` | int | author's unix seconds |
| `author` | bytes(32) | author's EndpointId (raw) |
| `acl` | array of `[bytes(32), uint]` | full ACL after this epoch, sorted by endpoint id, unique; perms ⊆ `r=1,w=2,a=4` |
| `pinned` | array of `[text, bytes(32)]` | `["backup", A_bk]` always; `["operational", A_op]` in mode A; sorted by role |
| `dek_version` | uint | the `group_dek.version` this epoch's wraps open |
| `mint` | bool | this epoch created `dek_version` |
| `keys` | map, optional | `{"c0": bytes(32), "wraps": [[bytes(32) pk, bytes(32) c_i], …] sorted by pk, "proof": bytes(64), "commit": bytes(32)}` |
| `carry` | map, optional | `{"from": uint epoch, "removed": [bytes(32), …]}` — exactly one of `keys`/`carry` is present |
| `reencrypted` | bytes(32) | digest of section 2.3; 32 zero bytes when `mint == false` |

Sizes: ~150 B fixed + 36 B per ACL row + 66 B per recipient + 64 + 32 + 32 + 64
(sig). A 50-reader group is ~5.5 KB per record.

### 2.2 Hash and signature

```
hash = SHA-256("secret-bunker-iroh/epoch/1" || body)
sig  = Ed25519(author secret key, "secret-bunker-iroh/epoch-sig/1" || hash)
```

Verification uses `VerifyingKey::verify_strict`. The server's stored `hash`
column is this value; `prev`/`genesis` reference it.

### 2.3 The `reencrypted` digest

Over the re-encrypted secret versions submitted with a minting epoch, sorted by
`(name, version)`:

```
leaf_j = SHA-256(0x00 || len(name) u64 BE || name || version u64 BE ||
                 dek_version u64 BE || nonce (12 B) || SHA-256(ciphertext))
reencrypted = SHA-256(0x01 || leaf_1 || … || leaf_n)
```

A flat digest, not a Merkle tree: nobody needs partial proofs, and the whole
set is always presented together.

## 3. Verifier rules (identical code on server and replicas)

`epoch::verify(record, prev: Option<&Record>, ctx { authoritative: EndpointId, genesis: Option<Hash> }) -> Result<Verified>`.

| # | Rule | On failure |
|---|---|---|
| V1 | Strict parse; `v == 1`; `group` matches the group being applied | reject |
| V2 | Genesis (`prev == None`): `epoch == 1`, `prev` and `genesis` zero. Otherwise `epoch == prev.epoch + 1`, `prev == hash(prev)`, `genesis == ctx.genesis` | reject |
| V3 | `sig` verifies under `author` | reject |
| V4 | Authorship. Genesis: `author ∈ admins(acl)`. Later: `author ∈ admins(prev.acl)` **or** `author == ctx.authoritative` (a *server-authored* epoch, subject to V9) | reject |
| V5 | ACL sorted, unique, perms ⊆ 7. At least one admin — except a server-authored epoch may leave zero admins (compromised-identity removal always wins; recovery is a later server-authored epoch, 11.5) | reject |
| V6 | Recipients. With `keys`: set(wraps.pk) == readers(acl) ∪ pinned.pk, no duplicates, all points canonical and torsion-free, `c0` likewise. With `carry`: `from ≤ prev.epoch`, epoch `from` has `keys`, effective set = wraps(from) − removed, and the same equality holds against this epoch's readers ∪ pinned; `removed ⊆ wraps(from)` | reject |
| V7 | Generation. `mint == true` ⇒ `keys` present and `dek_version > prev.dek_version` (genesis: any value ≥ 1). `mint == false` with `keys` ⇒ `dek_version == prev.dek_version` and `commit == prev_keys.commit`. `carry` ⇒ `mint == false`, `dek_version == epoch[from].dek_version` | reject |
| V8 | `pinned == prev.pinned` unless server-authored; exactly one `backup` always; at most one `operational` | reject |
| V9 | Server-authored epochs are shape-restricted: (a) genesis; (b) `carry` whose ACL differs from `prev.acl` only by removed rows or cleared bits (never adds a bit); (c) `keys` with ACL == `prev.acl` and only `pinned` changed (a re-pin/recovery: `mint` may be true or false); (d) anything, **if and only if** `prev.pinned` contains `operational` (mode A: the server is a reader and its `Grant`/`RotateDek`/`RemoveIdentity` handlers author freely, as they do today) | reject |
| V10 | DLEQ verifies (1.3) when `keys` present. (The `from` epoch of a `carry` was verified when it was applied; removing recipients from a proven set preserves the property for the rest) | reject |
| V11 | `at ≥ prev.at` (monotone; no wall-clock comparison anywhere) | reject |

The server additionally enforces, at submission (not chain-verifiable): the
deliverer's transport EndpointId equals `author`; `author` is a registered
identity (or the server itself); for minting epochs the staged set matches
`reencrypted` and covers every current version (section 8); in mode A the
server decrypts `M` and checks `commit`, and trial-decrypts every staged
version.

### 3.1 Who may do what (recommended defaults)

- **Any group admin may kick any reader, including another admin, and may
  remove itself**, as long as V5 leaves one admin. This is today's `Grant`
  semantics made verifiable; a single compromised admin key was already a
  full-group compromise (it can read everything and grant anyone), and a
  quorum would only trade that for lockout risk. Offered as an open question.
- **Rotate (mint) requires holding `read`** in `prev.acl`, not as a rule but by
  construction: without a wrap the author has no `M` to re-encrypt from. A
  `carry` epoch (w/a-bit edits, revoke-without-rotate) needs no `M`, so an
  admin without `read` can still edit write/admin bits.
- **Adding a reader requires `M`** (a `keys` epoch with `mint == false`), hence
  a reader-admin — the role the brief calls for, replacing the operational key
  in today's `wraps_for_new_reader`.
- **Service admins** keep their implicit `read|write|admin` on the *server's*
  request handling in mode A (the server decrypts for them). They have no
  standing in the chain: to author an epoch they need an explicit `admin` row,
  exactly as sync already refuses the implicit read. In mode A the server
  authors on their behalf (server-authored epoch, V9(d)); in mode B they must
  be granted like anyone else.
- **Last admin / lockout**: V5 for human-authored epochs; server-authored
  removal may orphan; the orphan recovery is `db grant` (11.5), which now
  produces a server-signed epoch that replicas verify like any other.

## 4. What "kick + roll the key" does to ciphertext

### 4.1 Re-encrypt current versions; history goes cold

A minting epoch re-encrypts **every current secret version** of the group under
the new generation, in place (same `version` number; new `dek_version`,
`nonce`, `ciphertext`; `created_at`/`created_by` untouched because the logical
write did not change). Non-current `secret_version` rows are left under their
old generation.

Why current-only is the right default here:

- `secret-bunker/1` has no way to read a non-current version (`Get` has no
  version parameter; `secret_current` is the only read). History is reachable
  only by the operator with database access plus the operational or backup key.
- The kicked reader already holds the old DEK; re-encrypting history denies it
  nothing it did not have. What it must not get is anything written *after* the
  kick, and any *current* value — both are under the new generation.
- Cost is bounded by the group's live size, not its write history.

Retired generations keep their wraps for pinned recipients: legacy generations
via `dek_wrap` (age), epoch generations via their own records, which stay in
the chain forever (a chain must be walkable from genesis to be verifiable, so
"pruning old wraps" is dropped from the skeleton — the wraps are public-key
ciphertext the kicked reader could open anyway). A reader added later has no
wrap for old generations, which is consistent with "history is operator-only".

The alternative — re-encrypt every retained version — is supported by the same
mechanism (the client may include non-current versions in the staged set; the
server accepts any superset of the current set whose `dek_version` matches),
exposed as `--with-history`. Bandwidth then scales with total history size.

### 4.2 Bandwidth

Per version: download `len + 16` bytes of ciphertext, upload the same. A kick
costs `2 × S_current` over the admin's iroh connection where `S_current` is the
group's live ciphertext size. 200 tokens of 100 B: 40 KB. 50 config files of
200 KB: 20 MB. Pathological: 1000 × 4 MiB = 8 GiB, minutes, still correct.
Replicas then refetch `S_current` each (nonce changed for every secret). After a
`--with-history` kick, multiply by history depth.

Server-side authoring in mode A (the `Grant`/`RotateDek` compatibility path)
costs no bandwidth: the server holds both DEKs and re-encrypts locally in the
same transaction, as `revoke_read_and_rotate` does today minus the
re-encryption it did not do.

### 4.3 Atomicity

The client does `fetch → decrypt → re-encrypt → stage → submit`; the server
applies in **one SQLite transaction**: epoch row, `group_dek` row, ACL
replacement, in-place `UPDATE secret_version` for each staged version, staging
cleanup, audit rows. Readers see the old generation until that commit and the
new one after; there is no intermediate state. A crash before commit leaves
only staging rows, which expire.

Concurrent `Put` during the client's window: the server's coverage check fails
(`StaleVersions{names}`), the client refetches those names, restages, recomputes
`reencrypted`, re-signs, resubmits (bounded retries). Writers are never blocked.

### 4.4 Attribution

`author` + `sig` on the minting record answers "who last re-encrypted"; the
`reencrypted` digest binds that signature to the exact ciphertexts. The server's
audit log keeps its `endpoint_id` row (`epoch-submit`, target `group#epoch`) and
the `epoch` table's `author` column is queryable; `GroupStatus` (7.2) exposes
`last_author`/`last_at`. Per-put signatures on individual versions are the
natural next step and are out of scope.

## 5. Roles, deployment modes, threat model

### 5.1 Mode A: server-recipient (default; preserves today's behavior)

The operational age key, re-interpreted on Edwards, is pinned in every epoch.
The server derives the current DEK from its own wrap (cached per
`(group, dek_version)` in a zeroizing map) and:

- serves plaintext `Get` and accepts plaintext `Put` exactly as today;
- authors epochs for `CreateGroup` (genesis), `Grant`, `RotateDek`,
  `RemoveIdentity`, signed with its **endpoint key** (the identity replicas
  already dial), so the Go client and old CLIs keep working unchanged;
- checks `commit` and trial-decrypts staged versions on every `SubmitEpoch`.

Service admins keep implicit read. Write-only identities keep `Put`.

### 5.2 Mode B: end-to-end

No `operational` in `pinned`. The server never holds `M`. Consequences, all
explicit:

- `Get` on such a group answers `Failed{reason: "sealed group: use GetSealed"}`;
  `GetSealed` returns ciphertext for any reader; `PutSealed` is the only write.
- Write-only identities (no `read`) cannot `Put` (no DEK); they can `Delete`.
  Documented loss; grant `read` or keep those groups in mode A.
- Service-admin implicit read disappears for these groups. Group creation is a
  client-authored genesis (`SubmitEpoch` with `epoch == 1`, service-admin
  gated).
- `Grant` changing read bits, and `RotateDek`, answer `Failed` with a pointer to
  the client-side flow; `Grant` touching only w/a bits still works (server
  authors a `carry`, V9(b) only if it removes; adding a w/a bit needs a human
  author — the CLI does it).
- `RemoveIdentity` authors a `carry` tombstone per readable group (removes the
  reader and its wrap) and sets `secret_group.needs_rotation = 1`; the ACL
  denial is immediate; any admin mints next. `GroupStatus.needs_rotation` and
  the TUI `!` marker surface it.
- Replicas and the operator are unchanged: they are readers with their own
  wrap.

Mode is a property of the group's chain (`pinned`), so groups can be mixed. The
server-level default `meta.dek_mode ∈ {server-recipient, e2e}` decides what the
migration epoch and server-minted genesis do. A→B for a group is a
server-authored re-pin (V9(c)) followed by an admin mint (the server cannot
un-know `M`); B→A needs an admin to include the operational point in a mint.

### 5.3 The backup key

Stays the existing age X25519 key. Its Edwards point is pinned in every epoch;
recovery derives the scalar from the age identity and resolves the sign (1.4).
`recover` gains a second job: for epoch generations it recovers `M` from
`c_bk`, then authors one server-signed re-pin epoch per group (V9(c)) with a
fresh `r` to the new operational point, needing `--endpoint-key` alongside
`--backup-key`. Legacy generations are handled by today's `apply_recovery`.
Switching the backup to a native Ed25519 key later is a server-authored re-pin;
not required.

### 5.4 Replicas

A replica verifies every record before applying (section 9), authorizes from
the verified head's ACL, decrypts with `a_i = SigningKey::to_scalar()` of its
endpoint key, and keeps its last good mirror on any verification failure. It
still needs exactly one key.

### 5.5 Threat-model delta

Gains:

- A compromised or hostile authoritative node **cannot add a reader or raise a
  permission** on a mode-B group: every additive change must be signed by a
  group admin, and replicas check. It can still remove (V9(b)) and withhold —
  liveness only, as today.
- Every ACL/key change is attributable to a specific key, and the last
  re-encryption is attributable and bound to exact bytes.
- No hidden recipient is possible; recipient sets are explicit and checked.
- Reader wraps shrink from ~200 B (age) to 32 B.

Losses / new surface:

- Custom curve code (ElGamal, DLEQ, torsion/canonical checks) replaces a
  standard age format for hot generations. Mitigated by golden vectors and a
  small, isolated `epoch` module.
- A kick by an admin moves `2 × S_current` bytes and takes seconds instead of a
  millisecond server-side rotation (mode A keeps the fast path).
- Mode B removes write-only writes and service-admin implicit read.
- The admin's machine holds the group's plaintext in memory during a kick (it
  could read it all anyway).
- History under a burned key is still readable by the kicked reader from a
  stolen database — unchanged from today, now documented as "history is cold".

## 6. Storage: schema v3

### 6.1 Tables

```sql
-- new
CREATE TABLE epoch (
  group_id    INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
  epoch       INTEGER NOT NULL,
  hash        BLOB    NOT NULL,          -- SHA-256 of body (2.2)
  body        BLOB    NOT NULL,          -- exact signed bytes, never re-serialized
  sig         BLOB    NOT NULL,          -- 64 bytes
  author      TEXT    NOT NULL,          -- hex endpoint id, denormalized for queries
  dek_version INTEGER NOT NULL,
  mint        INTEGER NOT NULL,          -- 0/1
  created_at  INTEGER NOT NULL,          -- server clock at apply
  PRIMARY KEY (group_id, epoch),
  UNIQUE (group_id, hash)
);
CREATE TABLE epoch_staging (
  group_id    INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
  epoch_hash  BLOB    NOT NULL,
  name        TEXT    NOT NULL,
  version     INTEGER NOT NULL,
  dek_version INTEGER NOT NULL,
  nonce       BLOB    NOT NULL,
  ciphertext  BLOB    NOT NULL,
  staged_at   INTEGER NOT NULL,
  PRIMARY KEY (group_id, epoch_hash, name, version)
);
-- altered
ALTER TABLE secret_group ADD COLUMN genesis_hash   BLOB;                       -- NULL until migrated
ALTER TABLE secret_group ADD COLUMN head_epoch     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE secret_group ADD COLUMN needs_rotation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE group_dek    ADD COLUMN epoch          INTEGER;                    -- NULL = legacy age generation
-- meta
('schema_version','3'), ('dek_mode','server-recipient'|'e2e')
```

`group_dek` remains the generation registry (`version` continues the same
counter, so `secret_version.dek_version` and `crypto::secret_aad` are
untouched). `dek_wrap` keeps only legacy rows: `operational` and `backup` for
generations with `group_dek.epoch IS NULL`; reader rows are deleted at
migration. `secret_version` is unchanged. The read path dispatches on
`group_dek.epoch`: `NULL` → age unwrap (server only, via the operational
identity; replicas hold none after their first v2 apply); otherwise → find the
newest record with that `dek_version` that carries a wrap for the caller
(server: the operational point; replica: its own endpoint point).

The server's `group_acl` table stays the authorization source for request
handling and is kept **identical to the head record's ACL** by the apply
transaction. Replicas do the same from the verified head.

### 6.2 Migration v2 → v3

SQL part, in `migrate()` on open (pure, idempotent): the DDL above, stamp `3`.

Crypto part, at authoritative `serve` startup before the sync ALPN is mounted
(the slot `backfill_reader_wraps` occupies today), per group with
`genesis_hash IS NULL`, one transaction each:

1. Unwrap the current legacy DEK with the operational identity.
2. Mint `M`, `dek_version = MAX(group_dek.version) + 1`, DEK/KCV.
3. Decrypt and re-encrypt every current version under the new generation.
4. Build epoch 1: `acl` from `group_acl`, `pinned` from the two age
   recipients' Edwards points (`operational` only if `dek_mode` is
   server-recipient), wraps to readers ∪ pinned, proof, digest; sign with the
   server endpoint key.
5. Insert `epoch`, `group_dek(version, epoch=1)`, update versions in place,
   set `genesis_hash`/`head_epoch = 1`, delete `dek_wrap` rows whose recipient
   is an endpoint id, audit `epoch-migrate`.

Groups already migrated are skipped, so a crash mid-way resumes. Wall time is
one AEAD decrypt+encrypt per current version; a 10k-secret bunker migrates in
seconds. **Back up the SQLite file before the first v3 start.** The
authoritative node cannot start v3 without the operational key it already
needs. After migration, age wraps and epoch records coexist permanently for
cold history and never for hot generations.

Replica mirrors: `migrate()` applies the same DDL. The replica keeps serving its
old mirror from its legacy age wraps until each group's first v2 apply, which
fetches every current version (all nonces changed) and, because `deks` now
arrives empty, deletes the local age wraps in that same transaction (rule 3
unchanged). No mirror wipe, no serving gap.

## 7. Client protocol: additive requests on `secret-bunker/1`

Existing variants and fields are untouched; the Go client keeps working. New
variants use the same externally-tagged CBOR. Endpoint ids in request fields
stay 64-char hex (protocol convention); records and ciphertexts are byte
strings.

### 7.1 Requests

| Request | Requires | → |
|---|---|---|
| `GroupStatus {group}` | `read` or `admin` | `Status` |
| `GroupEpochs {group, since}` | `read` or `admin` | `Epochs` (records with `epoch > since`, byte-budgeted; page with the last returned epoch) |
| `GetSealed {group, name}` | `read` | `Sealed` |
| `ListSealed {group, after, limit}` | `read` | `SealedList` (current versions with ciphertext, ordered by name, as many whole entries as fit 3.5 MiB; a lone oversize entry is returned alone) |
| `PutSealed {group, name, dek_version, nonce, ciphertext, expected_version}` | `write` | `Version`, `VersionConflict`, `DekConflict` (if `dek_version` is not the head generation) |
| `StageReencrypted {group, epoch_hash, versions}` | `admin` | `Ok` |
| `SubmitEpoch {group, record, versions}` | see 8 | `Ok`, `EpochConflict`, `StaleVersions`, `Failed` |

`versions` entries are `SealedVersion {name, version, dek_version, nonce, ciphertext}`.
`SubmitEpoch.record` is the `{"body","sig"}` map encoded as one byte string.
`SubmitEpoch` with `record.epoch == 1` and an unknown group name **creates the
group** (service admin required); this is how mode B groups are made.

### 7.2 Responses

```
{"Status":        {"epoch": 12, "head_hash": h'…', "dek_version": 9, "mint_epoch": 11,
                   "last_author": "1a98…", "last_at": 1770000000,
                   "e2e": false, "needs_rotation": false}}
{"Epochs":        {"records": [h'…', h'…']}}
{"Sealed":        {"version": 4, "dek_version": 9, "nonce": h'…', "ciphertext": h'…'}}
{"SealedList":    {"versions": [{"name": "db", "version": 4, "dek_version": 9,
                                 "nonce": h'…', "ciphertext": h'…'}], "next": "db"}}
{"DekConflict":   {"current": 9}}
{"EpochConflict": {"head_epoch": 12, "head_hash": h'…'}}
{"StaleVersions": {"names": ["db"]}}
```

`Failed` and `Denied` semantics are unchanged; all new mutations answer
`ReadOnlyReplica` on a replica. `touched_groups` gains the new mutating
variants (`StageReencrypted` touches nothing; `SubmitEpoch`/`PutSealed` touch
their group). Golden vectors for every new variant go into
`proto::tests::wire_format_is_stable` and the Go test file in lockstep.

## 8. Server-side validation and atomic apply of `SubmitEpoch`

```
1. ident = identity_by_endpoint(remote) else Denied
2. parse record strictly; require record.author == remote's endpoint id  (else Denied)
3. group lookup:
   - absent and record.epoch == 1: require ident.service_admin (else Denied); prev = None
   - present: require admin bit on the group per group_acl (== head.acl) unless
     the record is a genesis for an existing name → Failed; prev = head record
4. epoch::verify(record, prev, ctx{authoritative = own endpoint id, genesis})
   → Failed{reason} on any V-rule
5. CAS: record.prev == head.hash && record.epoch == head_epoch + 1
   else EpochConflict{head_epoch, head_hash}
6. if mint:
   a. require record.dek_version == MAX(group_dek.version) + 1  (server knows legacy versions)
   b. staged = rows in epoch_staging with epoch_hash == hash(record) ∪ inline versions
      (inline wins on duplicate key)
   c. current = every (name, version) that is the secret's current_version
      require current ⊆ staged.keys, every staged.dek_version == record.dek_version,
      staged may contain non-current versions of listed names (--with-history)
      else StaleVersions{names: current − staged}
   d. digest(staged sorted) == record.reencrypted else Failed
   e. mode A (operational ∈ pinned): M = c_op ∓ a_op·c0; KCV == commit else Failed;
      for each staged: decrypt_secret(DEK, aad(group,name,version,dek_version)) must succeed
      else Failed{"undecryptable re-encryption of <name>"}
   else (keys, !mint): mode A: check KCV as above
7. ONE transaction:
   INSERT epoch; if mint: INSERT group_dek(version, epoch); 
   UPDATE secret_version SET dek_version, nonce, ciphertext for each staged row
     WHERE secret_id/version match (rows must exist; else rollback → StaleVersions);
   DELETE FROM group_acl WHERE group_id; INSERT rows from record.acl;
   UPDATE secret_group SET head_epoch, genesis_hash (genesis), needs_rotation = 0 if mint;
   DELETE FROM epoch_staging WHERE group_id;   -- all stagings, any hash
   audit("epoch-submit", "group#n", "ok");  (and "rotate-dek" when mint, for continuity)
   COMMIT; publish change event for the group
```

Staging: `StageReencrypted` requires `admin`, one open staging per group at a
time (a different `epoch_hash` for the same group replaces the previous rows),
a per-group byte cap of `2 × current ciphertext bytes + 16 MiB`, and rows older
than 15 minutes are swept on the next `StageReencrypted`/`SubmitEpoch` for that
group. Nothing visible changes until step 7.

Server-authored epochs (mode A `Grant`/`RotateDek`/`RemoveIdentity`/`CreateGroup`,
mode B tombstones, migration, `db grant`, `recover`) go through the same
`verify` + step 7 with the server as author; `RemoveIdentity` batches one
epoch per readable group (mint in mode A, `carry` tombstone in mode B) plus a
`carry` for w/a-only groups in the single transaction `remove_identity_with_rotations`
already provides. `Put` (mode A) derives the DEK from the head record's
operational wrap instead of `dek_wrap('operational')` once
`group_dek.epoch IS NOT NULL`.

## 9. Sync protocol v2 and replica verification

ALPN `secret-bunker-sync/2`; v1 is not served after the upgrade (it would need
server-minted age reader wraps, which mode B cannot produce). Message and field
names are kept; changes are additive.

- `Group` gains `epochs: [bytes]` (records in ascending order, byte-budgeted at
  3 MiB per message; the existing "repeated `Group` messages append" merge rule
  carries it), `head_epoch: uint`, `head_hash: bytes`. `acl` stays and now
  serves **only to map endpoint ids to identity names**. `deks` stays and is
  always empty (legacy field).
- `FetchGroup` gains optional `have_epoch: uint`; the server ships records with
  `epoch > have_epoch`. The `Hello` manifest ships the full chain per group (a
  chain is one record per ACL change; 100 records ≈ 300 KB). A future
  `Hello{heads}` can trim it; not needed now.
- `SecretData`/`SecretEntry` are unchanged; the `(current_version, dek_version,
  nonce)` discriminator already detects re-encryption.

Replica apply, per group, one transaction, replacing rules 1–3 of
`apply_group_sync`:

| Rule | Replica behavior |
|---|---|
| R0 chain | Take local head (if any). Received records must start at `local_head + 1` (or at 1 on first sight; if `have_epoch` was sent and the server starts later, refetch without it). Verify each with `epoch::verify` against the previous (local or just-verified), `ctx.authoritative` = the stamped authoritative id, `ctx.genesis` = stored `genesis_hash` (TOFU on first sight). Any failure ⇒ **reject the whole group state**, keep the mirror, audit `sync-apply` outcome `rejected`, emit `ReplicaEvent::EpochRejected{group, epoch, reason}`, back off that group until the next `Changed`/resync. |
| R0' rewind | A `head_epoch` below the local head, or a `head_hash` that differs at the same epoch, is a fork ⇒ reject as above. An operator who restored the authoritative node from backup resets the mirror with `db drop-group --db mirror.sqlite --group g` (or deletes the mirror). Today's silent wrap-replacement on rewind is deliberately not carried over. |
| R1 identities | As today, from the roster — but only for endpoint ids present in the verified head ACL; roster rows for other ids are ignored; a head-ACL id with no roster entry gets the name `<hex[..8]>` rather than failing. `service_admin` pinned 0. |
| R2 ACL | Replace wholesale from the **verified head record**, never from the roster. A roster `perms` that disagrees with the record is ignored (and logged once). |
| R3 keys | Store the new epoch rows. Require the head generation opens for this replica: its endpoint point must be in the effective wrap set (V6 already guarantees it iff it holds `read`); derive `M`, check KCV; on KCV failure reject the state. Delete any legacy `dek_wrap` rows the state does not list (`deks` is empty ⇒ all of them). |
| R4/R5 secrets | Unchanged. A fetched `SecretData` whose `dek_version` is not opened by any stored record for this replica is filtered before apply and the group is re-run once (today's rule). |

A replica does not mount the sync ALPN and never authors; nothing in its
mirror can promote it. Its `Get` path becomes: head-generation record → own
wrap → DEK (cached, zeroized) → `decrypt_secret`, with the legacy age path
retained only while legacy wraps exist locally.

## 10. Kubernetes operator impact

- API: `Replica`, `ReplicaBuilder`, `get/list/groups/status/subscribe` are
  unchanged. One additive `ReplicaEvent::EpochRejected{group, epoch, reason}`
  variant: `operator/src/events.rs` matches exhaustively and needs an arm
  (warn log, counter `bunker_epoch_rejected_total{group}`, and a
  `Degraded`/`ChainRejected` condition on affected `BunkerSecret`s is
  reasonable but optional).
- A mint re-encrypts every secret in the group, so every `BunkerSecret` on it
  receives `SecretChanged` at once. `reconcile.rs` already compares the desired
  content hash before patching (line 296), so this is a no-op storm; verify with
  a `reconcile_apply` test that a rotation produces zero Secret updates.
- Keys: still exactly one mounted Secret (endpoint key). Chart, CRD, RBAC:
  unchanged. Onboarding: still "grant `read` to the pod's EndpointId" — now via
  a client-side epoch by a group admin, or server-side `Grant` in mode A.
- CPU: chain verification is milliseconds per group per resync.
- Upgrade order: authoritative node first (it migrates and switches to
  `sync/2`), then operator image. Between the two the operator's replica fails
  ALPN negotiation and serves its last mirror (existing behavior); after the
  upgrade it converges group by group with no serving gap (6.2).

## 11. CLI and TUI flows

All client-side flows live in a new `src/epochflow.rs` used by both the CLI
and the TUI; they need the caller's iroh key and nothing else.

### 11.1 `client epoch log --group g` / `client epoch status --group g`

`GroupEpochs` paged from 0, verified locally from genesis (TOFU on genesis;
`--genesis <hash>` to pin), printed as one line per epoch: `#12 2026-09-06T10:41
alice(1a98…) mint gen 9  −bob  +carol(r)  reencrypted 143 versions`. Names
resolve through `GroupAcl`/`ListIdentityNames` where the caller may, else hex.
This is the "who last re-encrypted" view.

### 11.2 Kick / revoke read: `client kick --group g --identity bob [--with-history]`

1. `GroupEpochs` → verify chain → own wrap in head → old DEK.
2. `ListSealed` pages → decrypt each (AAD with old `dek_version`) → re-encrypt
   under fresh `M` (new `dek_version = head.dek_version + 1`; the server rejects
   if legacy versions make it higher, returning the expected value in `Failed`
   — the client retries with it).
3. Build the record: `acl` = head ACL minus bob's read bit (or minus the row for
   `--perms none`), `keys` to readers ∪ pinned, proof, digest; sign.
4. `StageReencrypted` in ≤3.5 MiB chunks keyed by the record hash;
   `SubmitEpoch` with any remainder inline.
5. On `StaleVersions`: refetch those names, restage, rebuild (new hash, new
   sig), resubmit; on `EpochConflict`: restart from 1. Three attempts, then
   exit 2 (the existing CAS-conflict code).

Plaintext buffers are zeroized after re-encryption; the CLI streams page by
page so peak memory is one page, not the group.

### 11.3 Rotate: `client rotate --group g`

11.2 without the ACL change.

### 11.4 Grant: `client grant --group g --identity carol --perms rwa`

Gaining read → `keys` epoch, `mint == false`, same `M`, fresh `r`, no
re-encryption (bytes: one record). Losing read → 11.2. Only w/a bits → `carry`
epoch from the head's wrap epoch (no `M` needed; works for admins without
read). The existing server-side `Grant` request remains for the Go client and
for mode A; the CLI uses the client-side path whenever it can, because that is
the attributable one. `client create-group` in mode B authors genesis.

### 11.5 Offline recovery: `db grant`, `recover`

- `db grant --db … --endpoint-key server.key [--operational-key | --backup-key]`
  authors a server-signed epoch: `carry` for w/a bits; `keys` for read grants,
  recovering `M` from the operational point (mode A) or the backup point
  (mode B, `--backup-key`). V9(c)/(d) or the orphan-recovery exception apply;
  the audit row is appended as today.
- `recover --db … --backup-key … --endpoint-key … --new-operational-pubkey age1…`
  does today's legacy re-wrap plus one re-pin epoch per group (5.3).

### 11.6 TUI

ACL pane: `x`/`r` on a reader and `R` in the groups pane run 11.2/11.3 with a
progress line (`re-encrypting 143/200 · 12 MiB · attempt 1`); the groups pane
shows `epoch 12 · gen 9 · alice · 2h` and `!` when `needs_rotation`. A new `L`
key opens the epoch log. When the caller lacks read on the group, the TUI falls
back to server-side `Grant`/`RotateDek` and says so in the status line.

## 12. Trade-off: DLEQ versus "age wraps plus an author signature"

The simpler alternative keeps age wraps (now minted client-side by the admin,
who has the DEK as a reader) and signs a record of `(acl, wrap hashes,
reencrypted digest)`. It delivers the ask's core — admin-driven kick without
the operational key, attribution of the re-encryption — and reuses a standard
format. Adding a shared KCV lets each recipient check its own key matches the
claimed one.

What the DLEQ adds, precisely:

1. **Keyless verification of consistency.** A replica, an auditor, or the
   server in mode B can check that all recipients got the same key. With age,
   each recipient can only check itself; nobody can check the set.
2. **A verifiable recipient set.** ElGamal `c_i` are one-per-listed-key and V6
   equates the list with readers ∪ pinned. An age file's stanzas are opaque: a
   signer could add a stanza for a key nobody listed and no verifier could
   tell. This is the property that makes "a hostile server cannot add a
   reader" hold for mode-B groups even when the server relays records it did
   not author.
3. Smaller records (32 B per recipient plus 64 B total, versus ~200 B per
   recipient) and no age dependency on the hot path.

What it costs: ~200 lines of curve code with subtle checks (canonical
encodings, torsion, the backup sign rule), custom golden vectors, and a scheme
nobody else's tooling reads. In mode A the server can already verify
consistency by decrypting, so the DLEQ's marginal value there is the
recipient-set proof and replica-side verification. If the deployment will only
ever run mode A with trusted operators, the age-plus-signature variant is a
defensible cut. Recommendation: implement the DLEQ; the incremental cost over
the signed-record variant is small, and it is what makes mode B meaningful.

## 13. Phased delivery

| Phase | Ships | Compatibility |
|---|---|---|
| 0 | `src/epoch.rs`: points, ElGamal, DLEQ, HKDF, record encode/parse/hash/sign, `verify`, digest; golden vectors. No schema or protocol change. | none needed |
| 1 | Schema v3, migration, server-authored epochs for `CreateGroup`/`Grant`/`RotateDek`/`RemoveIdentity` in mode A, `Put`/`Get` via epoch generations, `GroupStatus`/`GroupEpochs`. | Go client unaffected; replicas on `sync/1` keep working only until phase 2 is deployed (they receive empty `deks` for migrated groups — so deploy 1 and 2 together on the authoritative node, or gate 1's migration behind 2) |
| 2 | `sync/2`, replica verification, `EpochRejected`, operator event arm. | operator image upgrade |
| 3 | `GetSealed`/`ListSealed`/`PutSealed`/`StageReencrypted`/`SubmitEpoch`, `epochflow`, CLI `kick`/`rotate`/`grant`/`epoch log`, TUI. | additive |
| 4 | Mode B (`dek_mode = e2e`), tombstones, `db grant`/`recover` rewrite, docs (`crypto-design.md` sections 4, 7, 8, 9; `protocol.md`; `sync-protocol.md`). | opt-in per server |

Phases 1 and 2 should be one release, since phase 1's migration empties the
v1 `deks` list. Everything else is independently releasable.

## 14. Testing plan

**Unit (`epoch.rs`).** Canonical/torsion checks against known bad encodings
(non-canonical Y, small-order points, the eight torsion points added to a valid
key). ElGamal round trip for reader, backup (both sign cases), operational.
DLEQ prove/verify; negatives: tampered `c_i`, swapped recipients, a torsion
point added to one `A_i`, wrong `e`, wrong `s`, `n = 1`, `n = 200`. HKDF/KCV
vectors. Record encode → parse → same bytes; strict parser rejects duplicate,
unknown, and trailing data; hash and signature vectors. A rule matrix: for each
of V1–V11 a minimal record that fails only that rule. Digest vectors including
the empty set. Fuzz: parser and verifier on random bytes never panic.

**Golden vectors.** A deterministic test RNG (fixed seeds for `m`, `r`, `k`,
nonces) produces one genesis and one mint record for a two-reader group;
pinned hex for `body`, `hash`, `sig`, `c0`, each `c_i`, `proof`, `commit`,
`reencrypted`, plus the derived DEK. These become the shared fixture for the Go
implementation, like `agebridge::derivation_golden_vector`.

**Store.** v2→v3 on the existing fixture databases (as the v1→v2 tests do);
first-boot migration yields a verifiable genesis per group, current versions
decrypt under the new generation, legacy history still decrypts with the
operational age key, reader age wraps are gone; staging cap/TTL/replacement;
`SubmitEpoch` apply is all-or-nothing when one staged row is missing.

**Server.** `SubmitEpoch`: happy path; `EpochConflict`; `StaleVersions` after a
racing `Put`; deliverer ≠ author → `Denied`; non-admin author → `Failed`;
mode A KCV mismatch and undecryptable staged row → `Failed` with nothing
applied; mode B refusals of `Get`/`Grant`(read)/`RotateDek`; `RemoveIdentity`
produces a mint per readable group (A) or a tombstone plus `needs_rotation`
(B); last-admin rule on human epochs, orphaning allowed on server epochs.

**End-to-end (`tests/e2e.rs` style, in-process iroh `presets::Minimal`).**
(1) Admin kicks reader client-side: reader's next `Get` is `Denied`, its
stashed old DEK opens neither the re-encrypted current versions nor later
writes, the replica converges and its `Get` denies the reader. (2) Add reader:
replica sees the new reader without any refetch. (3) Hostile authoritative
node: a test bunker whose store is edited to add an ACL row without an epoch,
and one that serves a server-signed additive epoch for a mode-B group → the
replica rejects, keeps its mirror, emits `EpochRejected`; the same for a
rewound chain. (4) Migration under a live replica: no serving gap, legacy wraps
gone after convergence. (5) 4 MiB secret through kick, staging and sync.
(6) Operator `reconcile_apply`: a rotation produces zero Secret patches.
(7) `recover` re-pins and the new operational key serves reads.

## 15. Open questions for the user

1. Admin-kicks-admin: keep today's "any admin, last-admin guarded" semantics
   (recommended), or require a second admin's co-signature to remove an admin?
2. History on kick: re-encrypt current versions only, leaving history cold
   under old generations for the backup/operational keys (recommended), or
   re-encrypt everything by default (`--with-history` becomes the default)?
3. Default mode for the migration epoch and new groups: server-recipient
   (recommended for continuity with the Go client and the operator's
   onboarding flow) or end-to-end?
4. Should a server-authored additive epoch be allowed in mode A at all (V9(d)),
   or should mode A also force human authorship for grants, keeping only the
   Go client's `Put`/`Get` on the server?
5. Replica behavior on an authoritative restore (rewind): reject and require a
   local mirror reset (recommended), or accept a server-signed "rewind" marker?
6. Keep the backup as the age key re-interpreted on Edwards (recommended: no
   ceremony), or require a native Ed25519 backup key at migration?

## Key decisions

- Epoch records are stored and transmitted as the author's exact signed `body` bytes plus `sig`; verifiers hash/verify the bytes as received and never re-serialize, so no canonical-CBOR machinery is needed and the parser can be strict (unknown/duplicate keys rejected, `v` bumps for new fields).
- The chain is never pruned: every epoch record stays in the `epoch` table and is shipped to replicas, because verifiability requires walking from genesis; old wraps are public-key ciphertext a kicked reader could already open, so keeping them costs nothing.
- `group_dek` remains the generation registry (same `version` counter, new nullable `epoch` column) so `secret_version.dek_version` and `crypto::secret_aad` are untouched; legacy age-wrapped generations coexist permanently with epoch generations for cold history, and reader age wraps are deleted at migration.
- A minting epoch re-encrypts only current secret versions, in place (same `version`, new `dek_version`/nonce/ciphertext); non-current history stays under its old generation, reachable only by pinned recipients (backup/operational). `--with-history` re-encrypts everything via the same staging mechanism.
- Two shapes of key material per epoch: `keys` (fresh `c0`, per-recipient `c_i`, 64-byte batched Schnorr/DLEQ proof, KCV) when the author holds M, and `carry {from, removed}` which references an earlier proven wrap set minus recipients, enabling w/a-bit edits by admins without read and server-side revoke-without-rotate tombstones in E2E mode.
- The server is an author (signing with its endpoint key, which replicas already dial) but never a recipient by identity; the operational and backup age X25519 keys are reused as Edwards ElGamal recipients via `MontgomeryPoint::to_edwards(0)` with a sign-resolution rule at decrypt, so migration needs no new key ceremony and operational/endpoint keys still rotate independently.
- Server-authored epochs are shape-restricted by verifier rule V9: genesis, removals-only `carry`, pinned-only re-pins, or anything at all only when `operational` is pinned (mode A). Hence a hostile authoritative node can revoke but never add a reader or raise a permission on an end-to-end group, and replicas can check this.
- Deployment mode is a property of the group's chain (`pinned` contains `operational` or not), with a server-level default for migration and server-minted genesis; mode A preserves every existing request's behavior for the Go client, mode B adds `GetSealed`/`PutSealed` and refuses server-side read-bit grants and rotations.
- Client-side re-encryption submits through `StageReencrypted` chunks keyed by the record hash plus a single `SubmitEpoch`; the server enforces CAS on `prev`/epoch number, coverage of every current version, digest match, mode-A KCV and trial decryption, then applies in one SQLite transaction. Racing `Put`s produce `StaleVersions` and a client retry rather than blocking writers.
- Sync bumps to `secret-bunker-sync/2` with additive fields only (`Group.epochs/head_epoch/head_hash`, `FetchGroup.have_epoch`); the roster `acl` field survives solely to map endpoint ids to names, and replicas authorize from the verified head record. Rewinds/forks are rejected (operator resets the mirror) instead of today's silent wrap replacement.
- The existing `Grant`/`RotateDek`/`RemoveIdentity`/`CreateGroup` handlers keep working in mode A by having the server author the implied epoch, while the CLI/TUI prefer client-side authoring so attribution lands on the human's key; `db grant` and `recover` become server-signed epoch authors needing the endpoint key file.

## Risks

- Custom curve code replaces a standard age format on the hot path: canonical-encoding and torsion checks, the backup/operational sign-resolution rule, and Fiat-Shamir transcript composition are all places where a subtle bug silently weakens the guarantee. Mitigation is a small isolated `epoch` module, a V1–V11 negative-test matrix, and pinned golden vectors before any schema change ships.
- Phase 1's migration empties the v1 `deks` list, so a v1 replica connected to a migrated authoritative node would stop decrypting new secrets; phases 1 and 2 must ship in one release and the authoritative node must be upgraded before replicas/operator (which serve their last mirror across the ALPN gap).
- Migration re-encrypts every current version on first boot and rewrites every nonce, so every replica refetches everything once and the operator sees a `SecretChanged` storm; the reconcile content-hash comparison makes it a no-op, but this must be tested, and the SQLite file must be backed up before the first v3 start.
- In end-to-end mode the server cannot verify KCV or trial-decrypt, so a malicious or buggy admin can publish a wrong `commit` or garbage re-encryptions that only readers (or someone who knew the old plaintext) detect; the design accepts this as attributable-but-not-prevented and documents it.
- Client-side kicks move 2x the group's live ciphertext through the admin's connection and hold plaintext in the admin's process; for groups holding many multi-MiB values this takes minutes and the `StaleVersions` retry loop can spin under heavy concurrent writes (bounded to three attempts).
- Verifier rule V5 lets server-authored epochs orphan a group (to keep `RemoveIdentity` unblockable), and `db grant` recovery now requires the server endpoint key file plus, in E2E mode, the offline backup key to re-add a reader; the operator runbook must change accordingly.
- The `Hello` manifest ships each group's full chain on every reconnect; groups with thousands of ACL changes will cost hundreds of KB per resync until a `Hello{heads}` optimization is added.
- Replica genesis is trust-on-first-use: a replica cannot verify the server's right to create a group, only that later epochs chain correctly, which is the same trust as today but should be stated in the docs.
- Reusing the age X25519 keys as Edwards recipients requires decoding the age secret bech32 string to a raw scalar in-process (age 0.11 only exposes it as a string), adding a second place secret material is handled outside age's types; zeroization discipline from `agebridge.rs` must be replicated.

## Open questions for the user

- Admin-kicks-admin: keep today's 'any group admin may remove any other admin, last-admin guarded' semantics (recommended), or require a second admin's co-signature to strip another admin's bits?
- History on kick: re-encrypt current versions only and leave older versions cold under their old generation, readable only by the backup/operational keys (recommended), or make full-history re-encryption the default?
- Default mode for the migration epoch and for server-minted new groups: server-recipient (recommended, keeps the Go client and operator onboarding unchanged) or end-to-end from day one?
- Should server-authored additive epochs remain allowed in server-recipient mode (so the Go client's `Grant` keeps working, at the cost of replicas trusting server-signed additions there), or should grants always require a human author even in mode A?
- Replica behavior when the authoritative node is restored from a backup (chain rewind/fork): reject and require an explicit local mirror reset (recommended), or accept a server-signed rewind marker automatically?
- Backup key: keep the existing age X25519 backup key re-interpreted as an Edwards recipient with no ceremony (recommended), or require generating a native Ed25519 backup key at migration?
