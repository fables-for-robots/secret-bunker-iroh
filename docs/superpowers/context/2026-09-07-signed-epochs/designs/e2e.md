# Design: the untrusted-store (E2E) variant, and the minimal thing to actually ship

Panel angle: end-to-end / SOPS-file purist, arguing against itself where the
evidence points the other way.

## 0. Position in one paragraph

Design the epoch record so that the server needs **no private key to accept,
verify, store, or replicate it**. Once that holds, "the server is a recipient"
versus "the server is not a recipient" is a one-field difference in the epoch
(whether the operational key appears in `pinned`), not a second design. Ship
the recipient-server mode first: it satisfies every word of the ask (admins
kick and re-key with their own iroh key, publicly verifiable, attributable),
leaves the Go client, write-only identities and the TUI's data paths untouched,
and lets the server sanity-check re-keys by decrypting them. Full E2E is then a
per-group choice made at genesis, paid for by every client growing a crypto
implementation. Section 8 makes the case; sections 1–7 are the design both
modes share.

## 1. Wrapping and proof scheme

### 1.1 Objects

All arithmetic is on the twisted Edwards form of Curve25519 (`EdwardsPoint`
from the curve25519-dalek re-exported by ed25519-dalek 3), prime-order subgroup
of order `L`, basepoint `B`. No Montgomery conversion, no age, no Ristretto.

- `A_i`: recipient `i`'s Ed25519 public key as an Edwards point
  (`VerifyingKey::to_edwards()`). An EndpointId is exactly this.
- `a_i`: the recipient's secret scalar, `SigningKey::to_scalar()` (the clamped
  SHA-512 half, reduced mod `L`). `A_i = a_i·B`.
- Per epoch: `m ← Scalar::random`, `M = m·B` (torsion-free by construction);
  `r ← Scalar::random`, `r ≠ 0`; `c0 = r·B`; per recipient `c_i = M + r·A_i`.
- Recipients are sorted by the 32 raw bytes of their EndpointId, ascending, no
  duplicates. `A_1` is the first in that order. For `i ≥ 2`:
  `E_i = A_i − A_1`, `D_i = c_i − c_1`.

### 1.2 Key derivation

`M` never leaves the process; two independent derivations from its compressed
encoding `Mc` (32 bytes):

```
DEK        = HKDF-SHA256(salt = "secret-bunker-iroh/dek/1", ikm = Mc, info = group_id ‖ dek_gen_be64, L = 32)
dek_commit = HKDF-SHA256(salt = "secret-bunker-iroh/kcv/1", ikm = Mc, info = group_id ‖ dek_gen_be64, L = 32)
```

`group_id` is 32 random bytes chosen at genesis (the group's permanent
identifier, see 2.1); `dek_gen` increments only when `M` changes. Binding both
into `info` ties a DEK to one group and one generation. `dek_commit` is
published in the epoch; a recipient that decrypts `M` recomputes it and refuses
the epoch on mismatch. Add the `hkdf` crate (RustCrypto, on top of the existing
`sha2`).

### 1.3 Proof (prover side)

The statement is: there exists `r` with `c0 = r·B` and `D_i = r·E_i` for every
`i ≥ 2`. It is a single Schnorr proof of knowledge of the preimage of the group
homomorphism `φ(r) = (r·B, r·E_2, …, r·E_n)` — the AND-composition of `n−1`
Chaum–Pedersen DLEQs sharing one witness, so the proof is 64 bytes regardless
of `n`.

```
k  ← Scalar::random
T0 = k·B ;  T_i = k·E_i  (i = 2..n)
e  = Scalar::from_hash(SHA-512("secret-bunker-iroh/dleq/1" ‖ group_id ‖ c0 ‖ n_be32 ‖ A_1..A_n ‖ c_1..c_n ‖ T0 ‖ T_2..T_n))
s  = k − e·r   (mod L)
proof = (e, s)     // 64 bytes, both canonical little-endian scalars
```

Prover cost: `2n` fixed-base/variable-base scalar multiplications (the `c_i`
and the `T_i`), in constant time (`Scalar` and `EdwardsPoint` ops are
constant-time). For `n = 20` that is well under a millisecond.

With `n = 1` the proof degenerates to a Schnorr proof that `c0 = r·B`, which is
still required (see `r ≠ 0` below).

### 1.4 Verification (anyone, no key)

```
verify_epoch(E, prev: Option<Epoch>, pin: Option<hash>) -> Result<()>
 1. Parse E strictly (2.1): exact length, every list sorted ascending and
    unique on its key, every point canonical (decompress, recompress, compare
    bytes), every scalar < L.
 2. Chain. epoch == 1: prev is None, E.prev == 0^32, E.kind ∈ {genesis, adopt},
    E.dek_gen == 1, and if `pin` is given, SHA-256 of E equals it.
    epoch > 1: prev is Some, E.prev == hash(prev), E.epoch == prev.epoch + 1,
    E.group_id == prev.group_id.
 3. Authorization (epoch > 1): E.author ∈ prev.acl with the admin bit, or
    E.author ∈ prev.pinned with role 1 (break-glass). Section 3.
 4. ACL invariants: every perms ∈ 1..=7; every entry with admin also has read;
    at least one entry with admin; pinned ∩ acl-ids = ∅; prev.pinned role-1
    entries ⊆ E.pinned unless E.author is a role-1 pinned key.
 5. Recipient set R = { id : (id, p) ∈ acl, p & read } ∪ { id : pinned }.
    The ids of E.wraps == R exactly.
 6. Points: c0 ≠ identity; c0, every c_i and every A_i (decompressed from
    the wrap ids) torsion-free (`is_torsion_free()`).
 7. Proof: T0' = s·B + e·c0 (`vartime_double_scalar_mul_basepoint`);
    T_i' = s·E_i + e·D_i (`vartime_multiscalar_mul`); recompute e' over the
    transcript of 1.3 with the T' values; require e' == e.
 8. Kind rules. rekey: dek_gen == prev.dek_gen + 1, dek_commit ≠ prev.dek_commit,
    body_root ≠ 0^32. acl: dek_gen == prev.dek_gen, dek_commit == prev.dek_commit,
    body_root == 0^32. adopt/genesis: dek_gen == 1.
 9. Signature: Ed25519 verify(E.author, "secret-bunker-iroh/epoch-sig/1" ‖ body, E.sig).
```

Verifier cost: `n+1` double-scalar multiplications plus `2n+1` torsion checks
(each one multiplication by `L`); ~2–3 ms for `n = 20` in vartime. Only the
prover needs constant time.

### 1.5 Decryption (recipient `i`)

```
M  = c_i − a_i·c0          // a_i·c0 = a_i·r·B = r·A_i
check HKDF(kcv) == E.dek_commit  else refuse the epoch (alert: author is buggy or malicious)
DEK = HKDF(dek)
```

The Go client (only needed in E2E mode, section 5) does the same with
`filippo.io/edwards25519` + `x/crypto/hkdf`: ~40 lines.

### 1.6 Security argument

**Proven, to anyone holding no key.** Special soundness of the Σ-protocol for
a homomorphism preimage over a prime-order group: from two accepting
transcripts with `e ≠ e'` one extracts `r = (s − s')/(e' − e)` satisfying
*all* `n` relations simultaneously. Hence `c_i − r·A_i = c_1 − r·A_1 =: M` for
every `i`: **every listed recipient decrypts the same point**. With step 6 (all
of `c0`, `c_i`, `A_i` in the prime-order subgroup and `c0 = r·B`) that point is
unique — there is no torsion component a recipient could see differently, which
is the caveat the background raised and why Ristretto is unnecessary here (1.7).
Fiat–Shamir with the whole statement in the transcript makes it non-interactive
in the ROM; HVZK gives that the proof reveals nothing about `r` (simulate by
choosing `s, e` and computing `T`).

**Confidentiality of `M` against non-recipients.** Multi-recipient ElGamal with
randomness re-use is IND-CPA under DDH in the prime-order subgroup
(Bellare–Boldyreva–Staddon, PKC 2003 — ElGamal is "reproducible", so
re-using `r` across recipients loses nothing; Kurosawa 2002). Plain, not hashed,
ElGamal is deliberate: the DLEQ needs the linear structure `c_i − c_1 = r·E_i`.
Plain ElGamal is malleable, which is harmless here because an epoch is only
ever decrypted after its author signature and proof verify, so there is no
chosen-ciphertext oracle: the only party who can produce an accepted epoch is
an admin, who already knows `r` and `M`, and the only feedback a decryptor
gives is the one bit "dek_commit matched" that the author already knows.
Re-using one Ed25519 key for signatures and static DH is the joint-security
model already relied on by `agebridge` (Thormarker, ePrint 2021/509); the
computation `a_i·c0` is the same static DH, on the Edwards form instead of the
Montgomery `u`-line.

**`r ≠ 0` is a hard check** (step 6): with `r = 0` every `c_i = M` and the
"encryption" is public, yet the proof verifies trivially.

**Not proven.** (a) That `dek_commit` opens to `HKDF(kcv, M)` — only a
recipient can check; but because all recipients provably share `M`, one honest
recipient's check speaks for all. (b) That the ciphertexts in the group decrypt
under this DEK — recipients find out on decrypt; the recipient-server mode
checks it at submit time (4.1). (c) Freshness: a hostile store can withhold or
roll back epochs and records (clients and replicas pin the head they last saw,
2.4). (d) Anything about the author's honesty beyond authorship: an admin who
can read can leak plaintext out of band, re-encrypt garbage, or kick everyone
else; the chain makes all of that attributable, not impossible.

**Key-committing AEAD is not needed.** The background's worry (one ciphertext
verifying under two keys) requires two keys in play. Here the DLEQ guarantees
one DEK per epoch for everyone, and ChaCha20 cannot decrypt one ciphertext to
two meaningful plaintexts under two keys anyway (the XOR of the plaintexts is a
keystream difference). `dek_commit` already makes a wrong key fail loudly.

### 1.7 Why torsion checks rather than Ristretto

Ed25519 public keys are Edwards points, not Ristretto encodings; converting
recipients into Ristretto would need a hazmat path and would not survive
`to_edwards()` round-trips. Checking `is_torsion_free()` on every published
point costs one scalar multiplication per point and gives the same guarantee:
every point the proof talks about lies in the prime-order subgroup, so
`M = c_i − r·A_i` is a subgroup element and identical for all `i`. A registered
EndpointId with a torsion component is rejected at epoch verification (it could
not complete an iroh handshake either: non-cofactored Ed25519 verification
fails for such keys with probability 7/8 per signature).

## 2. Canonical encodings

The wire stays CBOR (variant and field names remain the contract). The signed
and hashed objects are **not** CBOR: they are fixed binary layouts carried as
CBOR byte strings, so a Go implementation reproduces them byte-for-byte without
a canonical-CBOR library. Primitives: `u8`; `u32be`; `u64be`; `bytes` = `u32be
len ‖ data`; `id` = 32 raw bytes of an EndpointId; `point` = 32-byte canonical
compressed Edwards; `scalar` = 32-byte canonical little-endian `< L`; `hash` =
SHA-256 (32).

### 2.1 Epoch record (`SBE1`)

```
"SBE1"          4       magic + format version
group_id        32      random at genesis; immutable (step 2)
epoch           u64be
prev            hash    0^32 in epoch 1
kind            u8      0 genesis · 1 acl · 2 rekey · 3 adopt
dek_gen         u64be   1 at genesis/adopt; +1 on rekey
dek_commit      hash
at              u64be   unix seconds, informational
author          id
n_acl           u32be
  acl[i]        id ‖ perms u8              sorted by id, unique, perms ∈ 1..=7
n_pinned        u32be
  pinned[i]     id ‖ role u8               sorted by id, unique; role 0 = online reader (operational), 1 = break-glass admin (backup)
c0              point
n_wraps         u32be
  wraps[i]      id ‖ c point               sorted by id; id set == readers ∪ pinned
proof_e         scalar
proof_s         scalar
body_root       hash    0^32 unless kind ∈ {rekey, adopt}
---- end of body ----
sig             64      Ed25519(author, "secret-bunker-iroh/epoch-sig/1" ‖ body)
```

`epoch_hash = SHA-256("secret-bunker-iroh/epoch-hash/1" ‖ body ‖ sig)`.
`genesis_hash = epoch_hash` of epoch 1; it is what verifiers pin. Size ≈
`400 + 97·n_readers + 97·n_pinned` bytes (2.5 KB for 20 recipients).

### 2.2 Secret record (`SBR1`)

```
"SBR1"          4
group_id        32
epoch           u64be   epoch the record was written under (authorization context)
dek_gen         u64be   must equal that epoch's dek_gen
kind            u8      0 put · 1 rekey-body (re-encrypted as part of a rekey/adopt)
name            bytes
version         u64be
nonce           12
ciphertext      bytes   ChaCha20-Poly1305
at              u64be
author          id      signer of THIS ciphertext
origin_author   id      first writer of this plaintext, carried across re-keys (attested only by `author`)
origin_at       u64be
sig_kind        u8      0 none (server-attested via transport; recipient-server groups only) · 1 author-signed
---- end of body ----
sig             64      present iff sig_kind == 1: Ed25519(author, "secret-bunker-iroh/record-sig/1" ‖ body)
```

AEAD associated data (replaces `secret_aad`):
`"secret-bunker-iroh/2" ‖ group_id ‖ len_be64(name) ‖ name ‖ version_be64 ‖ dek_gen_be64`.
The group *name* leaves the AAD — `group_id` is the identity; names are a
server-local label. `record_hash = SHA-256("secret-bunker-iroh/record-hash/1" ‖
record)`. `body_root = SHA-256("secret-bunker-iroh/body/1" ‖ n_be32 ‖
sorted record_hashes)` over the kind-1 records submitted with the epoch, sorted
by `(name, version)`.

### 2.3 Group bundle (`SBG1`) — the SOPS-file analogue

```
"SBG1"
n_epochs   u32be ; repeat: bytes(epoch record)      epochs 1..head, in order
n_records  u32be ; repeat: bytes(secret record)     every retained version
```

Offline verification of a bundle needs nothing but the file and optionally a
pinned genesis hash: verify the chain (1.4) epoch by epoch; for every record
check `group_id`, that `dek_gen` equals the head's (invariant: exactly one live
generation per group, 4.1), that its `epoch` exists in the chain and that
`author` held `write` in that epoch's ACL (kind 0) or is that epoch's author
(kind 1), and the signature when `sig_kind == 1`; recompute `body_root` of the
latest rekey/adopt epoch from the kind-1 records that reference it and compare.
Decryption needs any one recipient key. CLI: `bundle export | verify | decrypt
| rekey | import` (4.6). Deletions are not tombstoned, so a `body_root` of an
*older* rekey may become unrecomputable once a version is deleted; `verify`
reports it as "historical checkpoint, not recomputable" rather than failing.
Signed tombstones are the E2E-mode extension that closes this (section 8).

### 2.4 Pins

Every verifier keeps `(group_id → genesis_hash, head_epoch, head_hash)`: the
replica in `secret_group`, the CLI/TUI client in its data directory keyed by
server. A chain that does not extend the pinned head is a fork or rollback and
is refused with a loud error. This is the only freshness defence; it bounds
what a hostile store can do to "serve an old but signed state and withhold new
ones".

## 3. Authorization rules the verifier enforces

These are checked by the server at submit, by every replica at sync, and by
`bundle verify` offline, against the **previous signed epoch**, never against a
server table. That is the whole difference from SOPS (section 7).

| Rule | Recommended default | Why |
|---|---|---|
| Who may author epoch `n > 1` | any id with `admin` in epoch `n−1`, or a role-1 pinned key | the ask: any admin, no operational key |
| `admin ⇒ read` | enforced (an ACL entry `a` without `r` is invalid) | kick and add-reader both need `M`; an admin who cannot read cannot do the job it was given, and the last-admin rule would then guarantee nothing |
| Admin kicks admin | allowed, including the creator | SOPS parity; the chain makes it attributable and the kicked admin's client detects it on next sync ("removed in epoch n by X"). Recovery: break-glass (below). A k-of-n rule for admin removal is a later extension (multi-signature epochs); not needed to make the ask safe |
| Last admin | epoch `n` must keep ≥ 1 non-pinned admin; self-removal allowed only if another admin remains | a group must stay manageable online without break-glass |
| Pinned role 1 (backup) | carried forward verbatim; only a role-1 author may change the role-1 set | mandatory recipient cannot be dropped by an ordinary admin |
| Pinned role 0 (operational) | any admin may add/remove it | it is a reader; admins may add readers. The *server* additionally refuses to drop its own key from a group unless E2E groups are enabled (deployment policy, 5.2) |
| Genesis author | not checked by the verifier; server policy (service admin creates, or the server authors an adopt epoch); replicas pin genesis on first sight | there is no previous state to check against |
| Registry vs chain | `RemoveIdentity` (service admin) deletes the identity row → denied at the door immediately; it cannot and does not rewrite any epoch | revoking a compromised key always wins; cryptographic re-key is a group admin's job (4.4) |

## 4. Operations

All client-side operations use one library routine: fetch epochs since the
pinned head → verify → decrypt own wrap → act → submit. `SubmitEpoch` is CAS on
the epoch number.

### 4.1 Kick / explicit rotate (kind `rekey`)

Invariant introduced: **exactly one live `dek_gen` per group**. A rekey
re-encrypts every retained version, current and historical, under the new DEK.
This is the SOPS `-r` semantic and what "roll the single random data key"
means; it also fixes today's gap where a stolen database plus a kicked key
still reads all history. `group_dek`/`dek_wrap` versioning disappears.

Client (`A`, admin+reader):

1. `GetEpochs{group, since}` → verify chain, `head`. Require `A` admin in
   `head.acl`; target present.
2. `M_old` from own wrap, KCV check, `DEK_old`.
3. `ListRecords{group}` → every `(name, version, record_hash)`;
   `GetRecord` each; verify each record; decrypt with `DEK_old` and the AAD;
   re-encrypt under `DEK_new` with `dek_gen+1`, `kind = 1`, `epoch = head+1`,
   `author = A`, `origin_*` carried over, `sig_kind = 1`, sign.
4. New `M`, `r`; wraps for `readers(head.acl − target) ∪ pinned`; proof;
   `dek_commit`; `body_root`; sign the epoch.
5. Staged submit (a group's ciphertext can exceed `MAX_MSG`):
   `BeginEpoch{group, epoch: bytes}` → `Ok`;
   `StageRecord{group, epoch_hash, record: bytes}` × N;
   `CommitEpoch{group, epoch_hash}` → `Ok | EpochConflict{head} | Failed{reason}`.
6. On `EpochConflict` (someone else's epoch or put landed first) restart at 1.

Server, in one SQLite transaction at `CommitEpoch`: caller == `epoch.author`;
`verify_epoch` against the stored head; the staged set's `(name, version)`
pairs equal the group's current `secret_version` rows exactly; each staged
record verifies and has `dek_gen == epoch.dek_gen`, `epoch == epoch.epoch`,
`kind == 1`; `body_root` matches; **if the server is a recipient**: decrypt its
wrap, check `dek_commit`, decrypt every staged record (a rekey that would brick
readers is rejected here instead of discovered by the k8s operator); replace
all `secret_version` rows; insert the epoch; refresh the materialized
`group_acl`; audit `rotate-dek`/`grant` rows attributed to the caller; publish
`Changed`. Staging rows older than 10 minutes are garbage-collected.

Concurrent `Put` under the old `dek_gen` after the swap gets `StaleEpoch{epoch,
dek_gen}` and the client re-fetches, re-encrypts, retries — the existing CAS
loop, one more retry cause.

### 4.2 Add reader (kind `acl`, same `M`)

Fresh `r`, wraps to the enlarged set, fresh proof, same `dek_commit`, same
`dek_gen`, no records. The verifier's kind rule (1.4 step 8) makes "the DEK did
not change" publicly checkable. Needs a reader-admin (has `M`); replaces
today's operational-key unwrap in `wraps_for_new_reader`.

### 4.3 Plain w/a edit, remove `write` (kind `acl`)

If the reader set is unchanged, `c0`, wraps and proof are carried verbatim
(the transcript binds `group_id` and the points, not the epoch number,
precisely so this is legal). Still needs an admin; still signed.

### 4.4 `RemoveIdentity` (service admin)

CLI `remove-identity <name>`: for every group where the target reads and the
caller is admin+reader, run 4.1 client-side first; then send `RemoveIdentity`;
finally print the groups it could not re-key and their admins. The server
deletes the identity row (immediate denial) and `Groups` gains an additive
`tainted: bool` per group (a head-epoch reader is no longer registered) so
admins see the debt.

### 4.5 Put, Delete, CreateGroup

- Recipient-server group: `Put` (plaintext, transport-authenticated) is
  unchanged on the wire; the server derives the DEK from its own wrap, writes a
  kind-0 record with `sig_kind = 0`, `author = caller`. `PutRecord{group,
  record}` is the signed alternative any client may use (server checks: caller
  == author, `write` in head ACL, `dek_gen`/`epoch` current, CAS on version).
- E2E group: only `PutRecord`; `Put` answers `Failed{"e2e group: sign the
  record"}`. `Get` answers `Record{record}` instead of `Secret` (new response
  variant, sent only to clients that asked with `GetRecord`; plain `Get` on an
  E2E group is `Failed`).
- `Delete`: transport-authorized against the head ACL, audited, unsigned (both
  modes; see 2.3 on tombstones).
- `CreateGroup{name}` (service admin) keeps working: the server authors genesis
  with the operational Ed25519 key (`kind = adopt` semantics: ACL = creator
  `rwa`, pinned = operational role 0 + backup role 1, fresh `M`). The server
  authors **epoch 1 and nothing else, ever**. A client may instead submit its
  own genesis through `BeginEpoch/CommitEpoch` with `epoch = 1` on a new name
  (service-admin gated); that is the only way to create an E2E group.

### 4.6 Break-glass and recovery (backup key)

The backup key is an Ed25519 key held offline, pinned with role 1 in every
epoch, so it is a recipient of every `M` and an authorized author of any
epoch. It never comes online: `bundle export --group g` (any reader) →
offline `bundle rekey g.sbg --key backup.key --kick <id> --add <id>:rwa` →
`bundle import g2.sbg` (staged submit by whoever carries the file; the epoch is
signed by the backup key, so the carrier needs no permission beyond being
registered). This one flow replaces today's `db grant` (orphaned group) and
`recover` (operational key compromise: re-key every group, pinning the new
operational key), and needs the service stopped for neither.

## 5. Roles, modes, and what breaks

### 5.1 The two modes are one field

| | Mode A: recipient server (default) | Mode B: E2E group |
|---|---|---|
| `pinned` | operational (role 0) + backup (role 1) | backup (role 1) only |
| Server private keys | endpoint key + operational **Ed25519** key (replaces the age key; still separate from the endpoint key so they rotate independently) | endpoint key only |
| Server authors epochs | genesis/adopt only | never (client-submitted genesis) |
| `Get` / `Put` | plaintext, unchanged wire | `GetRecord` / `PutRecord`; client decrypts, verifies, encrypts, signs |
| Write-only identity | works (server encrypts for it) | invalid: verifier rejects `w` without `r` when no role-0 pinned key exists |
| Service-admin implicit read | works (server authorization rule, server holds `M`) | gone; service admin = registry + group-creation policy + denial at the door |
| Server can validate a rekey by decrypting | yes (4.1) | no — structural checks + DLEQ only; readers discover bad ciphertext |
| Go client | unchanged for Get/Put/List/Delete; `Grant`/`RotateDek` answered `Failed` (see open questions) | needs a port: edwards25519 decrypt, HKDF, ChaCha20-Poly1305, Ed25519 record/epoch verification, chain verification, pins |
| TUI | `Get`/`Put` unchanged; grant/revoke/rotate forms call the client epoch library (the TUI runs as a user identity; if that identity is not a reader-admin the form fails with a clear message) | every pane goes through the client library |
| k8s operator | already a reader; verifies chains, decrypts its own wrap | identical |
| Confidentiality vs hostile operator | no (as today) | yes for the ciphertext; the operator still controls the registry, creation policy, and liveness |

Per-group choice at genesis, no global flag: a group is E2E iff no role-0
pinned key is present. Deployment policy on the server says whether E2E
groups may be created (default off until a signing Go client exists).

### 5.2 Threat model, both modes, versus today

Gained in both modes: a compromised authoritative node (or SQLite writer) can
no longer forge ACL changes — replicas and clients verify the chain; every ACL
change and every re-key is attributed to a signing key; grant-of-reader and
kick no longer need the operational key; a kick re-encrypts history, so a
stolen database plus a kicked key reads nothing; rollback of the ACL is
detectable via pins. The operator's `db grant` and `recover` powers move to the
offline backup key.

Lost or changed in both modes: cryptographic revocation now depends on a
client completing 4.1 (the server's registry removal still denies at the door
instantly); a kick moves the whole group's ciphertext through the admin's
client (bounded by the 4 MiB per-value cap × retained versions); `RotateDek`
no longer keeps old versions under old keys. A hostile store can still
withhold and, absent a pin, serve a stale signed state.

Gained only in Mode B: the operator cannot read secrets. Lost only in Mode B:
everything in the right-hand column above.

## 6. Storage, protocol, migration

### 6.1 Schema v3

```
secret_group   + group_uid BLOB UNIQUE (32)  + genesis_hash BLOB  + head_epoch INTEGER  + dek_gen INTEGER
group_epoch    (group_id, epoch INTEGER, hash BLOB UNIQUE, record BLOB, PRIMARY KEY (group_id, epoch))
epoch_staging  (group_id, epoch_hash BLOB, name TEXT, version INTEGER, record BLOB, created_at, PRIMARY KEY (group_id, epoch_hash, name, version))
secret_version + epoch INTEGER  + kind INTEGER  + author BLOB(32)  + origin_author BLOB(32)  + origin_at INTEGER  + sig_kind INTEGER  + sig BLOB NULL
                 (dek_version now holds dek_gen; created_by keeps the name for display)
group_acl      unchanged shape, now a materialized copy of the head epoch's ACL, rewritten inside every epoch-apply transaction so authorize_group and the sync scope query need no change
meta           + operational_ed25519 (hex id)  + backup_ed25519 (hex id)  + epochs_migrated (0/1)
group_dek, dek_wrap   kept only while any group lacks an epoch; dropped by the v3→v4 cleanup migration once epochs_migrated = 1
```

The replica database gets the same additions; `apply_group_sync` grows the
verification of 6.3.

### 6.2 Client protocol (`secret-bunker/1`, additive)

New requests, all answered `Denied` to unauthorized callers exactly like the
existing ones:

```
{"GetEpochs":   {"group": "prod", "since": 0}}                     read|admin → {"Epochs": {"records": [h'…'], "head": 12}}   (paginated by `since`)
{"ListRecords": {"group": "prod"}}                                 admin (rekey needs all versions) → {"Records": [["db-password", 4, h'hash'], …]}
{"GetRecord":   {"group": "prod", "name": "db-password"}}          read → {"Record": {"record": h'…'}}
{"PutRecord":   {"group": "prod", "record": h'…'}}                 write → Version | VersionConflict | {"StaleEpoch": {"epoch": 12, "dek_gen": 3}}
{"BeginEpoch":  {"group": "prod", "epoch": h'…'}}                  caller == author, admin in head (or epoch 1 + service admin) → Ok | EpochConflict
{"StageRecord": {"group": "prod", "epoch_hash": h'…', "record": h'…'}}
{"CommitEpoch": {"group": "prod", "epoch_hash": h'…'}}             → Ok | {"EpochConflict": {"head": 12}} | Failed
```

`Groups` entries gain additive fields `epoch`, `dek_gen`, `last_rekey_by`
(hex id), `tainted`. `Grant` and `RotateDek` on an epoch group answer
`Failed{"epoch group: use a signing client"}` — the wire variants stay (names
are the contract) but the server cannot execute them; the Rust CLI/TUI
implement them client-side. `AddIdentity`, `SetServiceAdmin`,
`ListIdentities`, `ListIdentityNames`, `GroupAcl`, `List` are untouched.

### 6.3 Sync protocol → `secret-bunker-sync/2`

`Group` gains `genesis_hash`, `head: bytes` (the head epoch record) and keeps
`acl` for display; `deks` is sent empty. New `FetchEpochs{group, from, to}` →
`Epochs` for filling a gap between the replica's pinned head and `head`.
`SecretEntry` gains `record_hash` as the change discriminator (it covers the
nonce, so ABA detection is preserved). `SecretData` gains `record: bytes`.
Replica apply, per group, one transaction: pin genesis on first sight; verify
each new epoch against its stored predecessor; require own id among the head's
recipients — otherwise drop the group and log "kicked in epoch n by
<author>"; decrypt own wrap and check `dek_commit`; verify every fetched
record (a `sig_kind 0` record is accepted only if the head has a role-0 pinned
key, i.e. the group is a recipient-server group and server attestation is the
trust model); then the existing rules 1–5. Rule 3 (wraps) becomes: store the
epoch, nothing else. A v1 replica cannot connect to a v2 server (ALPN), so the
operator image is upgraded before the server.

### 6.4 Migration

1. Generate the Ed25519 operational key (`key generate operational`) and,
   offline, the Ed25519 backup key; record both public ids:
   `secret-bunker-iroh migrate-epochs --db bunker.sqlite --backup-id <hex>`
   (one shot, service stopped, needs the **age** operational key for the last
   time). Per legacy group, in one transaction: unwrap the current DEK
   versions with the age key; decrypt every retained `secret_version`
   (`--drop-history` keeps current versions only, recommended: history is
   neither served nor mirrored today); generate `M`; write kind-1 records
   (`author = operational id`, `origin_author` = the id behind `created_by` if
   it still exists, `sig_kind = 0`); genesis epoch `kind = adopt`, `acl` =
   current `group_acl`, pinned = operational (0) + backup (1), signed by the
   operational Ed25519 key; delete the group's `group_dek`/`dek_wrap` rows.
   Set `epochs_migrated = 1`. The age operational and backup keys are then
   only needed to read pre-migration database snapshots; archive them.
2. Deploy: operator image (sync/2) first, then the server. Replicas resync
   fully (the `Group` shape changed) and pin every genesis on first sight.
3. Clients: old CLIs keep working for data operations; `grant`/`rotate-dek`
   need the new CLI.
4. Cleanup migration v3→v4 drops `group_dek`/`dek_wrap`, `agebridge.rs`, the
   `age` dependency from the server path (kept for `bundle decrypt` of old
   snapshots if desired).

Golden vectors: pin `SBE1`/`SBR1`/`SBG1` encodings, the DLEQ transcript, the
HKDF outputs and a full verify/decrypt round trip from a fixed seed, in the
same spirit as `derivation_golden_vector`, and mirror them in the Go client
before any E2E group is enabled.

## 7. Trade-offs

### 7.1 Versus "keep age wraps, add an author signature"

Be honest about this alternative: it also satisfies the ask. An admin who
reads holds the DEK, can `age`-encrypt it to each reader's derived recipient
client-side, put the ACL and the wraps in a record, sign it with the iroh key,
and the server can verify the signature and the admin rule against the
previous record without any key. No new curve code, the backup key stays an
age key, Go can use `filippo.io/age` for an eventual E2E client. That is 90%
of the value for perhaps 40% of the work.

What the ElGamal + DLEQ wrap adds on top, concretely:

1. **The reader list becomes a proof instead of a claim.** With age wraps a
   malicious or buggy admin can list X as a reader and give X a wrap of some
   other key; nobody but X can tell, and X finds out when the k8s operator
   fails to render a Secret at 3 a.m. With the DLEQ the server (holding no key
   in E2E, or without opening its own wrap in Mode A) rejects that epoch at
   submit. Split-view exclusion is the one attack against the *availability*
   promise "the ACL is exactly who can read" that signatures alone do not
   catch.
2. **Verification needs no key and no age.** Replicas, `bundle verify`, and an
   auditor need curve arithmetic and SHA-256 only. With age wraps a replica can
   verify its own wrap and nothing about the others.
3. Wraps are 64 bytes instead of ~200; the epoch stays a compact record.
4. The Edwards→Montgomery bridge (`agebridge.rs`, the bech32 round-trips, the
   golden vector) is retired instead of being carried alongside a second
   scheme.

What it costs: `curve25519-dalek` used directly (via the re-export),
~300 lines of new crypto with a Fiat–Shamir transcript to get exactly right,
torsion checks, an `hkdf` dependency, a new Ed25519 backup key ceremony, and
— only for E2E — a Go port of decrypt and verify. Recommendation: take it,
because the migration is a one-time cost either way and item 1 is on-theme
for a system whose selling point is "any reader can run a replica".

### 7.2 SOPS "any recipient can re-key", and why an admin bit still matters

SOPS has no admin bit because it cannot have one: a file has no previous
state, so there is nothing to check an author against, and every master-key
holder is a fully trusted, anonymous author. Here every reader likewise
*could* decrypt `M`, build wraps and a valid proof — the cryptography does not
distinguish readers from admins. What distinguishes them is that the verifier
checks the author against the **previous signed epoch's ACL**, and the
signature names the author. Without that rule the most exposed keys in the
whole system — the CI key, the k8s operator's key — could kick every human;
with it they can only read. The hash chain is what makes an admin bit
enforceable by an untrusted server, and the signature is what turns "someone
re-encrypted" into "X re-encrypted in epoch n at t".

## 8. Verdict: what to ship, and what full E2E adds

**Is full E2E worth it for this project?** Not now. The project's own threat
model excludes the hostile operator, and the ask is about *admins* not
depending on the *operational key holder*, plus verifiability and attribution.
Mode A delivers all of that with zero change to the Go client's data path, the
TUI's data panes, write-only identities, and service-admin reads, and it keeps
the server able to refuse a rekey that would brick readers. Mode B's only
additional property is confidentiality against the operator, and even then the
operator keeps the registry (which id is "alice"), creation policy, and
liveness; the price is a crypto implementation in every client and the loss of
write-only identities. Design the record so Mode B is a per-group `pinned`
choice — which this design does — and leave it switched off until a signing Go
client exists.

**Minimal design that satisfies the ask** (everything above minus the Mode B
column): epoch record `SBE1` with ElGamal wraps + DLEQ + author signature;
secret record `SBR1` with `sig_kind 0/1`; server-side verifier and staged
submit; client-side kick/add/edit in the Rust CLI/TUI; operational key becomes
an Ed25519 role-0 pinned reader that authors only genesis; backup key becomes
an Ed25519 role-1 pinned admin used offline through bundles; sync/2 with chain
verification in replicas; one live `dek_gen` per group; pins for rollback
detection.

**What E2E adds on top of that**, as a checklist for the later mode:
`GetRecord`/`PutRecord` become the only data path; client-submitted genesis;
verifier rejects `w` without `r` for groups without a role-0 key; service-admin
implicit read removed for those groups; Go and TUI clients implement 1.5, 1.4,
record signing and pins; signed delete tombstones so `body_root` stays
recomputable offline; server policy flag to allow E2E genesis; no operational
key at all once every group is E2E.

## 9. Open questions for the user

1. Does the Go client use `Grant`/`RotateDek`, or only data operations? Mode A
   keeps the latter byte-identical; the former return `Failed` until a signing
   Go client exists.
2. History on migration and on rekey: recommended `--drop-history` at adoption
   (history is not served or mirrored today) and full re-encryption of
   retained versions on every rekey afterwards; alternatively cap retention
   (last N versions) as a separate feature.
3. Pinned role of the operational key: role 0 (reader only; recommended — an
   online-key compromise cannot rewrite ACLs) versus role 1 (keeps a local
   `db`-style orphan recovery without the backup key, but reintroduces a
   master admin).
4. Admin-kicks-admin without a quorum, with the offline backup key as the
   recovery — acceptable, or is a 2-of-n admin rule for removing an admin
   required from day one?
5. `Delete` stays transport-authorized and unsigned in Mode A; signed
   tombstones deferred to the E2E mode. Acceptable?
6. Backup key ceremony: a fresh Ed25519 key (recommended) versus converting
   the existing age backup scalar through a hazmat `ExpandedSecretKey` path to
   avoid a new ceremony.

## Key decisions

- Ship the recipient-server mode (Mode A) as the default; E2E (Mode B) is a per-group choice expressed solely by whether the operational key appears as a role-0 pinned recipient in the epoch. Same record formats, same verifier, no global mode flag.
- Wrap = multi-recipient ElGamal on the Edwards form with shared randomness (c0 = r·B, c_i = M + r·A_i), single 64-byte Schnorr proof of the homomorphism preimage r -> (r·B, r·E_2..r·E_n) (AND-composed Chaum-Pedersen), Fiat-Shamir transcript binding group_id and every point. Torsion-freeness checks on c0, all c_i and all A_i instead of Ristretto; c0 != identity is a hard check (r = 0 would publish M).
- DEK and dek_commit are two independent HKDF-SHA256 derivations from M's compressed encoding with info = group_id || dek_gen; dek_commit is the loud wrong-key check and makes 'same DEK as before' publicly checkable across add-reader epochs. Key-committing AEAD deliberately not required (the DLEQ removes the two-key scenario).
- Signed objects are fixed binary layouts (SBE1 epoch, SBR1 secret record, SBG1 bundle) carried as CBOR byte strings, so the CBOR wire contract (variant/field names) is untouched and a Go implementation needs no canonical-CBOR library.
- Exactly one live dek_gen per group: a kick or explicit rotate re-encrypts every retained version (SOPS -r semantics), fixing today's 'stolen DB + kicked key reads history' gap; group_dek/dek_wrap versioning disappears. Add-reader keeps M and only re-wraps.
- Authorization is checked against the previous signed epoch, never a server table: author must hold admin in epoch n-1 (or be a role-1 pinned key); admin implies read (enforced); admin may kick admin; at least one non-pinned admin must remain; role-1 pinned set only changeable by a role-1 author.
- The server authors epoch 1 (genesis/adopt) and nothing else, ever. Legacy Grant/RotateDek wire variants remain but answer Failed on epoch groups; the Rust CLI/TUI perform them client-side with the caller's iroh key. RemoveIdentity stays unblocked (registry removal = instant denial at the door) and the CLI re-keys the groups the caller can administer first.
- Backup key becomes an offline Ed25519 role-1 pinned admin recipient; break-glass, orphan recovery and operational-key-compromise recovery all become 'bundle export -> offline bundle rekey -> bundle import', replacing db grant and recover. Operational key becomes an Ed25519 role-0 pinned reader (still separate from the endpoint key).
- Rekey submission is staged (BeginEpoch/StageRecord/CommitEpoch) because a group's ciphertext can exceed MAX_MSG; the commit is CAS on epoch number and on the exact (name, version) set; in Mode A the server also decrypts its own wrap and every staged record so a rekey that would brick readers is rejected at submit.
- Replicas move to secret-bunker-sync/2, pin genesis on first sight, verify the chain and every record, and drop a group (with attribution) when their own id is no longer a recipient; secret records carry sig_kind 0 (server-attested, Mode A only) or 1 (author-signed).
- Verdict on the DLEQ vs 'age wraps + author signature': the signature is ~90% of the value; the DLEQ is taken anyway because it makes the reader list a proof rather than a claim (split-view exclusion rejected at submit), lets verifiers need no key and no age, and retires agebridge.

## Risks

- New hand-rolled curve code (Fiat-Shamir transcript, torsion checks, canonical point/scalar parsing): a transcript omission or a missed identity/torsion check silently breaks the 'same M for everyone' guarantee. Mitigate with golden vectors and negative tests (r = 0, torsioned recipient, duplicated recipient, swapped c_i).
- Plain (unhashed) ElGamal is malleable; the argument that no decryption oracle exists relies on every path verifying the author signature and proof before decrypting. Any code path that decrypts an unverified epoch (e.g. a convenience CLI flag) would reopen a CCA surface.
- Cryptographic revocation now depends on an admin client completing the rekey; a crashed or offline admin leaves a 'tainted' group readable from a stolen database by the kicked key until someone finishes 4.1. Registry removal only denies at the door.
- A kick moves the group's entire retained ciphertext through the admin's client and the staged submit; large groups with deep history could be slow or hit the 10-minute staging GC. History retention policy (open question 2) directly controls this.
- Any admin can kick any other admin and a single compromised admin key is a group takeover; recovery relies on the offline backup key and the bundle round-trip actually being rehearsed by the operator.
- Freshness is only pin-based: a hostile or restored-from-backup authoritative node can serve an older signed state and clients/replicas with no pin (fresh install) accept it; a restore that rewinds epochs will be refused by pinned replicas and needs an explicit 'reset pin' procedure.
- The Go client's Grant/RotateDek (if used) break in Mode A, and Mode B needs a full Go port of decrypt/verify before any E2E group can exist; enabling E2E early strands non-Rust clients.
- Migration is a one-shot, service-stopped operation that needs the age operational key one last time and a new Ed25519 backup ceremony; replicas must be upgraded to sync/2 before the server or they fail ALPN negotiation and serve stale mirrors indefinitely.
- Unsigned Delete (no tombstones) means body_root of older rekey epochs can become unrecomputable offline; bundle verify reports rather than fails, which weakens the 'SOPS-file' integrity story until tombstones ship.
- Materializing the head epoch's ACL into group_acl keeps authorize_group unchanged but introduces a second source of truth; any write to group_acl outside the epoch-apply transaction (e.g. a leftover db grant path) would desynchronize it from the chain.

## Open questions for the user

- Does the Go client use Grant/RotateDek, or only data operations (Get/Put/List/Delete)? Mode A keeps the data operations byte-identical; Grant/RotateDek answer Failed until a signing Go client exists.
- History policy: adopt with --drop-history (current versions only; history is neither served nor mirrored today) and re-encrypt all retained versions on every rekey afterwards — or cap retention (last N versions) as a separate feature?
- Pinned role of the operational key: role 0 reader-only (recommended; an online-key compromise cannot rewrite ACLs) or role 1 break-glass (keeps a local db-style orphan recovery without the backup key but reintroduces a master admin)?
- Admin-kicks-admin with no quorum and the offline backup key as the recovery path — acceptable, or is a 2-of-n admin rule for removing an admin required from day one?
- Delete stays transport-authorized and unsigned in Mode A, with signed tombstones deferred to the E2E mode — acceptable?
- Backup key ceremony: generate a fresh Ed25519 backup key (recommended) or convert the existing age backup scalar via a hazmat ExpandedSecretKey path to avoid a new ceremony?
- Should E2E (Mode B) group creation be allowed at all in the first release (server policy flag), or held until the Go client can verify and decrypt?
