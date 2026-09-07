# Signed Epochs: Verifiable, Admin-Driven DEK Rotation — Design

Date: 2026-09-07
Status: draft, awaiting user review (see section 19)

## 1. Summary

Today a group's data-encryption key (DEK) is wrapped, rotated and re-wrapped
by the **server**, using the operational age key it holds. A group admin asks
the server to revoke a reader or rotate the DEK; the server does the
cryptography and the server's audit log is the only record of who asked.
Anyone who can read the database file sees wraps but cannot check them, and a
replica trusts the authoritative node for the entire ACL.

This design moves the key management of a group into a per-group, hash-chained
sequence of **signed epoch records**, each produced by the party that made the
change, with its own iroh key:

- A group admin **kicks a reader and rolls the DEK** on their own machine: they
  decrypt the group with their own wrap, generate a fresh DEK, re-encrypt every
  retained secret version, wrap the new DEK to every remaining recipient, and
  sign the record. No operational key, no service admin, no server-side key
  material is involved in producing it.
- The wrap is **verifiable by anyone, with no key**: multi-recipient ElGamal on
  the Ed25519 curve plus a Chaum-Pedersen-style proof that every listed
  recipient — readers, the offline backup key, and in the default mode the
  server — decrypts to the *same* DEK. A recipient that would silently be given
  garbage, a hidden extra recipient, or two recipients with two different keys
  are rejected at submission by the server, by every replica, and by any
  offline auditor, before the record is ever stored.
- Every record carries its **author** and signature. "Who last re-encrypted
  the secrets" is the author of the newest rotating epoch; "who last changed
  membership" is the author of the head. Both are checkable by anyone holding
  the chain, and a replica can no longer be fed a forged ACL by a compromised
  authoritative node.

The server keeps serving plaintext `Get`/`Put` to today's clients (it stays a
recipient of every DEK in the default deployment mode), keeps registering
identities, and keeps its "remove a compromised identity always wins" power.
What it loses is the ability to add readers, raise permissions, or change the
group's recovery keys on its own: every additive change must be signed by an
admin of the previous epoch, and recovery of an orphaned or hijacked group is a
record signed by the offline backup key.

An end-to-end mode, in which the server holds no key at all, is specified by
the same record format (one field) and its extra rules (section 7.2), but is
**not built** in this iteration.

## 2. Decisions taken (with alternatives rejected)

| # | Decision | Rejected alternative(s) | Why |
|---|---|---|---|
| D1 | **Per-recipient randomness**: each wrap is `(c0_i = r_i·B, c_i = M + r_i·A_i)` with an independent `r_i`; the proof is one Fiat-Shamir challenge with `n` responses (`32·(n+1)` bytes). | Shared randomness `c0 = r·B`, `c_i = M + r·A_i` with a 64-byte batched proof, plus a proof-of-possession (PoP) signature at identity registration. | With a shared `r`, a registered key that is an affine function of another recipient's key (`−A`, obtained by flipping the sign bit of a hex EndpointId; `A_u + A_v`; `2·A`; the identity point) makes `M` computable **by everyone** from the public record, with a valid proof. This was verified numerically against `curve25519-dalek 5`. PoP closes it only if *every* path that puts a key into a wrap set checks it (registration, migration TOFU, the admin client, replicas); per-recipient randomness closes it by construction, needs no registration ceremony, and is IND-CPA under DDH for adversarially chosen keys. Cost: 64 more bytes per recipient and roughly twice the (millisecond-scale) verification time. |
| D2 | **Edwards form, exact subgroup checks**: every point is decoded canonically, must be torsion-free (`ℓ·P = O`) and must not be small-order; torsion is rejected, never cleared. | Ristretto; cofactored verification (multiply by 8). | Ed25519 public keys are Edwards points, not Ristretto encodings, and dalek exposes no public conversion. Cofactored verification accepts proofs over points that readers decrypt differently by a torsion point — the split-view attack the proof exists to exclude (verified: an 8-torsion component in one `c_i` passes an unchecked verifier after ~10 grinding attempts and hands that reader a different DEK). With dalek's mod-`ℓ` scalars, torsion in `c0_i` corrupts decryption even for clamped keys, so the check is load-bearing, not defense in depth. |
| D3 | **Signed, hash-chained epoch records** with a fixed binary layout, carried as CBOR byte strings; the hash and signature are over the layout bytes. | Sign canonical CBOR; sign the received CBOR bytes verbatim. | A fixed layout needs no canonical-CBOR guarantee, makes golden vectors byte-exact, and lets the Go client reproduce bytes without a canonicaliser. The CBOR wire contract is untouched: records are opaque `bstr` fields. |
| D4 | **Authorship is checked against the previous epoch's ACL** (`author ∈ admins(head)`); the server's key may author only genesis and *shrink-only* records; recovery records are authored only by the offline backup key. | Server authors on admins' behalf (today's `Grant`/`RotateDek`); a pinned server key with full authority. | A server that can author additive records is a chain root: a compromised node could add itself as a reader and every replica would accept it, and attribution would launder through the server key. Shrink-only authority preserves "removing a compromised identity always wins" while a compromised node degrades to denial. |
| D5 | **Admin implies read**; any admin may kick any reader including another admin (loud, attributable, reversible); every non-authority record leaves ≥1 admin; the author of a rotation must be a recipient of it (an admin cannot rotate itself out and keep the new key). | Independent bits with a "carry wraps verbatim" shape for admins without read; forbid admin-kicks-admin; k-of-n co-signatures. | Every key operation an admin exists for needs the DEK. Today any admin can already strip any other admin except the last; "forbid" converts a loud, reversible lockout into silent persistent access for a compromised key; co-signatures add a multi-party workflow the ask does not need and can be added later as a new record kind. |
| D6 | **Rotation re-encrypts every retained version** of the group (current and history), so a group has exactly one live DEK generation. | Re-encrypt current versions only, leaving history under retired generations; delete history on rotation. | One generation per group is the SOPS semantics the ask presumes, keeps records small, and makes a kicked reader's old wraps protect nothing. Cost is proportional to retained ciphertext, which for this system's payloads is small; a retention policy is a separate feature. **User decision** (Q5). |
| D7 | **Server-recipient mode ("mode A") is the only built mode**; end-to-end mode ("mode E") is a genesis-time flag with its extra rules specified but deferred. | Build E2E now. | The project's threat model excludes the hostile operator. Mode A delivers every word of the ask with the Go client's data path, write-only identities, the TUI's data panes and service-admin reads byte-identical, and lets the server refuse a re-key that would brick readers. Mode E costs a crypto implementation in every client. |
| D8 | The server's at-rest key and the offline backup key become **Ed25519 keys** (iroh secret-key format); the age keys are archived for pre-migration snapshots. | Reuse the X25519 age keys via a Montgomery→Edwards conversion with a sign rule. | The backup key must *sign* recovery records and the operational key must sign genesis and shrink records; an age scalar has no RFC 8032 seed and would need hazmat raw-scalar signing in Rust and Go. One key ceremony is cheaper than a second signing path. |
| D9 | **Replicas verify the chain**, keep a per-name pin that survives dropping a group, and refuse forks and rewinds; an operator resets a pin explicitly after an authoritative restore. | Accept a backup-signed "re-root" record automatically. | A restore from an old snapshot is rare; a re-root scheme re-issues generation numbers and must gather heads from every replica to avoid reviving kicks made after the restore point. Explicit operator action is the safer default. |
| D10 | `dek_commit` depends on `M` and the group only (not on the generation number); verifiers remember every `c0_i` (bunker-wide on the server) and every `dek_commit` (per group) they have seen; `m` and every `r_i` are derived with hedges so a stuck RNG reproduces an old `c0` (refused) rather than publishing `M`. | Fold the generation number into the commitment; plain `OsRng` for `m`/`r_i`. | "Rotation ⇒ new commit" and "add-reader ⇒ same commit" are meaningful *keyless* checks only when the commitment is a function of `M` alone. The residual — relations between randomness values chosen by a colluding author — is not detectable and is out of scope: an admin already holds `M`. |
| D11 | **Stage by client-chosen id under a write fence**: `OpenStage` snapshots the group's retained rows and fences `Put`/`Delete` until the stage is submitted or expires; a staged row names the source row it re-encrypts; at commit the retained set equals the snapshot and every row must be covered, or the reply lists the uncovered rows. | Stage keyed by the record hash; the server re-encrypts stragglers written during the window itself. | A hash-keyed stage forces the client to re-encrypt the whole group before staging anything. The fence makes stragglers impossible, so the server never re-encrypts on a client's behalf (which would let an admin churn heads for free and hold the store lock), the signed digest covers exactly the installed rows minus any dropped for a deleted version, and delete-then-recreate before the fence is caught by the source match. |
| D12 | Migration is an explicit, one-shot `db migrate-epochs` with the service stopped; a v3 server refuses to serve an unmigrated database; replicas and the operator are upgraded in the same maintenance window. | Implicit migration at first `serve`. | Migration needs the old age operational key *and* the new keys and rewrites every ciphertext; it should be a deliberate maintenance step with a backup taken first. |
| D13 | `RemoveIdentity` and legacy read revocations are **two-step on the server**: an immediate authority `carry` that drops the row and its wrap (cheap, under the lock, always wins) plus, in mode A, an authority `rotate` performed by a background worker outside the lock, resumed at startup, and retried until it lands; `Put` is refused on the group in between. | Do the whole re-encryption inside the `RemoveIdentity` transaction. | Re-encrypting every retained version of every readable group under the single store mutex would block the node for seconds and could fail (disk full, unopenable wrap), breaking the unconditional "always wins" guarantee. |
| D14 | **Replica genesis trust is keyed, then pinned**: a genesis whose `authority`/`backup`/`mode` match the replica's configured keys is admitted for a name the replica has never mirrored, audited, and pinned; an optional per-name expected genesis hash is a stricter pin; trust-on-first-use with no configured keys is opt-in. | Require a per-name genesis hash for every group; TOFU by default. | A per-name hash for every group makes every `CreateGroup` a chart change and cannot be seeded before migration mints the hashes, which pushes operators to TOFU permanently. Keyed admission bounds the residual to "a compromised node can present a new chain for a name this replica has never mirrored", stated in 7.4; names that matter get the strict pin. |

Decisions the user must confirm are collected in section 19.

## 3. Cryptography

### 3.1 Group, encodings, decoding rules

Notation: `p = 2^255 − 19`; the Ed25519 twisted Edwards curve; `B` the RFC 8032
basepoint of prime order `ℓ`; cofactor 8; `G = ⟨B⟩`; `O` the identity. All
arithmetic is on `EdwardsPoint`/`Scalar` from `curve25519-dalek 5`, which
becomes a direct dependency (it is already in the tree via `ed25519-dalek 3`).

**Point encoding**: 32 bytes, RFC 8032 compressed form. **Scalar encoding**:
32 bytes little-endian, canonical (`< ℓ`).

`decode_point(bytes) -> Option<EdwardsPoint>` is the only way a point enters
the system:

1. `CompressedEdwardsY(bytes).decompress()?`
2. `P.compress().as_bytes() == bytes`, else `None` (`decompress` masks bit 255
   and does not check `y < p`; this rejects the non-canonical encodings).
3. `P.is_torsion_free()` (exact `ℓ·P = O`), else `None`.
4. `!P.is_small_order()` and `P != O`, else `None`.

`decode_scalar(bytes) = Scalar::from_canonical_bytes(bytes)` (`None` for
`≥ ℓ`; never reduced).

EndpointIds inside records are the raw 32 bytes of the Ed25519 public key (the
wire protocol's 64-hex form is the text rendering of the same bytes). Every id
that appears in a record — ACL entries, `authority`, `backup`, wrap ids,
`author` — must pass `decode_point`. `AddIdentity` applies the same check, and
refuses an id equal to any configured operational (current or previous) or
backup key, so an EndpointId that iroh would accept but that carries torsion,
is small-order, is the identity, or is a pinned key can never be registered.

**Version traps (verified against the lockfile).** `curve25519-dalek 5.0.0`
binds `Scalar::random` to `rand_core 0.10` and `Scalar::from_hash` /
`hash_to_curve` to `digest 0.11`; the crate pins `rand 0.8` (`rand_core 0.6`)
and `sha2 0.10`. Use `Scalar::from_bytes_mod_order_wide(&[u8; 64])` fed with
64 bytes from `rand::rngs::OsRng` or with `sha2 0.10` SHA-512 output, and
derive the ElGamal scalar from the `SigningKey` iroh already holds
(`iroh::SecretKey::as_signing_key()`, present in iroh-base 1.0.3; otherwise a
`Zeroizing<[u8; 32]>` copy of the seed). Only `curve25519-dalek`'s default
features plus `zeroize` are needed (no `digest`/`rand_core` features). Add
`curve25519-dalek`, `hkdf 0.12` (already in the tree via age) and `subtle`
as direct dependencies.

### 3.2 Keys and roles

| Key | Form | Held by | Role in the chain |
|---|---|---|---|
| Client identity | iroh Ed25519 key (`client.key`) | the client | reader / writer / admin per ACL; recipient iff `read`; author of admin records |
| **Operational** (`operational.key`) | Ed25519, iroh secret-key format, **new** | the server process | `authority`: author of genesis and shrink-only records; in mode A also a recipient (serves plaintext) |
| **Backup** (`backup.key`) | Ed25519, iroh format, **new**, generated offline | the operator, offline | recipient of every generation; sole author of `recovery` records |
| Server endpoint key | iroh Ed25519 (`server.key`) | the server process | transport only; **never** in a record |

A recipient's ElGamal scalar is exactly its Ed25519 signing scalar:
`a = signing_key.to_scalar()` (the clamped SHA-512 half, reduced mod `ℓ`),
and `A = a·B` is its public key. Because every `c0_i` is forced into `G`,
`a·c0_i = r_i·A` exactly; the mod-`ℓ` reduction is invisible on a torsion-free
point. This is where torsion in `c0_i` would bite (an unreduced clamped scalar
annihilates 8-torsion, a reduced one does not, so two correct implementations
would disagree), hence the strict rejection.

The operational key is deliberately **not** the server endpoint key, so
transport identity and at-rest authority rotate independently (rotating the
endpoint key must not invalidate any chain). Authority records are minted only
by the server process; a wire `SubmitEpoch` whose `author` is a configured
operational key is refused (S1).

### 3.3 The wrap set

Inputs: the recipient public keys `A_1 < … < A_n` (sorted by the 32 raw
bytes, unique, each passed `decode_point`), the group's `group_uid`, the
head's hash `prev` (0^32 for genesis), and either a fresh `M` (rotation) or
the current `M` (re-wrap).

```
new generation:  m = from_bytes_mod_order_wide(SHA-512("secret-bunker-iroh/m/1" ‖ 0x00
                       ‖ group_uid ‖ prev ‖ OsRng 64 bytes));  M = m·B;  discard m
for each i:      r_i = from_bytes_mod_order_wide(SHA-512("secret-bunker-iroh/r/1" ‖ 0x00
                         ‖ M.compress() ‖ A_i ‖ OsRng 64 bytes))                 ; hedged (D10)
                 r_i ≠ 0 (retry otherwise)
                 c0_i = r_i·B
                 c_i  = M + r_i·A_i                        (constant-time r_i·A_i)
(DEK, dek_commit) = KDF(M, group_uid)                      (3.4)
proof = prove((r_i), statement)                            (3.5)
```

Wrap entry on the wire: `id (32) ‖ c0_i (32) ‖ c_i (32)`. `M` and every `r_i`
are held in `Zeroizing` memory only for the duration of the flow that
produced them (a rebase after `EpochConflict` re-wraps from the retained `M`
with fresh `r_i`, 6.1 step 8) and are never persisted. The hedges make a stuck
RNG harmless: `m` differs per group and per chain position, so `M` cannot
repeat across groups or rotations; `r_i` differs per recipient (E2 guarantees
distinct `A_i`), so a rotate produces pairwise-distinct `r_i ≠ m`; and a
re-wrap of the same `M` to a recipient already wrapped reproduces the previous
`c0` for that key wherever it sorts — which rule R5 refuses — instead of
leaking anything.

### 3.4 Key derivation and commitment

```
PRK        = HKDF-SHA256-Extract(salt = group_uid (32 bytes), ikm = M.compress())
DEK        = HKDF-Expand(PRK, "secret-bunker-iroh/dek/1",        32)
dek_commit = HKDF-Expand(PRK, "secret-bunker-iroh/dek-commit/1", 32)
```

`DEK` is the ChaCha20-Poly1305 key for `crypto::encrypt_secret`, unchanged.
`dek_commit` is public: two independent PRF outputs, so it reveals nothing
about `DEK`; it is collision-resistant in `M`; and it depends on `M` and the
group only (D10). The secret AAD `secret_aad(group, name, version,
dek_version)` is **unchanged**; `dek_version` keeps its meaning (the
generation a ciphertext was produced under) and is the chain's `dek_gen`.

### 3.5 The proof

**Statement.** With `D_i = c_i − c_1` for `i ≥ 2`: there exist `r_1..r_n` such
that `c0_i = r_i·B` for every `i`, and `D_i = r_i·A_i − r_1·A_1` for every
`i ≥ 2`. Equivalently `c_i − r_i·A_i = c_1 − r_1·A_1 =: M` for all `i`: every
recipient's decryption is the same point. This is the AND-composition of `n`
Schnorr relations and `n − 1` Chaum-Pedersen-style equalities sharing one
challenge (a proof of plaintext equality for ElGamal); nothing is claimed about
`M` itself (3.8).

**Transcript** (fixed-size fields, no separators; points compressed, integers
big-endian):

```
T = "secret-bunker-iroh/dleq/1" ‖ 0x00
  ‖ group_uid (32) ‖ dek_commit (32) ‖ prev (32) ‖ u64be(epoch) ‖ u32be(n)
  ‖ A_1 ‖ c0_1 ‖ c_1 ‖ … ‖ A_n ‖ c0_n ‖ c_n            (sorted order)
  ‖ T_1 ‖ … ‖ T_n                                     (commitments to r_i)
  ‖ V_2 ‖ … ‖ V_n                                     (commitments to the differences)
e = from_bytes_mod_order_wide(SHA-512(T))
```

Strong Fiat-Shamir: the whole statement precedes the commitments, `n` is
explicit, and the group, commitment and chain position are part of the
statement, so a proof cannot be transplanted to another group, generation,
epoch or fork. `acl` and `author` are the signature's scope (3.7). A `carry`
record (4.1) carries no proof at all: it reuses wraps byte-for-byte and is
accepted on the strength of the record that introduced them (R4).

**Prove** (all secret-dependent arithmetic constant-time):

```
for each i: k_i = from_bytes_mod_order_wide(SHA-512("secret-bunker-iroh/nonce/1" ‖ 0x00
                    ‖ r_i ‖ SHA-512(T without commitments) ‖ OsRng 32 bytes))   ; hedge drawn per i
T_i = k_i·B
V_i = k_i·A_i − k_1·A_1                    (i ≥ 2)
e   = H(T)
s_i = k_i + e·r_i                          (mod ℓ)
proof = e ‖ s_1 ‖ … ‖ s_n                  (32·(n+1) bytes)
zeroize k_i
```

The prover takes its randomness through a small `RandomSource` trait
(`fn fill(&mut self, &mut [u8])`); production uses `OsRng`, tests inject fixed
bytes for the `m` hedge, every `r_i` hedge and every `k_i` hedge, and a
test-only switch disables the `m` hedge. That trait is the golden-vector hook
for the Go implementation.

**Verify** (public data; variable-time arithmetic is correct here):

```
preconditions: every A_i, c0_i, c_i passed decode_point; ids strictly increasing;
               all c0_i pairwise distinct; n ≥ 1; e and every s_i canonical
T_i' = s_i·B − e·c0_i                      (vartime_double_scalar_mul_basepoint)
V_i' = s_i·A_i − s_1·A_1 − e·D_i           (vartime_multiscalar_mul, i ≥ 2)
accept iff H(T with T_i', V_i') == e
```

Cost: `~3n` variable-base scalar multiplications plus `3n` torsion checks.
Measured (release build, Apple Silicon, `n = 50`): prove ≈ 5 ms, verify ≈
12 ms including torsion checks. `n = 1` degenerates to a Schnorr proof of
knowledge of `r_1` and is kept for a single code path.

### 3.6 Reader decryption

```
1. the record has been fully verified (section 5); never open an unverified record
2. locate own id among the wraps; absent ⇒ "not a recipient"
3. M' = c_i − a·c0_i                                   (constant-time a·c0_i)
4. (DEK', commit') = KDF(M', group_uid)
5. subtle::ConstantTimeEq: commit' == dek_commit, else fail closed:
   "wrap does not open to the committed key" — attributable to `author`
6. use DEK'; zeroize M', DEK' on drop
```

Step 5 is the loud failure. The proof shows "the same `M` for everyone"; the
commit check by any one honest recipient shows "and it is the one the author
committed to" — and because every recipient provably shares `M`, one honest
check speaks for all. In mode A that honest recipient is the server, at
submission (rule S5); in mode E it is the first reader to open the record.

### 3.7 Author signature and record hash

```
msg  = "secret-bunker-iroh/epoch-sig/1" ‖ 0x00 ‖ body        (body = layout without sig, 4.1)
sig  = Ed25519(author_seed, msg)                              (RFC 8032 pure, deterministic)
verify with VerifyingKey::verify_strict                       (rejects small-order R, non-canonical S)
hash = SHA-256("secret-bunker-iroh/epoch-hash/1" ‖ 0x00 ‖ body ‖ sig)
```

iroh signs raw messages with the same key: rustls' TLS 1.3
`CertificateVerify` input begins with 64 × `0x20`; the relay handshake signs
a 32-byte derived value; discovery records are signed by the client-built
pkarr packet. None of those can begin with this prefix, which this code adds
itself. Pure Ed25519 with a prefix is what `iroh::SecretKey::sign` and Go's
`ed25519.Sign` already do. The signature, not the proof, binds the ACL, the
keys, the `reencrypted` digest and the author.

### 3.8 Security argument

**What the proof guarantees.** In the prime-order group (enforced by
`decode_point`), the protocol of 3.5 is a Σ-protocol with special soundness:
two accepting transcripts with equal commitments and `e ≠ e'` yield
`r_i = (s_i − s_i')/(e − e')` for every `i`, satisfying all `2n − 1` relations
simultaneously. Fiat-Shamir in the random-oracle model (SHA-512 reduced mod
`ℓ` is statistically uniform) makes it non-interactive; it is honest-verifier
zero-knowledge (simulate by choosing `e`, `s_i` and computing `T_i'`, `V_i'`),
so publishing the proof leaks nothing about any `r_i`. Consequence: **every
recipient that opens its wrap recovers the same `M`, hence the same `DEK`,
hence the same plaintexts.** No key-committing AEAD is needed: key-commitment
matters only when two readers could hold two keys, and that is what the proof
excludes; ChaCha20-Poly1305 stays.

**Cofactor.** If any of `A_i`, `c0_i`, `c_i` carried an 8-torsion component
`T`, the verification equations would involve `e·T`, which depends only on
`e mod 8`, so a dishonest prover succeeds after ~8 attempts with wraps that
decrypt to `M + T_i` — a different key per reader. Rejecting torsion on every
point removes the cofactor from the picture; honest keys and honest wraps are
always torsion-free, so a rejection is never a false positive.

**Confidentiality of `M`.** Each wrap is an independent ElGamal encryption of
`M` under `A_i`; only `KDF(M)` is used, so this is hashed ElGamal. Against an
adversary holding no recipient scalar, the `n`-recipient scheme is IND-CPA
under DDH in `G` by a standard hybrid over the `n` ciphertexts, and the hybrid
goes through **even for adversarially chosen, related recipient keys**
(`−A_v`, `A_u + A_v`, `t·A_v`, `A_v + t·B`), because each reduction picks the
other ciphertexts' randomness itself. (With a shared `r` the hybrid fails and
the related-key attack of D1 is real.) The reader's commit check is a
plaintext-checking oracle on the reader's static-DH function; hashed ElGamal
with such an oracle is secure under Gap-DH in the ROM (the DHIES argument) —
the same assumption the existing age wrapping rests on. Small-order and
identity recipient keys are excluded because `c_i = M + r_i·A_i` would then
take at most 8 values (the identity publishes `M` verbatim). Within one
record, `c0_i` values must be pairwise distinct and `KDF(c0_i)` must not
reproduce any commitment seen for the group (E2, R5): a stuck RNG that made
`r_i` equal some `m` would otherwise publish that `M` as `c0_i`.

**Malleability.** ElGamal ciphertexts are malleable and anyone can produce a
consistent wrap set for an `M` of their choosing with a valid proof. That is
why every record is signed by an author whom the previous epoch authorises,
and why a recipient decrypts only verified records. The proof says "these
wraps are consistent"; only the signature says "an authorised admin asserts
these wraps, this ACL, at this chain position". Neither substitutes for the
other.

**One key for TLS, epoch signatures and ElGamal.** The endpoint key already
does Ed25519 signing (TLS, discovery) and X25519 ECDH (age bridge). ElGamal
decryption `c − a·c0` is the same static Diffie-Hellman function `X ↦ a·X` on
the Edwards form. Thormarker (ePrint 2021/509) proves joint security of Ed25519
signing with an X25519-based hashed KEM under one key in the ROM; this scheme
sits inside that model (the decapsulation output is never exposed unhashed and
all inputs are forced into `G`). Domain separation between the signature uses
is the prefix of 3.7. No new assumption is introduced.

**What is NOT proven**, and is claimed by nothing here. The proof and the
commit check guarantee *consistency* of what recipients receive, not
confidentiality against the author: an author who holds `M` can leak it, can
choose `M = t·B` and publish `t`, or can commit to garbage (a detectable,
attributable denial of service, caught at step 5 of 3.6 or at the AEAD tag).
Admins are trusted for confidentiality, as they are today. Not proven either:
that the author knows `M`; that the re-encrypted ciphertexts were produced
under the committed DEK or decrypt to the previous plaintext (checked by the
server in mode A, rule S5; by readers on decrypt); that the server delivered
the newest record (liveness — pins bound rollback, sections 10 and 11);
forward secrecy (a recipient key leaked later opens every generation it was a
recipient of; old records are retained for auditability, and retired
ciphertext pages are scrubbed by `PRAGMA secure_delete = ON` on every
connection plus a `VACUUM` after migration, best-effort); anything about data
a kicked reader fetched before the kick.

**Hygiene.** Constant-time paths for `r_i·B`, `r_i·A_i`, `k_i·B`, `k_i·A_i`,
`a·c0_i`, and all `Scalar` arithmetic on secrets; `vartime_*` only in the
verifier. `subtle::ConstantTimeEq` for the commit check. `Zeroizing` for every
`r_i`, `k_i`, `m`, `M`, `a`, `DEK`, the seed copy if one is made, and the
`[u8; 64]` RNG/hash buffers. Never log wrap-set private inputs. `OsRng` only;
the hedges are backstops against RNG repetition, not a licence for a weak RNG.

## 4. The epoch record

### 4.1 Layout

Storage and wire form is a CBOR byte string containing this fixed layout;
the hash and the signature are over the layout bytes, so no CBOR
canonicalisation exists anywhere. `group_uid` is the 32-byte permanent group
identity; `group_id` in this document always means the SQLite integer key.

```
magic        "secret-bunker-iroh/epoch/1"   26 bytes, no length prefix
group_uid    32      random at genesis; KDF salt; the group's permanent identity
name         bytes   u32be len ‖ UTF-8 group name (1..=255 bytes); fixed at genesis
epoch        u64be   1 for genesis, then +1
prev         32      hash of the previous record; 0^32 for genesis
kind         u8      1 genesis · 2 rewrap · 3 rotate · 4 carry · 5 recovery
mode         u8      1 server-recipient (A) · 2 end-to-end (E); set at genesis, changed only by recovery (C4/G4)
authority    32      the server's operational Ed25519 key
backup       32      the offline backup Ed25519 key
dek_gen      u64be   the group_dek.version of this generation; +1 iff M changes
dek_commit   32      3.4
n_acl        u32be   then n_acl × (id 32 ‖ perms u8), strictly ascending by id
n_wraps      u32be   then n_wraps × (id 32 ‖ c0 32 ‖ c 32), strictly ascending by id
proof_e      32      0^32 for carry
n_s          u32be   == n_wraps, or 0 for carry;  then n_s × (s 32)
reencrypted  32      digest of the author-staged ciphertext set (4.3); 0^32 iff dek_gen is unchanged
author       32
at           u64be   author's clock, advisory only; < 2^63
---- end of body ----
sig          64      3.7
```

`pinned(rec) = {backup} ∪ ({authority} if mode == A)`.
`readers(rec) = {id : (id, perms) ∈ acl, perms & 1}`.
`recipients(rec) = readers(rec) ∪ pinned(rec)`. Pinned ids never appear in
`acl`. Identity *names* are not in the record: the chain speaks keys, names
stay a server-attested display layer (as replicas already treat them).

Size ≈ 360 bytes + name + 33 per ACL row + 96 per recipient + 32 per response
+ 64. A 50-recipient group is ≈ 8.5 KB per record.

**Kinds.**

| kind | `M` | wraps and proof | who authors | typical use |
|---|---|---|---|---|
| `genesis` | fresh | full set, proof | `authority` (mode A); an admin in `acl` (mode E, deferred) | group creation, migration |
| `rewrap` | unchanged | full set with fresh randomness, proof; `dek_commit == head` | admin of head | add a reader (recipients enlarged); the explicit repair of a bad head (recipients unchanged) |
| `rotate` | fresh | full set, proof; `dek_gen = head + 1`; `reencrypted` set | admin of head; `authority` (mode A, shrink-only) | kick, explicit rotate, the second half of a server-side revocation |
| `carry` | unchanged | wraps a byte-identical **subset** of head's wraps; no proof | admin of head (recipients unchanged); `authority` (shrink) | every ACL edit that leaves the recipient set unchanged; the first half of a server-side revocation |
| `recovery` | either (by `dek_gen`) | full set, proof | `backup` | orphaned or hijacked group; operational-key or backup-key replacement; mode change |

One rule decides the kind of an admin's ACL edit: recipients enlarged →
`rewrap`; recipients unchanged → `carry`; recipients shrunk → `rotate`. A
`rewrap` with unchanged recipients is only the explicit repair
(`client epoch repair`).

### 4.2 Group identity

`group_uid` is 32 random bytes drawn by whoever mints genesis. It — not the
name — is what binds the KDF and the transcript, is the replica's chain key,
and is unique in `secret_group`. The genesis hash is what verifiers pin;
`name` inside the layout stops a chain from being served under another name.

### 4.3 The `reencrypted` digest

Over the ciphertext rows the author staged, exactly as received by the server
(including rows whose version was deleted before the fence), sorted by
`(name, version)`:

```
leaf   = SHA-256(0x00 ‖ u64be(len(name)) ‖ name ‖ u64be(version) ‖ u64be(dek_gen) ‖ nonce (12) ‖ SHA-256(ciphertext))
digest = SHA-256(0x01 ‖ "secret-bunker-iroh/reenc/1" ‖ u32be(count) ‖ leaf_1 ‖ … ‖ leaf_count)
```

An empty set hashes with `count = 0`, so the field is never zero for a
rotating record. The set actually **installed** is the staged set minus rows
dropped at install (their version no longer exists in the snapshot, or its
source changed before the fence); the server records the installed set's
digest, the covered count and the dropped count in `group_epoch` and in the
audit row, and serves them as the unsigned `meta` side table of `Epochs`
(section 9) so `epoch log` can print "re-encrypted 143 by alice (2
dropped)". An offline auditor recomputes `reencrypted` from an export only for
a record whose dropped count is zero.

## 5. Verifier rules (normative)

MUST / MUST NOT are normative. "Verifier" is the server at submission, every
replica at apply, the CLI's client-side verifier, and any offline auditor,
unless prefixed `S` (server only) or `P` (replica only). The first failing
rule rejects the record; nothing is applied.

**Verifier state.** R2, R5 and G6 refer to what a verifier has seen of the
chain. The server holds every chain; a replica holds every chain it mirrors
and rebuilds the seen sets from the whole chain when it re-mirrors a dropped
group (P1); a client or auditor that holds only a pin evaluates R2/R5/G6 over
the records it fetched and says so (section 18). A verifier that holds a pin
but not the pinned record fetches from `head_epoch − 1`, checks that the first
record's hash equals the pin's `head_hash`, and only then treats it as the head.

**Reply mapping (server).** S1 failures answer the uniform `Denied` (on the
server S1 subsumes A2: a non-admin author is a non-admin caller). C2/S3
mismatches answer `EpochConflict{head_epoch, head_hash}` wherever detected.
Every other rejection answers `Failed{reason}` with `reason = "<rule>: <short
text>"` (e.g. `"G2: no admin left"`); the rule ids below are the wire-visible
vocabulary. Stage-related reasons: `"stage: cap"`, `"stage: too many"`,
`"stage: not found"`, `"S5: wrap does not open to dek_commit"`, `"S5: stage
wraps differ"`, `"S5: undecryptable"`, `"S5: plaintext mismatch"`, `"S5: nonce
reuse"`, `"rotation-pending"`, `"needs-rotation"`, `"authority key
unavailable"`.

**Encoding (E).**

- E1 The layout parses exactly: known `magic`, `kind`, `mode`; `perms ∈ 1..=7`;
  no trailing bytes; `name` 1..=255 bytes; `at < 2^63`.
- E2 `acl` and `wraps` are strictly ascending by id (no duplicates); no id
  appears in both `acl` and `pinned`; all `c0_i` in the record are pairwise
  distinct.
- E3 Every id, `c0_i` and `c_i` passes `decode_point` (canonical, torsion-free,
  not small-order, not identity). `proof_e` and every `s_i` are canonical
  scalars.
- E4 `at` MUST NOT be used to accept or reject; a verifier MAY warn if `at` is
  below the head's.

**Chain (C).**

- C1 Genesis: `epoch = 1`, `prev = 0^32`, `kind = genesis`, `dek_gen ≥ 1`. A
  verifier with no head for this `group_uid` accepts a genesis only if it
  holds no pin for `name`, or the pin's `genesis_hash` equals the record's
  hash (a re-mirror after a drop); a verifier holding a head MUST NOT accept
  another genesis.
- C2 Otherwise: `prev == hash(head)`, `epoch == head.epoch + 1`, and
  `group_uid`, `name` equal the head's.
- C3 `sig` verifies under `author` (`verify_strict`, prefix of 3.7).
- C4 `authority`, `backup` and `mode` equal the head's unless `kind = recovery`.

**Recipients and generation (R).**

- R1 `ids(wraps) == recipients(rec)` exactly: no missing recipient, no extra.
- R2 `dek_gen ∈ {head.dek_gen, head.dek_gen + 1}`. `rewrap`/`carry`:
  unchanged, `dek_commit == head.dek_commit`, `reencrypted == 0^32`. `rotate`:
  `+1`, `dek_commit` differs from **every** commit seen for the group,
  `reencrypted ≠ 0^32`. `recovery`: either branch, by `dek_gen`, with the
  matching constraints. `genesis`: `reencrypted ≠ 0^32`.
- R3 Non-`carry`: `n_s == n_wraps` and the proof of 3.5 verifies.
- R4 `carry`: `n_s == 0`, `proof_e == 0^32`, and every wrap entry is
  byte-identical to an entry of `head.wraps` (a subset of a verified set is
  verified).
- R5 Non-`carry`: no `c0_i` equals any `c0` seen earlier (the server keeps
  this set bunker-wide, a replica per mirrored group; with the hedges of 3.3
  a compliant prover never repeats a `c0`, so this is a backstop for a prover
  that skips them — the backup key, present in every group, is what makes a
  cross-group repeat visible), and for every `i`, `KDF(c0_i,
  group_uid).dek_commit` is not in the group's seen-commit set, this record's
  commit included.
- R6 If `recipients(head) ⊄ recipients(rec)` (any recipient removed) then
  `kind ∈ {rotate, recovery-with-rotate}`, or `kind = carry` with
  `author = authority` (a server-side revocation, section 6.3: the server
  sets `needs_rotation`, refuses `Put` on the group, and in mode A rotates
  right after). Taking a key away without changing `M` is never silent and
  never durable.

**Authorship (A).**

- A1 `genesis`: `author == authority`. (`S`: the wire caller is a service
  admin, or it is `init`/`db migrate-epochs`.) Mode E relaxes this (7.2).
- A2 `rewrap`, `rotate`, `carry` by a non-authority: `author` holds the admin
  bit in **`head.acl`**. Being added as admin in the same record does not
  qualify.
- A3 `author == authority` and `kind ≠ genesis`: `kind ∈ {carry, rotate}`;
  `rotate` only if `mode == A`; `acl ⊆ head.acl` entrywise (no new rows, no
  raised bits); `authority`, `backup`, `mode` unchanged (C4). The authority
  can only ever shrink.
- A4 `recovery`: `author == head.backup`. Nothing else may author a recovery —
  not a service admin, not the authority, not an operator with a shell.
- A5 `rotate`: `author ∈ recipients(rec)`. `recovery` with a new generation:
  `head.backup ∈ recipients(rec)` unless `rec.backup ≠ head.backup` (a backup
  replacement is authored by, and its `M` drawn by, the retiring key; if that
  key is suspect an admin rotates once more afterwards, 6.4). Whoever draws a
  new `M` must be entitled to hold it; an admin that leaves a group is rotated
  out by another admin (G5).

**Governance (G).**

- G1 Every ACL entry with the admin bit has the read bit.
- G2 `acl` contains at least one admin, except when `author == authority`
  (removing a compromised identity may orphan a group; recovery is A4).
  Applies to `recovery` too: a recovery that leaves no admin is refused.
- G3 (= R6) any reader removal is a rotation or a server-side revocation.
- G4 `group_uid`, `name` immutable; `authority`, `backup`, `mode` immutable
  except by `recovery`. A recovery that removes a recipient (changes
  `authority` in mode A, replaces `backup`, or switches A→E) MUST be a rotate
  (R6).
- G5 Self-promotion is impossible by A2. An admin MAY drop its own admin or
  write bits (a `carry`, subject to G2). An admin MUST NOT remove its own read
  bit: that is a recipient removal, hence a rotate, hence forbidden by A5 —
  another admin kicks it. `client grant --identity <self>` refuses to clear
  `r` with that explanation.
- G6 A **revived id** is one that appears in the ACL of an earlier record of
  the chain but not in `head.acl`. A `rewrap`, `rotate` or `carry` whose ACL
  adds a revived id MUST make no other ACL change (verifiers holding the chain
  enforce this; a pin-only client cannot and says so). A `recovery` is exempt:
  its ACL is deliberate by construction (A4). First-time ids are
  unconstrained, so multi-reader grants stay one record. What G6 does not
  catch — a non-compliant client resubmitting a stale ACL whose only delta
  happens to be one revival — is a client-side residual covered by the 6.2
  delta rule. A kicked key can never replay the record in which it was a
  recipient (C2).
- G7 Mode E only: every entry with the write bit has the read bit (a writer
  without the DEK cannot produce ciphertext).

**Server-only (S).** S9 and S10 bound wire submissions by non-authority,
non-backup authors; the only authority record a freeze holds back is the
rotating half of a revocation (6.3), and recoveries are never rate-limited.

- S1 The submitting connection's EndpointId equals `author`, and `author` is
  not a configured operational key; `recovery` records may be carried by any
  registered identity. For a caller that is not an admin of the group and
  whose record is not a recovery that passes C1–C4 against the current head
  (chained on it, not merely signed; evaluated first), the answer is the
  uniform `Denied`: `SubmitEpoch` must not be a group-existence oracle. The
  same gating applies to `OpenStage`: a stage is admitted only for a caller
  holding the admin bit in `head.acl` (service admin implicit in mode A, as
  for `ExportGroup`), or whose `OpenStage.recovery` passes C1–C4 against the
  current head; anything else, including a reader, a write-only identity, a
  stale recovery record and an unknown group, answers `Denied`.
  `StageVersions`/`SubmitEpoch` on a stage that was not admitted answer
  `Denied`.
- S2 Every id in `acl \ head.acl` is a registered identity, re-checked inside
  the install transaction. For `genesis`, `authority` is
  `meta.operational_ed25519` and `backup`/`mode` the configured defaults
  (`meta.backup_ed25519`/`meta.epoch_mode`, changed only by the explicit
  operator steps `db set-backup`/`db set-mode`, audited). For `recovery`, the
  record's `authority` is either `meta.operational_ed25519` or
  `meta.operational_ed25519_previous` (6.4); `backup` and `mode` are read
  from the record itself (C4) and never written to `meta`.
- S3 CAS: C2 is evaluated against the current head under the store lock;
  mismatch answers `EpochConflict{head_epoch, head_hash}` and changes nothing.
  Records rejected here are never persisted. The `frozen` flag (S10) is
  evaluated here too.
- S4 Rotating records: at `OpenStage` the server snapshots the group's
  retained `(name, version, dek_gen, nonce)` rows and fences `Put`/`Delete`
  (6.1), so at commit the retained set equals the snapshot. Every snapshot
  row must be **covered**: a staged row names it and names its source
  `(src_dek_gen, src_nonce)`. Uncovered rows answer `StaleVersions{versions}`
  and the client stages exactly those; a staged row whose version is not in
  the snapshot, or whose source does not match it (deleted and re-created
  before the fence), is dropped, not installed. The digest of the staged rows
  as received equals `reencrypted`. The server never re-encrypts on a
  client's behalf: a rotate that stages nothing against a non-empty group is
  answered with every row, at the author's cost.
- S5 Mode A, every record that carries wraps (`genesis`, `rewrap`, `rotate`,
  `recovery`): before S3 the server opens its own wrap **from that record**
  and refuses unless `KDF(M')` reproduces `dek_commit` — a rewrap that copies
  the head's commit over a different `M` never lands. For a `recovery` the
  wrap opened is the one addressed to the record's `authority` (either `meta`
  key); for every other record, the head's. For rotating records the per-row
  checks run at `StageVersions` time, per message: at `OpenStage` the server
  opens its own wrap in `OpenStage.wraps`, checks the supplied `dek_commit`
  (refusing the stage otherwise), and keeps the derived DEK with the
  `epoch_stage_open` row (zeroized when the stage is deleted); each staged row
  is decrypted under that DEK and its AAD and the source row under the old
  DEK, and the message is refused unless the plaintexts are byte-identical
  and no `(dek_gen, nonce)` pair repeats within the group; a staged row whose
  source does not match the snapshot is not checked (S4 will drop it). At
  `SubmitEpoch` the record's wrap set and `dek_commit` must be byte-identical
  to the stage's `wraps` (`"S5: stage wraps differ"`); a rebase that changes
  the recipient set re-opens the stage with the new wraps, which keeps the
  staged rows when `dek_commit` is unchanged. The DEK cache is keyed by
  **record hash** and populated only from a wrap the server opened for that
  record.
- S6 A `carry` whose ACL equals `head.acl` is refused (`"S6: no-op epoch"`);
  a `recovery` is never a no-op. A `rewrap` with an unchanged ACL is the
  explicit repair and is allowed.
- S7 `AddIdentity` refuses an id that appears in any group's head ACL, and
  any id equal to a configured operational (current or previous) or backup
  key (`"E2: pinned id"`). The first state is unreachable by construction (a
  removed id leaves every head in the transaction that deregisters it, 6.3;
  `db remove-identity` on a migrated database authors the same carries); the
  rule is defensive.
- S8 Verification (E/C/R/A/G) and the S5 wrap check run **outside** the store
  lock on a blocking thread; the lock is taken only to snapshot the head, then
  for S3/S4 and the install transaction (6.1). `Bunker::handle` routes
  `OpenStage`, `StageVersions`, `SubmitEpoch`, `RemoveIdentity` and legacy
  shrink `Grant` to `Bunker::open_stage`/`stage_versions`/`submit_epoch`/
  `revoke`, which take and drop the lock themselves; `accept` awaits
  `tokio::task::spawn_blocking` for those variants, everything else stays on
  the synchronous path. The generic post-dispatch audit row is skipped for
  `SubmitEpoch` (the install transaction writes it). Verified records and
  DEKs are cached in memory keyed by record hash (LRU of 1024 records and 256
  DEKs bunker-wide, zeroized on evict).
- S9 Rate limit, per non-authority, non-backup author per group: at most 5
  accepted non-rotating and 1 accepted rotating `SubmitEpoch` records per 60 s
  (`"S9: rate"`, audited). It makes churning the head costlier than rebasing
  onto it (6.1 step 8) while leaving room for a burst of TUI edits.
- S10 `FreezeGroup{group, frozen}` (service admin, audited; unknown group →
  `Denied`): while frozen the server answers every wire mutation on the group
  — `Put`, `Delete`, legacy `Grant` that is not a strict-subset shrink,
  non-`recovery` `SubmitEpoch` — with `Failed{"S10: frozen"}`, evaluated under
  the lock with S3. Server-side revocation carries (`RemoveIdentity`, legacy
  shrink `Grant`) still land (denying a removed key is the freeze's own
  purpose); the rotating half is deferred while frozen. A recovery does **not**
  clear the freeze: the operator verifies the new head with `client epoch log`
  and unfreezes explicitly, so a multi-record ceremony cannot be raced between
  records. Denial is within the authority's shrink-only power (D4); the freeze
  is what lets an offline-signed recovery land against an admin who is online
  and churning.

**Replica-only (P).** See section 10.

## 6. Operations

### 6.1 Kick / explicit rotate (client-side, by an admin)

```
1. GroupEpochs{group, since: pinned head − 1}  →  check the first record against the pin;
   verify the tail; head
2. own wrap in head  →  M_old  →  (DEK_old, commit check)
3. ExportGroup{group, after, limit} pages  →  every retained (name, version, dek_gen, nonce,
   ciphertext, created_at, created_by)     (admin; service admin in mode A)
4. fresh M_new (retained in Zeroizing memory for the flow); per row: decrypt (DEK_old,
   aad(group, name, version, dek_gen_old)), re-encrypt (DEK_new, aad(group, name, version,
   dek_gen_new), fresh nonce); the staged row carries src_dek_gen/src_nonce of the row it
   replaces; plaintext zeroized after each row
5. OpenStage{group, stage_id, wraps}  →  Ok   (stage_id: 16 random bytes, client-chosen;
   `wraps` = the new wrap set + dek_commit; the server snapshots the retained rows and the
   fence starts here)
   StageVersions{group, stage_id, versions} — messages of at most 3.5 MiB, or exactly one
   version when that version alone is larger (upsert by (name, version))
6. build the record: kind = rotate, acl = head.acl minus the target (row deleted, or bits
   cleared), the stage's wraps, proof over (prev, epoch), dek_commit, reencrypted = digest of
   the staged rows as the client sent them; sign
7. SubmitEpoch{group, stage_id, record}  →  Ok | EpochConflict | StaleVersions | Failed
8. StaleVersions: ExportGroup{versions: <listed>}, re-encrypt and restage exactly those rows,
   rebuild the record (new digest, new signature), resubmit with the same stage_id.
   EpochConflict: refetch the head and show the intervening ACL diff. If every intervening
   record left dek_gen unchanged: recompute the wrap set for the new head's recipients minus
   the target from the retained M_new (fresh r_i), re-open the stage with the new wraps if the
   recipient set changed (staged rows are kept, same dek_commit), re-prove over the new
   (prev, epoch), re-sign, resubmit. Otherwise restart at step 2. Refuse to rebase
   automatically over a record authored by the kick target.
```

**The escalation ladder** when the target is an online admin who keeps moving
the head (or strips the kicker's admin bit with a `carry`): (1) the client-side
kick above; (2) a legacy shrink `Grant` (server-side revocation, one lock
hold; needs the requester to still be an admin in the projection and the
target not to be the last admin); (3) `RemoveIdentity` by a service admin
(always wins, may orphan); (4) a backup-signed recovery behind `FreezeGroup`
(6.4); (5) against a rogue *sole service admin*: service stopped, `db
remove-identity --name <rogue> --operational-key` (authors the carries) and
`db set-service-admin`, restart, then (4). 7.4 states the same ladder.

Peak client memory is one page. Bandwidth is `2 × total retained ciphertext`
over the admin's iroh connection.

**Write fence.** From `OpenStage` until the stage is submitted, aborted or
expires, `Put` and `Delete` on the group answer `Failed{"rotation-pending"}`
(both modes). Only an admin of the group or a recovery carrier can open a
stage (S1), and an accepted rotate — by an admin or by the server — deletes
every other open stage on the group. `SubmitEpoch{group, stage_id, record:
null}` aborts a stage.

**Server side** (`SubmitEpoch`), the two-phase discipline every rotating
operation uses, including server-authored rotates:

1. Under the lock: snapshot the head record; release.
2. On a blocking thread: S1, E/C/R/A/G against the snapshot head; in mode A,
   the S5 wrap check and the stage-binding check.
3. Under the lock, in **one SQLite transaction**: S3 CAS (head unchanged,
   not frozen); S2 re-check for added ids; S4 coverage against the stage's
   snapshot; insert `group_epoch` (with `installed_digest`, `covered`,
   `dropped`); insert the `group_dek` registry row for a new generation;
   `UPDATE secret_version SET dek_version, nonce, ciphertext` for every
   covered row; rebuild `group_acl` from the record; update
   `secret_group.head_epoch`; clear `needs_rotation` iff `dek_gen ==
   head.dek_gen + 1`; delete the stage (and every other stage on the group);
   audit `submit-epoch` (target `group@epoch#hash[..16]`, outcome `ok`,
   `covered=n dropped=m`) and, for continuity with today's log, `rotate-dek`,
   both via `Store::audit_in(&tx, …)`; commit; publish `Changed`; enqueue the
   rotation worker's sweep (6.3).

Readers see the old generation until the commit and the new one after; there
is no intermediate state. A crash before commit leaves only stage rows.

**Stages.** A stage is keyed by `(group_id, submitter, stage_id)`; a second
`stage_id` from the same submitter for the same group replaces the first;
`SubmitEpoch` resolves the stage by `(group, connection EndpointId,
stage_id)`. `OpenStage.wraps = u32be(n_wraps) ‖ n_wraps × (id 32 ‖ c0 32 ‖ c
32) ‖ dek_commit 32`, validated with E2/E3 and the S5 own-wrap check at
`OpenStage` and stored verbatim; when `recovery` is present `wraps` is taken
from the record and the field must be empty. A submitter may hold at most two
open stages bunker-wide (`"stage: too many"`), each subject to a
per-`(group, submitter)` byte cap of `2 × total retained ciphertext of the
group + 16 MiB` (`"stage: cap"`; the total is reported by `GroupStatus`). A
stage expires 15 minutes after its last `OpenStage`/`StageVersions`/
`SubmitEpoch` (idle TTL, 6 h hard ceiling); sweeps remove whole stages, never
single rows. A server-authored rotate holds its rows in memory (no stage
rows).

### 6.2 Add a reader, edit bits

- **Add reader**: the admin obtains the grantee's EndpointId either directly
  (`--endpoint-id`, e.g. from the operator pod's identity Secret) or by name
  through `ResolveIdentity{group, name}` (admin-gated). The CLI prints the
  resolved id and requires `--expect-id <hex>` or an interactive confirmation
  of it: the registry is server-controlled and a compromised node could answer
  with any key. The admin then re-wraps the current `M` with fresh randomness
  to the enlarged set (`rewrap`, same `dek_commit`, no re-encryption, no
  stage) and submits. Several readers, and bit changes, fit in one record;
  a delta that touches a revived id is split by the CLI into a sole-revival
  record and the rest (G6), and a G6 refusal is handled the same way.
- **Edits leaving recipients unchanged** (`w` either way; `a` on a reader;
  dropping `a`): `carry` with head's wraps verbatim. Raising `a` on an entry
  without `r` enlarges the recipients (G1) and is a `rewrap`.
- **Revoke read**: 6.1.
- **EpochConflict**, every flow: re-read the head and re-apply the *delta*
  (add carol; clear bits on X) to the new head — never resubmit a previously
  computed ACL — and abort with the diff if any recipient of the old head is
  missing from the new one (someone else kicked in between). G6 is the
  verifier backstop for a non-compliant client's multi-change resubmission.

### 6.3 Server-authored records

All server-authored records go through the same verifier and the same
two-phase discipline; the audit row (`epoch-carry`, `rotate-dek`, via
`audit_in` inside the transaction) names the wire requester; S9 does not apply
to them and S10 holds back only the rotating half.

- **Server-side revocation** (the immediate half): under the lock, in one
  transaction, the server authors one authority `carry` per affected group
  that drops the identity's row and its wrap (if it was a reader), sets
  `secret_group.needs_rotation = 1` for groups where it was a reader, and
  commits. From that commit: the identity is denied on the authoritative
  node; every replica drops it on apply; `Put` on a flagged group answers
  `Failed{"needs-rotation"}` (both modes — nothing may be written under a key
  a removed party holds); `GroupStatus` and the TUI (`!`) surface the flag.
- **The rotating half** (mode A): a rotation worker (`Bunker::spawn_rotator`,
  started once by `main.rs`'s `Serve` branch before `serve_with_rebind`, so
  per-generation rebinds do not restart it; tests drive
  `Bunker::run_pending_rotations()` synchronously) performs an authority
  `rotate` for each group with `needs_rotation = 1`: fresh `M`, server-side
  re-encryption of every retained version it can open, no client stage. A
  retained row the server cannot open (corrupt ciphertext) is quarantined
  (`secret_version.unreadable = 1`: excluded from serving, coverage and sync;
  audited `rotate-quarantine`), so the rotate always lands. The worker scans
  `needs_rotation = 1` at startup (audited `rotate-resume`), after every
  install transaction, and on a backoff timer; it re-reads the flag under the
  lock and stops when an admin's rotate cleared it; it defers a frozen group
  and a group whose head names an operational key the server does not hold.
  The record is signed by, and opens wraps with, the operational key the
  group's head names (6.4). Mode E: an admin rotates (6.1); until then the
  group is read-only.
- **`RemoveIdentity`** (service admin): unchanged wire request. Deletes the
  identity row and performs the revocation above for every group the identity
  had a row on (a `carry` dropping the row for write-only rows, with no flag).
  Never blocked, never rate-limited, lands on a frozen group; may orphan a
  group (G2 exception), whose recovery is 6.4. Today's refusal to remove the
  last service admin is kept; rung 5 of the ladder covers a rogue sole service
  admin.
- **Legacy `Grant`**: a request whose bits equal the current row answers `Ok`
  and authors nothing (idempotent, as today). A request whose bits are a
  strict subset of the current row's (including `perms = 0`) performs the
  server-side revocation above — a `carry`, plus the rotating half when the
  read bit was cleared — subject to today's last-admin guard (an ACL edit is
  never urgent; only `RemoveIdentity` may orphan), and lands on a frozen
  group. Any other request answers `Failed{"signed epochs: use a signing
  client"}` after the authorization check. **Legacy `RotateDek`** answers the
  same `Failed`. Q2 assumes the Go client uses neither; if it does, that is a
  spec change (server-signed additive records would need a service-admin
  explicit row and reintroduce D4's concern).
- **`CreateGroup`**: unchanged wire request; the server mints `genesis` with
  `acl = {creator: rwa}`, `mode` from `meta.epoch_mode`, fresh `M`, `dek_gen
  = 1`, an empty `reencrypted` set, signed by `meta.operational_ed25519`.
  `CreateGroup` gains the `name` length check of E1; the CLI prints the new
  group's genesis hash. Client-submitted genesis is the mode-E creation path
  (deferred).

### 6.4 Recovery with the offline backup key

Triggers: a rogue admin locked everyone out; all admin keys lost; suspected
operational-key compromise; operational key **lost**; `authority`/`backup`
replacement; mode change.

```
0. a rogue admin whose key can be deregistered: RemoveIdentity (immediate denial, automatic
   rotate) — no ceremony needed. Otherwise, or when several admin keys are suspect:
   client freeze-group --group g
1. any admin, or a service admin in mode A:  client epoch export --group g --out g.bundle
   (chain + every retained version's ciphertext, via GroupEpochs + ExportGroup); export only
   when GroupStatus shows frozen; if it also shows needs_rotation, author with --rotate
2. offline machine:  secret-bunker-iroh recovery author --bundle g.bundle --backup-key backup.key
                       [--acl id:rwa …] [--keep-acl] [--rotate] [--authority <id>] [--backup <id>] [--mode A|E]
   verifies the chain, opens the backup wrap, builds kind = recovery chained on the bundle's
   head (+ the re-encrypted set if --rotate or if R6 requires it), signs → g.recovery.
   No --acl: head.acl unchanged. --acl: the listed entries are the entire ACL (--keep-acl merges).
   A recovery may revive any number of ids and remove the rogue in one record (G6 exempts it).
3. any registered identity:  client epoch submit --bundle g.recovery   (S1 exception; OpenStage
   carries the recovery record, which admits the stage; the record's wraps are the stage's)
4. the operator verifies the head with `client epoch log`, repeats 1–3 if more records are
   needed, then `client freeze-group --group g --unfreeze`
```

The backup key never comes online and the service is never stopped. A
`RemoveIdentity` touching the group after the export moves the head; `client
epoch submit` then reports the intervening records (as 6.1 step 8) and the
bundle is re-exported and re-signed. This one flow replaces `db grant`
(orphaned group) and `recover` (operational-key compromise). The backup key
is the group's root, as it already is today (it opens every DEK); what is
new and explicit is that it is the **only** root: no shell command reaches
the chain without it. A stolen backup key that re-roots a group (replacing
`backup`) can only be undone by restoring the authoritative database from a
snapshot and resetting replica pins.

**Backup replacement** (`--backup <id> --rotate`): authored by the retiring
key, which draws the new `M` (A5). For a routine replacement nothing else is
needed; when the old key is suspect, any admin runs `client rotate` afterwards
so the live generation was not drawn by it. The server's genesis default for
new groups changes with `db set-backup` (audited).

**Operational-key replacement.** `serve --operational-key new.key
--previous-operational-key old.key`: at start, `meta.operational_ed25519 :=
new` and `meta.operational_ed25519_previous := old` (audited
`authority-rotated`); genesis records and S2's "configured" authority mean the
new key; server-authored records on a group are signed by, and open wraps
with, the key the group's head names (A1/A3); `read_secret` and S5 do the
same. Replicas' `expect_keys` accept a list; the operator adds the new key to
`bunker.expectAuthorityId` on every replica before creating groups. The
operator authors one recovery per group (`--authority <new id> --rotate`; a
rotate because the old authority is a removed recipient in mode A).
`GroupStatus` shows which groups still name the previous key; a start without
`--previous-operational-key` is refused while any head names it, and clears
the `meta` row otherwise.

**Operational key lost.** `serve --operational-key new.key
--previous-operational-id <hex>` (public key only) satisfies that check;
groups whose head names a key the server does not hold answer
`Failed{"authority key unavailable"}` to `Get`/`Put`, are skipped by the
rotation worker and S5, and come back one by one as their recoveries land.
For a server that cannot start at all, `db submit-recovery --db bunker.sqlite
--bundle g.recovery` runs the verifier and the install transaction against the
file with the service stopped (the `SubmitEpoch` code path without S1).

**A recovery bundle chains on the head the bundle was exported from** (C2).
After an authoritative restore from an older snapshot, the recovery chains on
the restored head; replicas that saw a later head reject the rewound chain
and are reset by the operator (D9, section 10).

### 6.5 Attribution

`client epoch log --group g` prints the verified chain, one line per record,
rendering the unsigned `Epochs.meta` side table and `names` map:

```
#12 2026-09-07T10:41Z alice(1a98…)   rotate gen 9   −bob(r)   re-encrypted 143 by alice (2 dropped)
#11 2026-09-06T18:03Z carol(7c01…)   rewrap gen 8   +dave(r)
#10 2026-09-06T17:50Z authority (requested by carol, unsigned)   carry   −erin(r)  [needs-rotation]
```

"Who last re-encrypted" = author of the newest record with `reencrypted ≠ 0`;
"who last changed membership" = author of the head. Authority-authored records
are rendered with the audit requester marked as unsigned. `client epoch status
--group g` prints `GroupStatus` next to the local pin with a verdict (`ok`,
`behind`, `fork`). Per-version authorship (`created_by`) remains
server-attested in mode A; a signed put is the mode-E extension (Q10). A
kicked identity may fetch the chain up to and including the record that
removed it (one-record grace in `GroupEpochs`), so the loud record is visible
to the party with standing to dispute it.

## 7. Roles, modes, threat model

### 7.1 Mode A (server-recipient) — built

`pinned = {backup, authority}`. The server derives each group's DEK from its
own wrap (cached per record hash), serves plaintext `Get`, accepts plaintext
`Put` from write-only identities, and keeps service-admin implicit read/write
through the server. Gained: verifiable, admin-authored, admin-attributed
membership and rotation that the server cannot forge and replicas check; a
submit-time guarantee — by the server's own wrap (S5) — that every recipient's
wrap, the backup key's included, opens to the committed DEK. Not gained:
confidentiality against the operator (a stated non-goal).

### 7.2 Mode E (end-to-end) — specified, deferred

`pinned = {backup}`. The server verifies, stores and relays; it holds no DEK.
Extra rules, so the flag can be chosen now: A1 becomes "`author` is an entry
of `acl` with the admin bit; S1 applies; the wire caller is a service admin";
`Put` carries ciphertext (`PutSealed{group, name, expected_version, dek_gen,
nonce, ciphertext}` → `Version`/`VersionConflict`/`StaleEpoch{dek_gen}` when
`dek_gen` is not the head's); `Get` answers `Sealed{version, dek_gen, nonce,
ciphertext, epoch_hash}`; G7; no service-admin implicit read; S5 is skipped
(no key), so a bad head is detected by the first reader and repaired by an
admin `rewrap`; `needs_rotation` fails writes closed until an admin rotates;
per-version plaintext commitments (the writer signs `group_uid ‖ name ‖
version ‖ SHA-256(salt ‖ plaintext)`; stored with the row, carried across
rotations, verified by readers) so a rotation cannot rewrite history; every
client (Go included) implements 3.5–3.7, chain verification and pins.

### 7.3 Where each party sits

| Party | Holds | In the chain as | May author |
|---|---|---|---|
| Group admin | own iroh key | `acl` entry `rwa`/`ra` (G1) | `rewrap`, `rotate`, `carry` |
| Reader | own iroh key | `acl` entry with `r`; recipient | nothing |
| Writer (mode A) | own iroh key | `acl` entry with `w`, no wrap | nothing; plaintext `Put` via server |
| Replica / k8s operator | own iroh key | reader | nothing; verifies everything |
| Service admin | own iroh key + registry flag | nothing unless granted | nothing; `CreateGroup` triggers a server genesis; `RemoveIdentity`/legacy shrink `Grant` trigger server revocations; `FreezeGroup` |
| Server | endpoint key + operational key | `authority` (+ recipient in mode A) | `genesis`, shrink-only `carry`/`rotate` |
| Operator, offline | backup key | `backup` | `recovery` |

**Service admins after migration.** They keep the registry, group creation,
`RemoveIdentity`, `FreezeGroup`, implicit read/write through the server in
mode A, and shrink-only revocations through legacy `Grant`. They can no longer
add a reader to, or rotate, a group where they hold no explicit admin row:
those are admin-signed records. `db migrate-epochs --service-admins-as-group-admins`
adds explicit `rwa` rows for every current service admin (audited) so today's
operational model survives; new groups they create name them as creator.
`ListGroups` gains `chain_perms` per group (the caller's explicit bits) so the
TUI greys out what the caller cannot author. **User decision** (Q14).

### 7.4 Threat-model delta versus `design/crypto-design.md`

| Threat | Today | New (mode A) |
|---|---|---|
| Hostile / compromised authoritative node | Reads everything; rewrites ACLs; feeds replicas any roster; forges `created_by` | Still reads everything (not in mode E). **Cannot** add a reader, raise a bit, change `backup`/`authority`/`mode`, or forge a rotation that adds anyone: replicas verify A2/A3/C4. Can withhold, serve a stale chain, equivocate between replicas (each sees a valid monotone history; detectable only by comparing heads), lie about names — including answering `ResolveIdentity` with a key of its choosing, which is why the admin confirms the key (6.2) — invent new groups, present a new chain under a name a replica has **never mirrored or whose pin was reset** (D14; pin the names that matter), and orphan groups (shrink-only). |
| Compromised admin key | Reads the group; strips any admin but the last; service admin undoes it | Reads the group; can lock everyone out **loudly** (the record names it) and can strip other admins' bits with a `carry`; undone by the ladder of 6.1: a surviving admin, a server-side revocation, `RemoveIdentity`, a backup-signed recovery behind `FreezeGroup`, or the offline rung against a rogue sole service admin. Cannot rewrite plaintext through a rotation (S5). Cannot rotate itself out and keep the key (A5). A stale-ACL resubmission by a broken client that revives exactly one id is a client-side residual (G6). |
| Compromised reader key | Forward protection after revocation; old versions under old DEKs stay readable from a copy | Same until kicked; after the rotate nothing in the database is under a generation it knew (D6). During a server-side revocation's window the group is write-fenced and the rotate resumes across restarts. Copies taken before the kick are unaffected. |
| Stolen SQLite (authoritative) | Readable by any reader/operational/backup key of retained DEK versions | Readable only by keys in the *current* record's wraps (old records' wraps open an `M` that protects nothing once the rotate landed). The chain history — who was in, who kicked whom — is in the file in signed form: ACL-grade metadata. |
| Stolen replica database | Roster + ciphertext | Same, plus chain history. |
| Replica lag / partition | Serves last mirror; silently follows a rewound authoritative node | Same bound; cannot be fed a forged ACL; a pinned replica detects rewinds and forks and holds its last verified state. |
| Database write access (operator) | Rolls back versions; redirects wraps | Rolling back a version is still possible (unauthenticated CAS pointers, as today); redirecting wraps or editing membership is not (R1/C3 on every verifier). |
| Compromised operational key | Reads everything; recovery re-wraps | Reads everything (mode A); can author shrinks. Replaced by per-group recoveries on a two-key server; no additive power to abuse. A lost key is recovered the same way (6.4). |
| Compromised backup key | Reads everything | Reads everything and authors recoveries; it was the root already, now it is the only one. A re-root by a stolen backup key is undone only by restoring from a snapshot and resetting pins. |
| Malicious admin sabotaging recoverability (bad backup wrap) | Impossible (server mints wraps); would be possible with "age wraps + signature" | **Impossible**: R1/R3 guarantee every listed recipient gets the same `M` (keyless, at submit), and S5 guarantees it is the committed one (the server's wrap, at submit). |

### 7.5 What the proof buys over "age wraps + author signature"

Signing today's record (ACL + per-recipient age wraps) would already give
attribution and admin autonomy for roughly a third of the work. What it cannot
give: a keyless verifier. With age wraps a rogue or buggy admin can list X as a
reader and hand X a wrap of some other key; only X can tell, when it next
decrypts (for the k8s operator: at 3 a.m.; for the offline backup key: on
disaster day). With the proof, the server, every replica and any auditor
reject that record at submission. That is the one property that is invisible
until it matters, and it is what makes mode E possible at all. Cost: ~300
lines of curve code with golden vectors, one Ed25519 key ceremony, and
verification measured in milliseconds.

## 8. Storage: schema v3

```sql
-- new
CREATE TABLE group_epoch (
  group_id         INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
  epoch            INTEGER NOT NULL,
  hash             BLOB    NOT NULL,      -- 3.7
  prev             BLOB    NOT NULL,
  kind             INTEGER NOT NULL,
  dek_gen          INTEGER NOT NULL,
  dek_commit       BLOB    NOT NULL,
  author           TEXT    NOT NULL,      -- hex, denormalized for queries
  at               INTEGER NOT NULL,
  record           BLOB    NOT NULL,      -- exact layout bytes incl. sig, never re-serialized
  installed_digest BLOB,                  -- 4.3; NULL for non-rotating records
  covered          INTEGER NOT NULL DEFAULT 0,
  dropped          INTEGER NOT NULL DEFAULT 0,
  requested_by     TEXT,                  -- wire requester of an authority-authored record
  received_at      INTEGER NOT NULL,
  PRIMARY KEY (group_id, epoch), UNIQUE (group_id, hash)
);
CREATE TABLE epoch_stage (
  group_id    INTEGER NOT NULL REFERENCES secret_group(id) ON DELETE CASCADE,
  submitter   TEXT    NOT NULL,
  stage_id    BLOB    NOT NULL,
  name        TEXT    NOT NULL,
  version     INTEGER NOT NULL,
  dek_gen     INTEGER NOT NULL,
  nonce       BLOB    NOT NULL,
  ciphertext  BLOB    NOT NULL,
  src_dek_gen INTEGER NOT NULL,
  src_nonce   BLOB    NOT NULL,
  staged_at   INTEGER NOT NULL,
  PRIMARY KEY (group_id, submitter, stage_id, name, version)
);
CREATE TABLE epoch_stage_open (        -- one row per open stage: the fence, the wrap set, the snapshot, the idle clock
  group_id INTEGER NOT NULL, submitter TEXT NOT NULL, stage_id BLOB NOT NULL,
  wraps BLOB NOT NULL, snapshot BLOB NOT NULL,      -- snapshot: CBOR list of (name, version, dek_gen, nonce)
  opened_at INTEGER NOT NULL, touched_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, submitter, stage_id)
);
CREATE TABLE group_pin (               -- replica only: survives dropping the group
  name TEXT PRIMARY KEY, group_uid BLOB NOT NULL, genesis_hash BLOB NOT NULL,
  head_epoch INTEGER NOT NULL, head_hash BLOB NOT NULL
);
-- altered (each ALTER guarded by pragma_table_info, all in one BEGIN/COMMIT)
ALTER TABLE secret_group   ADD COLUMN group_uid      BLOB;                    -- NULL until migrated
CREATE UNIQUE INDEX IF NOT EXISTS secret_group_uid ON secret_group(group_uid) WHERE group_uid IS NOT NULL;
ALTER TABLE secret_group   ADD COLUMN head_epoch     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE secret_group   ADD COLUMN needs_rotation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE secret_group   ADD COLUMN frozen         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE group_dek      ADD COLUMN epoch          INTEGER;                 -- the record that introduced the generation
ALTER TABLE secret_version ADD COLUMN unreadable     INTEGER NOT NULL DEFAULT 0;
-- meta: schema_version=3, epoch_mode, operational_ed25519, operational_ed25519_previous, backup_ed25519, epochs_migrated
```

(SQLite refuses `ADD COLUMN … UNIQUE`; the partial unique index is the
equivalent. Both DDL forms were checked against SQLite 3.51.) `group_dek`
stays the generation registry (`version` continues the same counter, so
`secret_version.dek_version` and `crypto::secret_aad` are untouched; a
genesis's `dek_gen` is whatever row it inserts, C1). After migration every
retained version is under the head generation and `dek_wrap` is empty on the
authoritative node; on a replica, pre-migration `dek_wrap`/`group_dek` rows
of a group are deleted at its first accepted genesis. The table and
`agebridge.rs` are dropped in a later v4 cleanup. `group_acl` becomes a
**projection** of the head record, rebuilt inside every apply transaction, so
`authorize_group`, the sync scope query and the TUI need no change;
`RemoveIdentity`'s `ON DELETE CASCADE` on `group_acl` is harmless (the
projection is rebuilt from the record authored in the same transaction). The
seen-`c0`/seen-commit sets (R5) are derived from `group_epoch` at startup and
kept in memory. `Store::audit_in(tx, …)` appends audit rows inside a
transaction, sharing the hash-chain code with `audit`. `Store::open` sets
`PRAGMA secure_delete = ON` next to `foreign_keys` for both roles. The CLI's
pins are a JSON file (section 11), not this table.

`Store::is_initialized()` and `Bunker::new` key on `meta.operational_ed25519`
(and `backup_ed25519`, `epoch_mode`); the age rows `operational_pubkey`/
`backup_pubkey` are left in `meta` after migration for snapshot forensics and
never consulted. `Bunker::new` takes the Ed25519 operational key(s) — or the
previous key's public id when the key is lost — and no age identity (callers:
`main.rs`, `src/server.rs` tests, `tests/e2e.rs spawn_authoritative`).

## 9. Client protocol: additive variants on `secret-bunker/1`

Existing variants and fields are untouched; the Go client keeps working.

**Sizes.** `Put.value` gains an explicit handler cap `MAX_VALUE = MAX_MSG −
4 KiB` (`Failed{"value too large"}` after authorization), documented in
`protocol.md` and the Go README; the existing cap-sized e2e test moves to
`MAX_VALUE`. Every stream read bound — the server's, the client's and the
replica's — becomes `MAX_MSG + 64 KiB`, so one cap-sized ciphertext fits
inside an `Export` page or a `StageVersions` message, and every existing
`Secret` reply still fits an old client's `MAX_MSG` bound. `Epochs` replies
are budgeted to `MAX_MSG`; `Export.limit` is a row count that the server
clamps so the encoded reply fits the read bound, always returning at least
one row.

| Request | Requires (service-admin implicit in mode A?) | Reply |
|---|---|---|
| `GroupStatus{group}` | `read` (yes) | `Status{group_uid: bstr, genesis_hash: bstr, head_epoch: uint, head_hash: bstr, dek_gen: uint, mode: uint, authority: text, needs_rotation: bool, frozen: bool, stage_open: bool, retained_bytes: uint, last_rotate: null or {epoch: uint, author: text, at: uint, covered: uint, dropped: uint}, chain_perms: uint}` |
| `GroupEpochs{group, since}` | `read`, plus the one-record grace of 6.5 (yes) | `Epochs{records: [bstr], head_epoch: uint, names: [{endpoint_id: text, identity_name: text}], meta: [{epoch: uint, requested_by: text or null, covered: uint, dropped: uint}]}` (records with `epoch > since`, ascending; page by the last returned epoch; `meta` is server-attested, unsigned) |
| `ResolveIdentity{group, name}` | `admin` on `group` (yes) | `IdentityId{endpoint_id: text}` |
| `ExportGroup{group, after: [name, version] or null, limit, versions: [[name, version]] or null}` | `admin` (yes) | `Export{versions: [SealedVersion], next: [name, version] or null}` (`versions` present: only those rows, `after`/`limit` ignored) |
| `OpenStage{group, stage_id: bstr(16), wraps: bstr, recovery: bstr or null}` | S1 gating (yes, via admin) | `Ok` |
| `StageVersions{group, stage_id, versions: [SealedVersion]}` | an admitted stage (n/a) | `Ok` |
| `SubmitEpoch{group, stage_id: bstr or null, record: bstr or null}` | S1 (no) | `Ok`, `EpochConflict{head_epoch, head_hash}`, `StaleVersions{versions: [[name, version]]}`, `Failed{reason}` |
| `FreezeGroup{group, frozen: bool}` | service admin (n/a); unknown group → `Denied` | `Ok` |

`SealedVersion = {name, version, dek_gen, nonce, ciphertext, created_at,
created_by, src_dek_gen, src_nonce}`; on input `created_at`/`created_by` are
informational and ignored (a rotation never changes a row's provenance);
`src_*` are required by `StageVersions`. Every new mutation answers
`ReadOnlyReplica` on a replica to registered callers and the uniform `Denied`
to unregistered ones; a replica answers `GroupStatus` and `GroupEpochs` from
its verified mirror (read-gated by the mirrored ACL, `Denied` otherwise) and
`ResolveIdentity`/`ExportGroup` with `ReadOnlyReplica`. `Request::op()`
names: `group-status`, `group-epochs`, `resolve-identity`, `export-group`,
`open-stage`, `stage-versions`, `submit-epoch`, `freeze-group`;
`touched_groups` gains `SubmitEpoch`, `FreezeGroup` and the server-authored
revocations. Golden vectors for every new variant go into
`proto::tests::wire_format_is_stable` and the Go test file in lockstep.
`GroupInfo` gains `chain_perms`.

Disclosure widening, to be recorded in `crypto-design.md` section 7: group
admins learn grantees' EndpointIds (`ResolveIdentity`), and every reader can
fetch the signed chain, which carries every recipient's key and the full kick
history. `GroupEpochs` is deliberately read-gated, not open to write-only
identities.

## 10. Sync protocol v2 and replica rules

ALPN `secret-bunker-sync/2`; v1 is not served after the upgrade (a migrated
group has no age wraps to send, and a v1 replica applying an empty `deks`
list would silently keep its last mirror forever; failing at ALPN is the
honest failure). Message names are kept where their meaning is; `Hello`
gains a body (a unit→struct change is fine on a new ALPN, pinned in
`sync::tests::wire_format_is_stable`):

```
{"Hello": {"have": [{"group": "prod", "have_epoch": 11, "have_hash": h'…'}, …]}}
{"Group": {"name": "prod", "group_uid": h'…', "head_epoch": 12, "head_hash": h'…',
           "epochs": [h'…', …],                       ; records with epoch > have_epoch, ascending, budgeted to SYNC_MAX_MSG
           "names": [{"endpoint_id": "1a98…", "identity_name": "ci"}, …]}}   ; display data only
{"FetchGroup": {"group": "prod", "have_epoch": 11}}
```

`acl` and `deks` are gone; `GroupSecrets`, `SecretEntry`, `SecretData`,
`Changed`, `ScopeChanged`, `FetchSecrets` are unchanged (`dek_version` is
`dek_gen`; the `(current_version, dek_version, nonce)` discriminator already
detects re-encryption, so a rotation makes the replica refetch the whole
group). `have` lists the groups with a mirrored head (a `group_epoch` row);
a pinned-but-dropped group is listed with `have_epoch: 0` and `have_hash:
0^32` and receives the whole chain. The server ships records after
`have_epoch` only if its own record at `have_epoch` hashes to `have_hash`;
otherwise it ships the whole chain from genesis and the replica applies P1/P4.
Repeated `Group` messages for one name append to `epochs`; the scalar fields
must be identical or the state is rejected.

**Replica apply**, per group, one transaction, replacing rules 1–3 of
`apply_group_sync`:

- P1 Pins. `group_pin` is written on the first accepted genesis and updated on
  every accepted head; it survives `drop_group_local` (which drops the mirror
  only). A whole chain received for a pinned group must contain the pinned
  genesis at epoch 1 and the pinned `head_hash` at `head_epoch`; the seen
  sets are rebuilt from it before newer records are verified. A `Group` whose
  `group_uid` differs from the pin for that name, or whose chain does not pass
  through the pinned head, is a fork: reject, keep the mirror, audit
  `sync-apply` outcome `rejected`, record `SyncStatus.rejected[group] =
  {epoch, reason, at, their_head}`, emit `ReplicaEvent::EpochRejected{group:
  String, epoch: u64, reason: String, their_head: Option<(u64, [u8; 32])>}`,
  and back off that group (1 s doubling to 60 s) until the next
  `Changed`/resync. Every accepted head emits
  `ReplicaEvent::HeadAccepted{group, epoch, hash}` after commit; a rejection
  clears, with `ReplicaEvent::ChainAccepted{group}`, on the next accepted
  head. `Replica::pins() -> Vec<GroupPin>` exposes the table.
- P2 Verify every received record with E/C/R/A/G against its predecessor
  (local head or the just-verified record). Genesis admission for a name with
  no pin (D14): if `expect_genesis[name]` is configured, the hash must equal
  it; otherwise, if `expect_keys` is configured, the record's `authority`
  (any of the configured list), `backup` and `mode` must match (admitted,
  pinned, audited `sync-genesis-keys`); otherwise the genesis is rejected
  (`unpinned-genesis`) unless `--tofu` is set (admitted, audited
  `sync-genesis-tofu`). Configuration: `ReplicaBuilder::expect_keys(
  authorities: Vec<id>, backup, mode)`, `ReplicaBuilder::expect_genesis(name →
  hash)`, `ReplicaBuilder::tofu(bool)`; flags `--expect-authority-id`
  (repeatable), `--expect-backup-id`, `--expect-mode`, `--expect-genesis
  name=hash`, `--tofu`; chart values `bunker.expectAuthorityId` (list),
  `bunker.expectBackupId`, `bunker.expectMode`, `bunker.expectGenesis`,
  `bunker.tofu` (default `false`).
- P3 Own id must be among the head's wraps; otherwise the group has been
  revoked for this replica: drop the mirror locally (pin kept).
- P4 Derive the DEK from the own wrap and check `dek_commit` before touching
  anything; on mismatch reject the state and keep the previous generation.
  Heads are monotone: a `head_epoch` below the local pin is a rewind and is
  rejected (D9). The operator resets a pin with `db reset-pin --db
  mirror.sqlite --group g --genesis <hash>` (audited `pin-reset`) or
  `Replica::reset_group(group, expected_genesis)`, both new API.
- P5 The mirrored ACL is the verified head's ACL; names come from `names`,
  defaulting to `hex[..8]`; `service_admin` pinned to 0 as today. (A removed
  identity leaves every head in the same transaction that deregisters it,
  6.3, so no separate deny list is needed.)
- P6 The undecryptable-fetch guard in `replica.rs` (today keyed on
  `state.deks`) becomes `secret.dek_version == head.dek_gen`; a fetched
  version under any other generation is filtered and the group re-run once,
  as today.

**Transitional read path.** `ReplicaInner` holds both `age_identity`
(transitional) and the Ed25519 scalar; `Replica::get` and the shared
`read_secret` dispatch on whether the group has a head record and use the age
path (`agebridge` + local `dek_wrap` rows) otherwise, so a standalone replica
serves its last mirror across the upgrade; the age field, `agebridge` and the
rows go in v4.

**The k8s operator.** Its mirror is an `emptyDir`, so pins must live outside
it: `operator/src/events.rs` writes the whole `Replica::pins()` table to an
operator-owned Secret (`<release>-bunker-pins`) on every `HeadAccepted`, on a
`Lagged` broadcast, and on a timer (RBAC already allows secrets
create/patch), publishing `Ready=False/PinsNotPersisted` on affected
`BunkerSecret`s while a patch fails; it loads the Secret into
`ReplicaBuilder::pins(…)` at boot; the stored pin wins over chart values; a
one-shot chart value `bunker.resetPins: {prod: <genesis_hash>}` makes the
operator call `reset_group`, rewrite the Secret row, record the applied reset
in the Secret so it is not re-applied on later boots, and audit `pin-reset`;
editing the Secret by hand is the documented break-glass path. The exhaustive
match gains `EpochRejected` (warn log; counter
`bunker_epoch_rejected_total{group}`), `HeadAccepted` and `ChainAccepted`;
`apply_bunker_secret` reads `SyncStatus.rejected` and publishes
`Ready=False/ChainRejected` on affected `BunkerSecret`s while a rejection is
present (still serving the last verified mirror), clearing on
`ChainAccepted`. A rotation re-encrypts every secret of a group, so every
`BunkerSecret` on it receives `SecretChanged` at once; `reconcile.rs` already
compares content hashes before patching, so this is a no-op storm (tested).
Still exactly one mounted key.

## 11. CLI and TUI

A new `src/epoch.rs` holds the crypto and the record (encode/parse/hash/sign/
verify/digest, the `RandomSource` trait); `src/epochflow.rs` holds the
client-side flows used by both the CLI and the TUI, needing only the caller's
iroh key and a **client pin file** (`$XDG_DATA_HOME/secret-bunker-iroh/pins/
<server EndpointId>.json`: per group name `{group_uid, genesis_hash,
head_epoch, head_hash}`). On first sight of a group the CLI prints the genesis
hash and asks for confirmation unless `--tofu` or `client epoch pin --group g
--genesis <hash>` was given; `client epoch reset-pin --group g [--genesis
<hash>]` handles the restore case; a pin that disagrees with the server is
reported as a fork and the flow aborts.

- `client kick --group g --identity bob` (6.1), `client rotate --group g`
  (6.1 without the ACL change), `client grant --group g --identity carol
  --perms rwa [--endpoint-id <hex> | --expect-id <hex>]` (6.2; losing read →
  6.1; own read → refused, G5), `client epoch repair --group g` (a `rewrap`
  with unchanged recipients), `client epoch log|status --group g` (6.5),
  `client epoch export|submit` (6.4), `client freeze-group --group g
  [--unfreeze]`. Flows print a progress line (`re-encrypting 143/200 ·
  12 MiB · attempt 1`); `EpochConflict` is retried three times per 6.1 step 8
  and then exits 2, the existing CAS-conflict code. `client create-group`
  prints the genesis hash.
- `init --db … --operational-key operational.key --backup-id <hex> [--mode A]
  [--admin-id <hex>]` for a fresh v3 database: records `operational_ed25519`,
  `backup_ed25519`, `epoch_mode`, `schema_version = 3`, `epochs_migrated = 1`,
  `role = authoritative` and the first service admin; no age material. A bare
  `init` auto-generates `backup.key` locally with today's "move it offline"
  warning (`key export backup`). `KeyRole::Operational`/`Backup` become
  Ed25519 files `operational.key`/`backup.key` (`is_age()` removed); the
  archived age keys are ordinary files the operator keeps for snapshots.
- `recovery author` (offline, 6.4); `db migrate-epochs` (section 12); `db
  remove-identity --db --name [--operational-key]` (offline removal: on a
  migrated database it authors the same authority carries as `RemoveIdentity`
  and sets `needs_rotation`, and is refused unless the key given is the head's
  authority for every affected group); `db set-service-admin`, `db
  set-backup`, `db set-mode` (audited defaults); `db submit-recovery` (6.4);
  `db drop-group` (replica mirror only) and `db reset-pin` (replica). `db
  grant` and `recover` are removed.
- TUI: ACL pane `x` and `r`-off → 6.1 (rotate); `r`-on, or `a`-on on an
  entry without `r` → `rewrap`; `a`-on on a reader, `w` either way, `a`-off →
  `carry`; groups pane `R` → rotate; a new `L` key opens the epoch log. The
  groups pane shows `epoch 12 · gen 9 · alice · 2h`, `!` when
  `needs_rotation`, `*` when frozen. Keys the caller cannot author
  (`chain_perms`) are greyed out; a service admin without an explicit row is
  offered the server-side revocation (legacy shrink `Grant`) for `x`/`r`-off
  and nothing for additive changes. Consecutive edits are batched into one
  record where possible.

## 12. Migration

`secret-bunker-iroh db migrate-epochs --db bunker.sqlite --operational-age
operational.age --operational-key operational.key --backup-id <hex> [--mode A]
[--service-admins-as-group-admins]`, run once with the service stopped, after
a backup of the SQLite file (`--mode E` is refused while mode E is unbuilt):

1. Validate every registered EndpointId with `decode_point` and against the
   configured pinned keys, and every group name against E1; refuse to migrate
   while any fails, listing them. An invalid identity is removed with `db
   remove-identity`; a group whose name exceeds 255 bytes cannot be migrated
   and is recreated under a shorter name before migrating (no rename exists).
   Record `operational_ed25519`, `backup_ed25519`, `epoch_mode` in `meta`.
2. Per group, in one transaction: unwrap every retained DEK version with the
   age operational key; decrypt every retained `secret_version`; draw `M`;
   `dek_gen = MAX(group_dek.version) + 1`; re-encrypt every version under it
   (fresh nonces); build `genesis` with `acl = group_acl` after applying G1
   (`a ⇒ r`, audited `migrate-admin-read`) and the optional service-admin
   rows, `mode`, `authority`, `backup`, the wrap set, proof, `reencrypted`
   over the new set; sign with the operational key; insert `group_epoch`
   (`installed_digest = reencrypted`), the `group_dek` row, update every
   version, set `group_uid`/`head_epoch`, delete the group's `dek_wrap` rows
   and retired `group_dek` rows; audit `epoch-genesis`; print the group's
   genesis hash for operators who want the strict per-name pin.
3. Set `epochs_migrated = 1`; `VACUUM` after all per-group transactions have
   committed. A v3 `serve` refuses an authoritative database without the
   flag; `backfill_reader_wraps` is deleted; `read_secret` opens the head
   record's authority wrap; `ReplicaInner` gains the Ed25519 scalar alongside
   `age_identity` (section 10).
4. Deploy, in one maintenance window: upgrade the k8s operator image and any
   standalone replicas with `bunker.expect*` set (they fail ALPN against the
   old server; a standalone replica serves its last mirror through the
   transitional read path, the operator's `BunkerSecret`s report
   `Ready=False/AwaitingSync` until the server is migrated because its mirror
   is empty at boot); migrate; start the v3 server; replicas resync from
   genesis, admit it by keys (D14) and pin it.
5. The age operational and backup keys are archived: they open pre-migration
   snapshots and nothing else.

Pre-existing identities are trusted as registered; D1 makes a proof of
possession unnecessary.

## 13. Testing

- **Unit (`epoch.rs`).** `decode_point` against every non-canonical encoding
  class, the eight torsion points added to a valid key, small-order points,
  the identity. ElGamal round trip for a reader, the operational key, the
  backup key. Proof prove/verify; a negative matrix keyed to verifier rules:
  torsion in one `c0_i`, in one `c_i`, in an `A_i`; `r_i = 0`; two equal
  `c0_i`; `c0_i` with `KDF(c0_i)` equal to a seen commit; swapped wraps; wrong
  `e`/`s_i`; non-canonical scalars; duplicate id; unsorted; hidden and
  missing recipient; proof transplanted to another `group_uid`/`dek_commit`/
  `prev`/`epoch`; `Δ`-shift of every `c_i`; commit mismatch (reader step 5);
  bad signature; every A/C/G/R rule with a minimal record that fails only it
  (A2 on a replica-fed record, A5 for rotate and for recovery with and
  without a backup change, G5, G6 revived vs first-time ids and the recovery
  exemption). Randomness: the same group rewrapped with the same fixed
  `RandomSource` bytes → existing recipients' `c0` repeat → R5 refuses; two
  groups rotated with the `m` hedge disabled and the same bytes → R5 refuses
  via the backup key's repeated `c0`. Related-key recipients (`−A`, `A_u +
  A_v`, `2A`) as a property test: the shared-`r` formulas return garbage.
  Record encode → parse → same bytes; strict parser rejects trailing data;
  digest vectors including the empty set. Fuzz: parser and verifier never
  panic. Golden vectors from fixed seeds (`[7u8; 32]`, `[8u8; 32]`,
  `[9u8; 32]`, fixed `group_uid`, fixed hedge bytes via `RandomSource`): pin
  `c0_i`, `c_i`, `DEK`, `dek_commit`, `e`, `s_i`, the body, `sig`, `hash` —
  the shared fixture for the Go implementation.
- **Store.** v2→v3 on inline-built v1/v2 schemas (as the existing migration
  tests do), authoritative and replica roles; migration yields a verifiable
  genesis per group whose `dek_gen` equals every `secret_version.dek_version`,
  with no `dek_wrap` rows; stage keys, caps, idle TTL, replacement,
  `epoch_stage_open` with its snapshot; all-or-nothing apply; `audit_in`;
  `secure_delete` set on open.
- **Server.** `SubmitEpoch` happy path; `EpochConflict`; the write fence;
  uncovered rows → `StaleVersions`, an empty stage against a non-empty group
  lists every row; delete-then-recreate before the fence installs nothing
  stale; a stage whose wraps differ from the record → `Failed`; deliverer ≠
  author → `Denied`; authority as wire author → `Denied`; existence oracle on
  `SubmitEpoch`, `OpenStage`, `StageVersions`, `FreezeGroup` → `Denied`; a
  reader, a write-only identity and a stale-recovery carrier cannot
  `OpenStage`; S5 rejections (copied commit over a different `M` on a rewrap,
  undecryptable row, changed plaintext, repeated nonce) apply nothing and
  cache nothing; S6; S9 bursts and the rotate limit, not applied to the
  authority; S10 refuses `Put`/`Delete`/additive legacy `Grant`/wire
  `SubmitEpoch`, lands the revocation carry and the shrink `Grant`, keeps the
  freeze across an accepted recovery; legacy `Grant`: same bits → `Ok`,
  strict subset → carry (+ flagged + rotate lands), add → `Failed`, last-admin
  guard; two `RemoveIdentity` within 30 s on identities sharing a group both
  land; `RemoveIdentity` → carry per group under the lock, `Put` fenced,
  rotate lands afterwards, resumes after a restart with the flag set,
  quarantines an unreadable row, is deferred while frozen and while the key
  is unavailable; freeze, `RemoveIdentity` of a reader, export, recovery
  `--rotate` lands and clears the flag; recovery carried and staged by a
  non-admin, reviving two ids and removing the rogue in one record on a
  frozen group; recovery replacing `authority` with the server running on two
  keys (Get/Put before, during, after) and `CreateGroup` during the window
  using the new key; a lost operational key (`--previous-operational-id`) and
  `db submit-recovery`; recovery replacing `backup` lands; G2 on admin
  records, orphaning allowed on authority records; A5 refuses a self-kicking
  rotate; `AddIdentity` of a pinned key → `Failed`.
- **End-to-end (`tests/e2e.rs`, in-process iroh).** (1) Admin kicks a reader
  client-side: the reader's next `Get` is `Denied`, its stashed DEK opens
  neither re-encrypted versions nor later writes, the replica converges and
  denies it. (2) Add reader by `--endpoint-id`: the replica sees it without a
  refetch. (3) Hostile authoritative node: a test bunker whose store gains an
  ACL row with no record, one that serves an authority-signed additive
  record, one that serves a rewound chain, one that re-presents a known name
  under a new genesis to a pinned replica (rejected), to a replica with
  `expect_genesis` for the name (rejected), to a replica with matching
  `expect_keys` only (admitted and audited — the D14 residual), and to a
  replica with wrong keys and no `--tofu` (rejected) → mirror kept where
  rejected, `EpochRejected` emitted and cleared on `ChainAccepted`. (4) A
  `MAX_VALUE`-sized secret through kick, staging, export paging and sync. (5)
  Migration under a live standalone replica: no serving gap. (6) Operator
  `reconcile_apply`: a rotation produces zero Secret patches; the pins Secret
  advances on a `carry` that changes no secret; pins survive a pod restart.
  (7) Recovery bundle for an orphaned group, with `--rotate`, against a rogue
  admin held off by `FreezeGroup`, the freeze surviving the recovery until
  the explicit unfreeze.

## 14. Documentation

`design/crypto-design.md` sections 2 (threat model), 3 (keys, derived
recipients → ElGamal), 4 (encryption at rest: epochs replace wraps), 7
(authorization: chain rules, service admin, disclosure widening), 8
(lifecycle: rotation, recovery, revocation), 9 (disaster recovery → recovery
records), 11 (primitives), 12 (non-goals); a new `docs/epochs.md` with the
record layout, verifier rules, reply mapping and golden vectors;
`docs/protocol.md` (new variants, `MAX_VALUE`, read bound); `docs/sync-protocol.md`
(v2); README (kick/rotate/epoch log; key generation; `init`; migration);
`operator/README.md` (pins Secret, `expect*`/`tofu`/`resetPins` values,
`ChainRejected`, `PinsNotPersisted`). The Go client's README notes which
requests it can and cannot make against a v3 bunker.

## 15. Explicitly out of scope / unchanged

- Mode E implementation (7.2), signed puts, signed delete tombstones, a
  signing Go client.
- k-of-n co-signatures for admin removal (a future record kind).
- Retention policy for secret history (D6 makes rotation cost proportional to
  retained ciphertext).
- Gossip or cross-replica head comparison (equivocation stays detectable only
  out of band; `EpochRejected` carries both heads to help).
- Hardware-backed keys, forward secrecy, replica chaining, write proxying,
  timing-uniform denials: unchanged non-goals.
- The client data path (`Get`/`Put`/`Delete`/`List`), the TUI's data panes,
  write-only identities and service-admin reads in mode A: byte-identical
  apart from `MAX_VALUE` and the rotation/needs-rotation write fences.

## 16. Delivery phases

| Phase | Ships | Compatibility |
|---|---|---|
| 0 | `src/epoch.rs`: points, ElGamal, proof, KDF, record encode/parse/hash/sign, verifier, digest, `RandomSource`; golden vectors. No schema or protocol change. | none |
| 1 | Schema v3, `init`, `db migrate-epochs`, Ed25519 operational/backup keys and the two-key `serve` (including the lost-key form), server-authored `genesis`/revocations for `CreateGroup`/`RemoveIdentity`/legacy `Grant` with the rotation worker, `Get`/`Put` via the head record, `MAX_VALUE` and read bounds, every new request of section 9, two-phase apply, DEK cache; `epochflow` with `grant`/`rotate`/`kick`/`repair`/`epoch log|status|export|submit`, client pins, `recovery author`, `db submit-recovery`/`reset-pin`/`remove-identity`/`set-service-admin`/`set-backup`/`set-mode`; `db grant` and `recover` removed. | Go data path unchanged |
| 2 | `secret-bunker-sync/2`, replica verification, pins, transitional read path, `EpochRejected`/`HeadAccepted`/`ChainAccepted`, `db drop-group`, operator pins Secret, chart values, `ChainRejected`/`PinsNotPersisted`. | one maintenance window with phase 1 |
| 3 | TUI flows and docs. | additive |

Phases 1 and 2 are one release, so that grants, rotations and recoveries all
work from the first migrated day. Mode E is a later spec.

## 17. Success criteria

- A group admin with `rwa` kicks a reader and rolls the DEK from their own
  machine; the server holds no age key; the reader is denied at the
  authoritative node and at every replica; every retained version is under
  the new generation.
- The server, every replica and `client epoch log` reject a record in which
  any listed recipient would not receive the same DEK, without holding any
  key; the mode-A server additionally rejects one whose DEK is not the
  committed one; a record with a hidden or missing recipient is rejected
  likewise.
- `client epoch log` names, verifiably, the author of the last rotation and
  of every membership change.
- A compromised authoritative node cannot make a pinned replica accept a new
  reader, a raised permission, a changed backup key, or a re-genesis.
- An orphaned group, and a group hijacked by an online rogue admin, are
  recovered by a backup-signed record submitted over the wire, with the
  service running; a lost operational key is recovered the same way.
- The Go client's `Get`/`Put`/`List`/`Delete` and the k8s operator work
  unchanged against a migrated bunker after upgrading the operator image.

## 18. Rule summary by verifier

| Rule | Server | Replica | Client / auditor |
|---|---|---|---|
| E1–E4 layout, canonical points, torsion-free, distinct `c0` | ✓ | ✓ | ✓ |
| C1–C4 genesis/pin, continuity, signature, immutable keys | ✓ | ✓ (+P1) | ✓ (pin file) |
| R1–R6 exact recipients, generation, proof, carry subset, freshness, no silent removal | ✓ | ✓ | ✓ (R2/R5 over fetched records) |
| A1–A5 authorship by kind; rotator is a recipient | ✓ | ✓ | ✓ |
| G1–G7 admin⇒read, last admin, self rules, revival delta, mode-E write⇒read | ✓ | ✓ | ✓ (G6 over fetched records) |
| S1–S10 caller, registry, CAS, coverage, own wrap and trial decryption, no-op, pinned-id guard, lock discipline, rate, freeze | ✓ | — | — |
| P1–P6 pins and events, configured genesis trust, own wrap, monotone heads, ACL from head, generation filter | — | ✓ | — |

## 19. Open questions for the user

Each carries the recommendation the design assumes; changing an answer
changes the spec, not the architecture.

1. **Deployment mode.** Confirm mode A (server keeps a dedicated Ed25519
   operational key as a recipient; `Get`/`Put`, write-only identities, Go
   client and service-admin reads unchanged) as the only built mode, with
   mode E specified but deferred. *Assumed: yes.*
2. **Go client.** Does it call `Grant` or `RotateDek`, or only data
   operations? On a migrated bunker additive `Grant` and `RotateDek` answer
   `Failed`; the Rust CLI/TUI perform them client-side. *Assumed: data only.*
3. **Admin kicks admin.** Allow (loud, attributable, reversible by a surviving
   admin, a server-side revocation, or the backup key) rather than forbid or
   require co-signatures. *Assumed: allow.*
4. **Admin implies read.** Accept that `a` without `r` becomes invalid and
   that migration adds `r` to such rows (audited). *Assumed: yes.*
5. **History on rotation.** (a) Re-encrypt every retained version (one live
   generation; cost ∝ retained ciphertext) — *assumed*; (b) re-encrypt current
   versions and delete history at each rotation; (c) leave history cold under
   retired generations (readable by the backup key only, and by a kicked key
   from a stolen copy).
6. **Backup key ceremony.** Generate a fresh offline Ed25519 backup key at
   migration; the age backup key is archived for pre-migration snapshots.
   *Assumed: yes.*
7. **Recovery requires the backup key.** Today an orphaned group is rescued
   with `db grant` and database access; in this design only a backup-signed
   recovery can add an admin to an orphaned group (otherwise a compromised
   node could orphan-then-adopt). *Assumed: acceptable.*
8. **Write fences.** Accept that `Put`/`Delete` on a group are refused while
   an admin's rotation stage is open (minutes) and while a server-side
   revocation's rotate is pending (seconds, resumed across restarts), in
   exchange for rotations that always converge, "always wins" removals, and no
   whole-group re-encryption under the lock. *Assumed: yes.*
9. **Replica on an authoritative restore.** Reject the rewound chain and
   require an explicit per-replica pin reset. *Assumed: yes.*
10. **Signed puts.** Defer to mode E; mode A relies on S5 plaintext equality
    during rotation. *Assumed: defer.*
11. **Migration downtime.** One maintenance window: operator/replica upgrade,
    `db migrate-epochs` with the service stopped (needing the age operational
    key plus the new keys), v3 server start; `BunkerSecret`s report not-Ready
    inside the window. *Assumed: acceptable.*
12. **Disclosure widening.** Group admins learn grantees' EndpointIds; every
    reader can fetch the chain (all recipient keys, full kick history);
    write-only identities cannot. *Assumed: acceptable.*
13. **Legacy `Grant` shrink path.** Keep server-side revocations requested
    through the old `Grant` (audit names the requester; the chain names the
    authority) as a rung of the escalation ladder, or make all ACL changes
    client-signed? *Assumed: keep.*
14. **Service admins and additive changes.** Service admins lose implicit
    grant/rotate on groups where they hold no explicit admin row; migration
    can add such rows for every current service admin
    (`--service-admins-as-group-admins`). *Assumed: run migration with that
    flag.*
15. **`MAX_VALUE`.** Cap `Put.value` at `MAX_MSG − 4 KiB` (a 4 KiB reduction
    of today's effective maximum) so that ciphertext-carrying envelopes have
    headroom. *Assumed: acceptable.*
16. **Replica genesis trust.** Admit an unlisted genesis when its keys match
    the replica's configured keys (D14), with per-name hashes as an optional
    stricter pin — rather than requiring a hash for every group (every
    `CreateGroup` becomes a chart change) or TOFU by default. *Assumed: keyed
    admission.*
