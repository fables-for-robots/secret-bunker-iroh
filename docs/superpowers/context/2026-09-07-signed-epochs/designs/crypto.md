# Cryptographic specification: verifiable multi-recipient DEK wrapping for secret-bunker-iroh

Angle: cryptographer. This document fixes the primitives, encodings, algorithms and
security argument for the "epoch record" of the brief, and answers section 5 of the
brief from that vantage point. Everything below is stated against the code as it exists
today (`src/crypto.rs`, `src/agebridge.rs`, `src/store.rs`, `src/server.rs`,
`src/sync.rs`) and against the pinned crates (`ed25519-dalek 3.0.0` re-exporting
`curve25519-dalek 5.0.0`, `sha2 0.10`, `hkdf 0.12` already in the lockfile via age,
`rand 0.8`, `ciborium 0.2`).

Full file: `/private/tmp/claude-502/-Users-dragan-fables-for-robots-secret-bunker-iroh/0c07f4bd-a1ff-4066-aa31-2b8de0a5ded7/scratchpad/designs/crypto.md`

## 0. Decisions in one screen

| Question | Decision |
|---|---|
| Curve / group | Ed25519 Edwards form directly; **no Ristretto, no Montgomery**. Every decoded point must be canonically encoded and torsion-free (exact `ℓ·P = O` check). Any torsion is treated as an attack and rejected, never "cleared". |
| Wrap | Multi-recipient ElGamal with one shared ephemeral scalar `r`: `E = r·B`, `c_i = M + r·A_i`, `M = m·B` random. |
| Proof | **One batched Schnorr proof with a shared witness `r`** (generalised Chaum-Pedersen over `n` bases), 64 bytes total, `e`-form (verifier recomputes the commitments). Not `n` separate DLEQs. |
| Fiat-Shamir | SHA-512 over a fixed-layout transcript that hashes the **entire statement** (domain, group id, DEK generation, commitment, every `A_i`, every `c_i`, `E`) and then the commitments; reduced with `Scalar::from_bytes_mod_order_wide`. |
| Key derivation | `HKDF-SHA256(ikm = M.compress(), salt = "secret-bunker-epoch/1 dek", info = group_id ‖ u64be(dek_version))` → 64 bytes: `DEK = okm[0..32]`, `dek_commit = okm[32..64]`. |
| Signature | Pure Ed25519 (RFC 8032 §5.1) by the author's endpoint key over `"secret-bunker-epoch/1 sig" ‖ 0x00 ‖ body_bytes`, verified with `verify_strict`. The signed object is the **exact CBOR bytes** received (no re-canonicalisation on the verifier side). |
| Record identity | `epoch_hash = SHA-256("secret-bunker-epoch/1 hash" ‖ 0x00 ‖ body_bytes ‖ sig)`. |
| Pinned recipients | Ed25519 keys (the offline backup key becomes an Ed25519 keypair; the server, if a recipient, uses a dedicated Ed25519 "operational" key, not its endpoint key). An X25519-compat mode for keeping the existing age keys is specified as an option. |

## 1. Group, encodings, decoding rules

Notation. `p = 2^255 − 19`, `E` the twisted Edwards curve of Ed25519, `B` the RFC 8032
basepoint, `ℓ = 2^252 + 27742317777372353535851937790883648493` the order of `B`,
cofactor 8, `G = ⟨B⟩` the prime-order subgroup, `O` the identity, `E[8]` the 8-torsion
subgroup (`curve25519_dalek::constants::EIGHT_TORSION`, public). Ed25519 public keys are
`A = a·B` with `a` the clamped SHA-512 scalar; `a ≡ 0 (mod 8)`, so honestly generated
keys are always in `G`.

**Point encoding.** 32 bytes, RFC 8032 compressed form: little-endian `y`, sign of `x` in
bit 255. **Scalar encoding.** 32 bytes little-endian, canonical (`< ℓ`).

**`decode_point(bytes: [u8;32]) -> Option<EdwardsPoint>`** — the only way any point
enters the system:

1. `P = CompressedEdwardsY(bytes).decompress()?` (rejects `y` not on the curve).
2. `P.compress().as_bytes() == bytes` else `None`. This is required because
   `decompress` masks bit 255 and does not check `y < p`: the 19 encodings with
   `y ∈ [p, 2^255)` and the two "`x = 0` with sign bit set" encodings decode to valid
   points. Verified against `curve25519-dalek 5.0.0` `decompress::step_1/step_2`.
3. `P.is_torsion_free()` else `None`. This is the exact check `ℓ·P == O` (one full
   scalar multiplication; inputs are public so timing is irrelevant). It rejects every
   point with an `E[8]` component, including all small-order points and the identity's
   torsion cousins. The identity itself passes step 3 and is rejected where it matters
   (section 8).

**`decode_scalar(bytes) -> Option<Scalar>`** = `Scalar::from_canonical_bytes(bytes)`
(`CtOption`, `None` for `≥ ℓ`). Non-canonical `e` or `s` are rejected outright; they are
never reduced.

**Endpoint ids** inside signed material are the raw 32 bytes of the Ed25519 public key
(the wire protocol's 64-hex form is the text rendering of the same bytes). Every endpoint
id that appears in a record (ACL entries, pinned, wraps, author) goes through
`decode_point`, so an `EndpointId` that iroh would accept but that carries torsion
(`VerifyingKey::from_bytes` does not check torsion) is unusable as a recipient or author.

**Version traps (verified).** `curve25519-dalek 5` is bound to `digest 0.11` and
`rand_core 0.10`; the project pins `sha2 0.10` and `rand 0.8`. Therefore do **not** use
`Scalar::from_hash`, `Scalar::random`, or `EdwardsPoint::hash_to_curve`; use
`Scalar::from_bytes_mod_order_wide(&[u8;64])` fed with `sha2 0.10` SHA-512 output or with
64 bytes from `rand::rngs::OsRng`. This also keeps the proof independent of any digest
trait plumbing. `curve25519-dalek` must become a direct dependency (default features:
`alloc`, `precomputed-tables`, `zeroize`).

## 2. Objects and byte layouts

Three objects: the **wrap set** (the cryptographic core, carried inside the body), the
**epoch body** (everything the author signs), and the **epoch record** (body bytes plus
signature, the unit of storage and sync).

### 2.1 Epoch body (CBOR map; producer emits fields in this order)

```
EpochBody = {
  "v":           1,                       ; format version, uint
  "group_id":    bstr(32),                ; random, fixed for the life of the group (section 2.4)
  "epoch":       uint,                    ; 1-based, = previous epoch + 1
  "prev":        bstr(32),                ; epoch_hash of the previous record; 32 zero bytes for epoch 1
  "acl":         [ [bstr(32) endpoint_id, uint perms], ... ],   ; full ACL after this epoch, sorted
  "pinned":      [ bstr(32) endpoint_id, ... ],                  ; mandatory recipients, sorted
  "dek_version": uint,                    ; DEK generation; bumps iff M changes
  "dek_commit":  bstr(32),                ; KDF commitment to M for this (group_id, dek_version)
  "eph":         bstr(32),                ; E = r·B
  "wraps":       [ [bstr(32) endpoint_id, bstr(32) c_i], ... ], ; sorted by endpoint_id, strictly increasing
  "proof":       [ bstr(32) e, bstr(32) s ],
  "reencrypted": bstr(32),                ; digest of the re-encrypted version set (section 12.3); zero bytes if dek_version unchanged
  "author":      bstr(32),                ; endpoint id of the signer
  "at":          uint                     ; unix seconds, informational
}
```

Encoding rules for producers (RFC 8949 §4.2.1 deterministic encoding): shortest integer
forms, definite lengths only, byte strings for all 32-byte fields, no floats, no tags.
Verifiers **decode with `deny_unknown_fields`** and reject trailing bytes, but never
re-encode: the signature and the hash are over the bytes received. Two encoders that
differ in map-key order would produce two different records with the same meaning; that is
harmless (different `epoch_hash`), and the rule keeps the Go client from needing a
byte-exact CBOR canonicaliser.

Sorting is bytewise on the 32-byte endpoint id, ascending, strictly increasing (a repeated
id is a decode error, not "last wins"). Identity *names* are deliberately not in the
body: the cryptographic state is about keys; names stay transport metadata
(`AclEntry.identity_name`) exactly as today.

### 2.2 Epoch record

```
EpochRecord = { "body": bstr(EpochBody bytes), "sig": bstr(64) }
epoch_hash  = SHA-256( "secret-bunker-epoch/1 hash" ‖ 0x00 ‖ body ‖ sig )
```

`sig` is fixed-length and last, so the hash input is unambiguous without length prefixes.
Including `sig` makes the identity of an epoch the identity of the stored bytes.

Size: ≈ 300 bytes fixed + ≈ 75 bytes per recipient (32 ACL + 32 wrap + CBOR framing) +
64 signature. 1,000 recipients ≈ 75 KB, far under the 4 MiB / 8 MiB frame caps.

### 2.3 Wrap set (the statement)

The tuple `(group_id, dek_version, dek_commit, E, [(A_i, c_i)]_{i=0..n−1}, (e, s))` with the
list in sorted order. Index 0 (smallest endpoint id) is the **anchor**. `n ≥ 1` always
(pinned recipients guarantee it). The recipient set must equal
`readers(acl) ∪ pinned` **exactly** — no extra recipient (an unlisted recipient would be a
hidden reader), no missing one.

### 2.4 `group_id`

32 random bytes drawn by whoever mints epoch 1 (`OsRng`). It is what binds the KDF and
the proof transcript to a group. It is *not* the hash of epoch 1 (that would be circular:
epoch 1's wrap set needs the id before the record exists). The chain's self-certifying
identity `hash(epoch 1)` still exists and is what replicas pin; `group_id` must be
identical in every epoch of a chain (verifier rule).

## 3. Key derivation and commitment

```
M_bytes = M.compress()                                  ; 32 bytes, canonical
prk     = HKDF-Extract(salt = "secret-bunker-epoch/1 dek", ikm = M_bytes)      ; HMAC-SHA256
okm     = HKDF-Expand(prk, info = group_id ‖ u64be(dek_version), L = 64)
DEK        = okm[0..32]        ; the ChaCha20-Poly1305 key, exactly today's crypto::Dek
dek_commit = okm[32..64]       ; public
```

`hkdf 0.12` + `sha2 0.10` are already in the lockfile (age uses them); add `hkdf` as a
direct dependency. Properties: `DEK` and `dek_commit` are independent PRF outputs, so
publishing `dek_commit` reveals nothing about `DEK`; the same `M` under a different
`(group_id, dek_version)` yields unrelated keys, so a wrap set can never be transplanted
between groups or generations even if the proof check were skipped; `dek_commit` is
collision-resistant in `M` (HMAC-SHA256 over a uniformly random group element).

The secret AAD (`crypto::secret_aad(group, name, version, dek_version)`) is unchanged.
`dek_version` keeps its current meaning (the generation a ciphertext was produced under);
what changes is only where the DEK comes from.

## 4. Wrapping (author side)

Inputs: the recipient public keys `A_0 < … < A_{n−1}` (already decoded per section 1),
`group_id`, `dek_version`, and either a fresh `M` (rotation / kick) or the current `M`
(add-reader, carry-over of the generation).

```
1. if new generation:  m ← from_bytes_mod_order_wide(OsRng 64 bytes); M = m·B (basepoint table)
                       ; M is torsion-free by construction; m is discarded immediately
                       ; (only M matters; m is never used again)
2. r ← from_bytes_mod_order_wide(OsRng 64 bytes); if r == 0 retry           ; MUST be fresh per wrap set
3. E = r·B
4. for each i: c_i = M + r·A_i                       ; constant-time r·A_i
5. (DEK, dek_commit) = KDF(M, group_id, dek_version)
6. proof = prove(r, statement)                      ; section 5
7. zeroize r, m, M, DEK when no longer needed
```

`r` is never stored. **Rule R1: `r` MUST be fresh for every wrap set.** Reusing `r` across
two generations with the same recipient leaks `M_new − M_old` from `c_i' − c_i`; a kicked
reader who knows `M_old` then recovers `M_new` and the rotation is void. Reusing `r` with
the *same* `M` for a superset of recipients is harmless (that is exactly the BBS
reproducibility property, section 9.4) but is not needed: a fresh `r` costs `n + 1`
scalar multiplications, and the author of an add-reader epoch generally does not hold the
previous author's `r` anyway.

## 5. The proof

### 5.1 Statement

With `D_i = A_i − A_0` and `C_i = c_i − c_0` for `i = 1..n−1`:

  there exists `r` such that `E = r·B` and, for every `i ≥ 1`, `C_i = r·D_i`.

Equivalently `c_i − r·A_i = c_0 − r·A_0` for all `i`: every recipient's decryption is the
same point `M := c_0 − r·A_0`. Nothing is claimed about `M` itself (section 9.3). All
points are in `G` (section 1), so the statement lives in a prime-order group and the
Schnorr/Chaum-Pedersen analysis applies verbatim.

### 5.2 Per-recipient DLEQs vs. one batched response — decision

Two ways to prove the `n − 1` equalities:

- **Per-recipient**: `n − 1` independent Chaum-Pedersen proofs `(e_i, s_i)`, each over the
  pair `(B, E), (D_i, C_i)`. Size `64(n − 1)` bytes, `n − 1` hashes, `2(n − 1)`
  commitments; each proof separately extractable.
- **Batched, shared witness** (chosen): one nonce `k`, commitments `R_0 = k·B`,
  `R_i = k·D_i`, one challenge `e` over the whole transcript, one response
  `s = k + e·r`. Size **64 bytes for any `n`**.

Why batched is correct here and not merely smaller: the witness really is one scalar. The
statement is a conjunction of `n` discrete-log relations that *share* `r`; a Σ-protocol for
"AND of relations with the same witness" uses the same `(k, e, s)` for all of them, and
special soundness extracts one `r` satisfying all `n` equations at once from any two
accepting transcripts with equal commitments and distinct challenges
(`r = (s − s')/(e − e')`, identical for every equation because `s, e` are shared).
Per-recipient proofs would prove "there is *some* `r_i` for each `i`", which is weaker
exactly where it matters: nothing would tie `r_i` to `r_j`, and only the shared `E = r·B`
equation inside each proof restores the link. Batched is both stronger in statement and
`n×` cheaper in bytes. There is no verification-cost difference (the verifier computes
`n` commitments either way).

### 5.3 Transcript (Fiat-Shamir input), byte-exact

All fields are fixed-size, concatenated without separators. Points are 32-byte compressed
encodings, integers big-endian.

```
T = "secret-bunker-epoch/1 dleq" ‖ 0x00        ; 26 ASCII bytes + NUL
  ‖ group_id                                     ; 32
  ‖ u64be(dek_version)                           ; 8
  ‖ dek_commit                                   ; 32
  ‖ u64be(n)                                     ; 8
  ‖ E                                            ; 32
  ‖ A_0 ‖ c_0 ‖ A_1 ‖ c_1 ‖ … ‖ A_{n−1} ‖ c_{n−1} ; 64·n, sorted order
  ‖ R_0                                          ; 32
  ‖ R_1 ‖ … ‖ R_{n−1}                            ; 32·(n−1)
e = Scalar::from_bytes_mod_order_wide(SHA-512(T))
```

This is "strong" Fiat-Shamir: the full statement precedes the commitments, so a proof is
bound to exactly these bases, these ciphertexts, this group and this generation. `n` is
hashed explicitly so no prefix of one transcript is another transcript. `dek_commit` is in
the statement because it is part of what the wrap set publicly asserts. `epoch`, `prev`,
`acl`, `author` are deliberately **not** in the transcript: they belong to the signature's
scope, and keeping them out lets a plain ACL edit (no key material moving) carry a wrap set
verbatim into the next epoch.

### 5.4 Prove

```
k   = from_bytes_mod_order_wide( SHA-512( "secret-bunker-epoch/1 nonce" ‖ 0x00
                                          ‖ r_bytes ‖ SHA-512(T without the R's) ‖ OsRng 32 bytes ) )
      ; hedged deterministic nonce: unpredictable even if the RNG repeats, distinct per statement
R_0 = k·B                          ; basepoint table, constant time
R_i = k·D_i        (i = 1..n−1)    ; constant time
e   = H(T)         (5.3)
s   = k + e·r                      ; Scalar arithmetic (constant time)
proof = (e.to_bytes(), s.to_bytes())
zeroize k, r
```

For `n = 1` the transcript contains `R_0` only and the proof degenerates to a Schnorr
proof of knowledge of `r` for `E`: vacuous as a consistency statement but kept for a
single code path; it costs one scalar multiplication.

### 5.5 Verify

Preconditions (all from section 8): every point decoded via `decode_point`, `E ≠ O`,
wraps sorted strictly increasing, `n ≥ 1`, `e, s` canonical.

```
R_0' = s·B − e·E                    ; vartime_double_scalar_mul_basepoint(&(-e), &E, &s)
for i in 1..n:
    D_i = A_i − A_0 ; C_i = c_i − c_0
    R_i' = s·D_i − e·C_i            ; EdwardsPoint::vartime_multiscalar_mul([s, -e], [D_i, C_i])
e' = H(T with R_0', R_1', …)
accept iff e' == e                  ; plain equality (public data)
```

Variable-time arithmetic is correct here: every input is public. Cost: `2n + 1` torsion
checks (one `ℓ`-multiplication each) + `n` two-term multiscalar multiplications ≈
`3n` scalar multiplications ≈ 100–150 µs × `n` on commodity hardware; `n = 100` ≈ 15 ms.
Torsion-freeness of an `A_i` is a property of the key and may be cached per endpoint id.

## 6. Reader decryption

Reader `i` holds the iroh secret key (32-byte seed). Its ElGamal scalar is exactly what
`ed25519-dalek` uses for signing:

```
a   = SigningKey::from_bytes(&seed).to_scalar()      ; clamped SHA-512 half, reduced mod ℓ
```

`A_i = a·B` holds exactly (that is how the Ed25519 public key is computed), and because
`E ∈ G` is enforced, `a·E = a·r·B = r·A_i` exactly — the mod-ℓ reduction inside
`to_scalar()` is invisible on a torsion-free `E`. This is where torsion in `E` would
bite: an unreduced clamped scalar kills `E[8]` (`a ≡ 0 mod 8`), the reduced one does not,
so two correct implementations would disagree. Hence the strict rejection rather than
"multiply by 8 somewhere".

```
1. fully verify the record (section 8) — never open an unverified record
2. locate own entry (A_i == own endpoint id) in wraps; absent ⇒ "not a recipient"
3. M' = c_i − a·E                                  ; constant-time a·E (EdwardsPoint * Scalar)
4. (DEK', commit') = KDF(M', group_id, dek_version)
5. subtle::ConstantTimeEq: commit' == dek_commit, else fail "wrap does not open to the committed key"
   (attributable: the record is signed by `author`)
6. use DEK'; zeroize M', a, DEK' on drop
```

Step 5 is the loud failure the brief asks for. It is also what turns the DLEQ's "same
`M` for everyone" into "same `M` *and* the one the author committed to": the proof cannot
show the latter (section 9.3), every reader can.

**X25519-compat recipients (optional).** An existing age/X25519 key `u` can be a
recipient without a new key ceremony: the encoder uses
`MontgomeryPoint(u).to_edwards(0)` — the Edwards point `A⁺` with `y = (u−1)/(u+1)` and
`x` non-negative — after the usual `decode_point` checks. The holder, with clamped scalar
`a`, computes `A = a·B`; if `A.compress() == A⁺` then `M = c − a·E`, else (`A = −A⁺`)
`M = c + a·E`. Deterministic, no trial decryption. The verifier treats `A⁺` as any other
base. This keeps the current backup and operational age keys usable; the recommendation
is still Ed25519 keys for all pinned recipients (one code path, `key generate` already
produces them), with this mode as the migration convenience if the operator prefers not
to rotate the offline backup key.

## 7. Author signature

```
msg = "secret-bunker-epoch/1 sig" ‖ 0x00 ‖ body_bytes
sig = Ed25519(author_seed, msg)                      ; RFC 8032 §5.1.6, pure, deterministic
verify: VerifyingKey(author).verify_strict(msg, sig) ; rejects small-order R and A, non-canonical S
```

Plus, from section 1, the author's point is torsion-free (it is decoded via
`decode_point` because it must appear in the previous ACL). With canonical `S`,
torsion-free `A` and non-small-order `R`, this is the strictly-verified Ed25519 variant
with a standard SUF-CMA argument in the ROM.

Why a domain prefix, and this one: the same key signs TLS 1.3 `CertificateVerify`
messages (which begin with 64 bytes of `0x20`), pkarr/BEP-44 discovery records (which
begin with `3:seq`), and iroh relay-handshake challenges (own prefix). Our message begins
with `secret-bunker-epoch/1 sig\0`, which no other consumer of this key will ever sign
and none of their messages can begin with. Ed25519ph/ctx (RFC 8032 §5.1 with context)
would be the standardised alternative and Go supports it since 1.20; pure Ed25519 with a
prefix is chosen because it is what `iroh::SecretKey::sign` and Go's `ed25519.Sign`
already do, needs no `hazmat` feature, and the prefix delivers the same separation.

The signature scope is the whole body, so it — not the proof — is what binds the ACL,
pinned set, chain position, `reencrypted` digest and authorship to the wrap set.

## 8. Full verification algorithm (server, replica, any client)

Ordered; the first failure rejects the record. Steps 1–9 need no key and no prior state;
steps 10–15 need the previous epoch (`head`).

1. Decode `EpochRecord`; `sig` is 64 bytes; `body` decodes as `EpochBody` with
   `v == 1`, `deny_unknown_fields`, no trailing bytes.
2. `acl`, `pinned`, `wraps`: each list sorted, strictly increasing by endpoint id; every
   endpoint id passes `decode_point`; `perms ⊆ {1,2,4}`; `perms ≠ 0`.
3. `recipients(wraps) == readers(acl) ∪ pinned` as sets, where
   `readers = { id : perms & 1 }`. `n = |wraps| ≥ 1`.
4. `E = decode_point(eph)`, `E ≠ O`. Every `c_i` passes `decode_point` (torsion-free,
   canonical). (`c_i = O` is allowed by the math but rejected too: it occurs with
   probability `2^−252` honestly and is a free sanity check.)
5. `e, s` canonical scalars.
6. DLEQ verification (5.5).
7. `author` ∈ `readers(acl) ∪ pinned` **if `dek_version` changed or any recipient was
   added**, i.e. the author must be able to know `M` when the epoch moves key material
   (for a carried-over wrap set this rule is skipped: an admin without read may edit
   `w`/`a` bits).
8. `verify_strict` of `sig` under `author` over the prefixed body (section 7).
9. `reencrypted` is 32 zero bytes iff `dek_version` equals the previous epoch's
   (checked at step 12); otherwise its digest must match the uploaded re-encrypted set
   (section 12.3).
10. Chain: `prev == epoch_hash(head)` and `epoch == head.epoch + 1`; for epoch 1,
    `prev == 0^32` and `epoch == 1`.
11. `group_id == head.group_id`.
12. `dek_version ∈ {head.dek_version, head.dek_version + 1}`; if unchanged then
    `dek_commit == head.dek_commit` (same generation ⇒ same committed key) and
    `reencrypted == 0^32`; if incremented then `reencrypted ≠ 0^32`.
13. Authorization (section 12.1): `author ∈ admins(head.acl) ∪ head.pinned`; for
    epoch 1, `author ∈ admins(acl) ∪ pinned` of the record itself (genesis is
    trust-on-first-use from the authoritative node, section 12.2).
14. `head.pinned ⊆ pinned` unless `author ∈ head.pinned` (only a pinned key may
    un-pin; server policy may be stricter, e.g. "the backup key is always pinned").
15. Last-admin rule: `admins(acl) ∩ readers(acl) ≠ ∅` unless `author ∈ pinned`
    (a recovery epoch may temporarily have no admin; section 12.1).

Readers additionally run section 6 and treat a `dek_commit` mismatch or an AEAD failure on
a re-encrypted version as an alarm attributable to `author`.

## 9. Security argument

### 9.1 What the proof guarantees, and under what assumptions

Let `G` be prime-order (enforced). The protocol of section 5 is a Σ-protocol for the
relation `R = {((E, D_i, C_i)_i ; r) : E = rB ∧ ∀i C_i = rD_i}`:

- **Completeness**: immediate.
- **Special soundness**: from two accepting transcripts with the same `R_j` and `e ≠ e'`,
  `r = (s − s')(e − e')^{−1}` (invertible since `ℓ` is prime) satisfies every equation.
  So a prover that convinces the verifier with probability noticeably above `1/ℓ`
  *knows* a single `r` making all `n` relations true (forking lemma, random-oracle
  model for SHA-512 → `mod ℓ`, which is statistically uniform on `Z_ℓ` from 512 bits).
- **HVZK**: pick `s, e` uniformly, set `R_0 = sB − eE`, `R_i = sD_i − eC_i`; the
  simulated transcript is distributed exactly as a real one. Fiat-Shamir makes it a
  NIZK in the ROM. Consequence: publishing the proof leaks nothing about `r` beyond the
  statement, so it does not weaken the encryption.

What follows for the wrap set: for every `i`, `c_i − r·A_i = c_0 − r·A_0`, and since
recipient `i` computes exactly `c_i − a_i·E = c_i − r·A_i` (section 6), **every recipient
that opens its wrap obtains the same `M`, hence the same `(DEK, dek_commit)`, hence the
same plaintexts from the same ciphertexts.** The last step needs no key-committing AEAD:
key-commitment matters only when two readers could hold different keys, and that is what
the proof excludes. ChaCha20-Poly1305 stays as is.

The proof binds the exact statement (strong Fiat-Shamir): changing, adding, removing or
reordering any `A_i` or `c_i`, or `E`, `group_id`, `dek_version`, `dek_commit`, changes
`e`. Soundness error `1/ℓ ≈ 2^−252` per verification; no grinding is possible because
`e` is 252 bits uniform and, crucially, because the cofactor has been removed from the
picture (9.2).

### 9.2 Cofactor: why "reject torsion" and why not Ristretto

If any of `E`, `c_i`, `A_i` carried an `E[8]` component `T`, the verification equations
would involve `e·T`, which depends only on `e mod 8`. A dishonest prover could then
commit to `R_i` guessing `e mod 8` and succeed after ~8 attempts — a valid-looking proof
for wraps that decrypt to `M + T_i`, different per reader by a torsion point, exactly the
failure the brief warns about. Two families of fixes:

- *Cofactored verification* (multiply both sides by 8): sound in the quotient `E/E[8]`,
  but readers decrypt in `E`, not the quotient, so `M + T_i` would still differ per
  reader. Unacceptable without also canonicalising `M`.
- *Ristretto*: canonicalises by construction, but Ed25519 public keys are Edwards points,
  not ristretto255 encodings, `curve25519-dalek` offers no public `EdwardsPoint →
  RistrettoPoint` constructor (`RistrettoPoint(pub(crate) EdwardsPoint)`), and a key with
  an odd (non-`2E`) component is not even a well-defined Ristretto element. It would mean
  a fork or `unsafe` transmutes to gain a property we can get by a check.
- **Chosen: exact subgroup-membership checks** on every decoded point (`ℓ·P = O`), plus
  canonical-encoding checks. After that, every value the arithmetic touches lies in the
  prime-order group `G`, and Ristretto's benefit is already obtained. Honestly generated
  Ed25519 keys and honestly produced wraps are always torsion-free, so a rejection is
  never a false positive: torsion is evidence of malice or corruption and should fail
  loudly, not be silently cleaned. Cost: one scalar multiplication per point, cacheable
  for keys.

### 9.3 What the proof does NOT guarantee

1. **That `M` is the key anyone expects.** The statement is about equality across
   recipients, not about the value. A malicious author can wrap a garbage `M'`,
   commit to it honestly, and everyone derives the same useless DEK; or commit to one
   `M` and wrap another. Readers detect this at the `dek_commit` check (section 6) or,
   for re-encrypted data, at the AEAD tag; nobody without a key can. This is a
   detectable, attributable denial of service, not a confidentiality break.
2. **That the author knows `M`.** Anyone can produce a wrap set for an `M` they do not
   know (choose `c_0` at random). Combined with (1): consistency ≠ correctness.
3. **That the body ciphertexts were re-encrypted under the committed DEK.**
   `reencrypted` is a digest, verified by readers on decryption.
4. **Anything about the ACL, pinned set, chain position, or authorship.** Those are
   outside the transcript by design; the signature carries them.
5. **Authorisation or provenance of the wrap set itself.** ElGamal ciphertexts and
   their proofs are freely producible by anyone for any `M` of their choosing, and by
   anyone who knows `r` they are re-randomisable and shiftable (`c_i + Δ` for all `i`
   preserves the relation; with a *weak* Fiat-Shamir that hashed only the `R`'s the
   old proof would even still verify — the reason section 5.3 hashes every `c_i`).
   Without a signature, a compromised authoritative node could mint an epoch with a
   fresh `M'`, itself as a recipient, and a perfectly valid proof; every honest writer
   would then encrypt future secrets to a key the attacker holds. The DLEQ says "these
   wraps are consistent"; only the signature says "an authorised admin asserts these
   wraps, this ACL, at this chain position". Both are needed; neither substitutes for
   the other.
6. **Confidentiality against recipients.** By construction every recipient learns `M`.
   "Insider" security in the multi-recipient model means insiders learn nothing about
   *other* messages, which here are none.

### 9.4 Confidentiality of `M` and randomness reuse across recipients

The wrap is hashed multi-recipient ElGamal with shared randomness. ElGamal is
*reproducible* in the Bellare–Boldyreva–Staddon sense: given a ciphertext `(E, c)` under
key `A` with known plaintext `M` and a fresh key pair `(a', A')`, one computes the
ciphertext of any `M'` under `A'` with the *same* `r` as `(E, M' + a'·E)`. BBS's theorem
then gives: the `n`-recipient scheme with shared `r`, against an adversary that corrupts
any subset of recipients, is as secure (IND-CPA) as single-recipient ElGamal, i.e. under
DDH in `G` for the point `M`, and — since only `KDF(M)` is used — under CDH in the ROM
for the derived key. Corrupt recipients gain nothing from the shared `r`: from
`(E, c_j, a_j)` they learn `r·A_j = a_j·E`, which they can compute from `E` alone.

The reader's commit check (section 6) is a plaintext-checking oracle on the reader's
static-DH function `X ↦ a·X`, available to anyone who can get a reader to process a
record — i.e. only to authorised epoch authors, who are readers themselves, but the
argument does not rely on that: hashed ElGamal with a PCA/decryption oracle is secure
under Gap-DH in the ROM (the DHIES/ECIES argument). So the confidentiality claim is:
*outsiders holding no recipient key learn nothing about `DEK` from any number of epoch
records, under Gap-DH in `G` in the random-oracle model.* This is the same assumption
the existing age wrapping already rests on.

### 9.5 One key for TLS signing, epoch signing, X25519 (age) and ElGamal

The endpoint key is now used for (i) Ed25519 signatures in the TLS 1.3 handshake and
iroh discovery, (ii) Ed25519 signatures on epochs, (iii) X25519 ECDH inside age
(existing `agebridge.rs`), (iv) ElGamal decryption `c − a·E` on the Edwards curve.
Operations (iii) and (iv) are the *same* static Diffie–Hellman function `X ↦ a·X` in
two coordinate systems: X25519 outputs the `u`-coordinate of `a·X`, ElGamal uses the
full Edwards point. Thormarker (ePrint 2021/509) proves joint security of Ed25519
signing with an X25519-based hashed KEM under the same key in the ROM (Gap-DH-type
assumption): the signing oracle does not help the KEM adversary and the decapsulation
oracle does not help the forger. Our ElGamal falls inside that model with two
observations: (a) the decapsulation output is never exposed unhashed (readers keep `M`;
only `KDF(M)` is ever used and `dek_commit` is a PRF output), so the oracle an adversary
gets is at most the PCA oracle of 9.4, which the Gap-DH argument covers; (b) all inputs
to the static-DH function are forced into `G`, so it never becomes a small-subgroup
oracle (moot for clamped `a` anyway, but it keeps the two coordinate systems
consistent). The TLS handshake uses the key for signatures only (ephemeral X25519 for
key agreement), so it adds no DH exposure. Domain separation between (i) and (ii) is
section 7's prefix. Net: the existing joint-use argument for age extends to the new
scheme without a new assumption. (`ed25519-dalek`'s own `to_scalar` docs cite the same
paper.)

### 9.6 Remaining crypto-level caveats

- No forward secrecy: a future leak of any recipient's key opens every generation it
  was a recipient of (unchanged from today).
- The author knows `m = log_B(M)`. This is harmless — knowing `m` is equivalent to
  knowing `M` — but `m` must be zeroized like `r`; do not store it.
- Ed25519 keys are software keys in process memory (unchanged).

## 10. Constant-time and hygiene requirements

Secret-dependent operations, all of which must use `curve25519-dalek`'s constant-time
paths: `r·B`, `r·A_i`, `k·B`, `k·D_i` (prover); `a·E` (reader); `s = k + e·r`
(`Scalar` ops are constant-time). Use `EdwardsPoint * Scalar` and the basepoint table;
never `vartime_*` with a secret scalar. Verifier-side arithmetic is public and uses the
`vartime_*` variants. `dek_commit` comparison uses `subtle::ConstantTimeEq` (subtle 2.6
is in the tree). Zeroize (`zeroize::Zeroizing`) `r`, `k`, `m`, `M`, `a`, `DEK`, and the
intermediate `[u8;64]` RNG/hash buffers. Never log a wrap set's private inputs; `E`,
`c_i`, proof and commit are public and may be logged. Decoding and point validation
are on public data; timing there is irrelevant. `OsRng` only; the hedged nonce of 5.4
is a backstop against RNG repetition, not a licence to use a weak RNG.

## 11. Test-vector plan

Golden vectors are generated once by the reference implementation from fixed inputs and
pinned as hex, in the style of `agebridge::tests::derivation_golden_vector` and
`proto::tests::wire_format_is_stable`. Fixed inputs: identities from
`iroh::SecretKey::from_bytes(&[7u8;32])`, `[8u8;32]`, `[9u8;32]`; a fixed
`group_id = 0x11..11`; `m` and `r` from fixed 64-byte seeds via
`from_bytes_mod_order_wide`; the prover's `k` computed with the hedge bytes fixed to
zero (test hook). Pin: `E`, each `c_i`, `dek_commit`, `DEK`, `e`, `s`, the body bytes,
`sig`, `epoch_hash`. A second vector with `n = 1`, a third with `n = 3` including an
X25519-compat recipient if that mode ships.

Negative tests (each must be rejected at the named step of section 8):

| Case | Construction | Rejects at |
|---|---|---|
| torsion in `E` | `E + EIGHT_TORSION[1]` | 4 (`decode_point`) |
| torsion in one `c_i` | `c_i + EIGHT_TORSION[k]`, `k = 1..7` | 4 |
| torsion in an `A_i` | ACL entry `A + EIGHT_TORSION[1]` (a key iroh's decoder accepts) | 2 |
| `E = O` | `r = 0` | 4 |
| swapped `c_i`, `c_j` | exchange two wrap values, keep proof | 6 |
| wrong `e` / wrong `s` | flip one bit | 6 |
| non-canonical `s` | `s + ℓ` as 32 bytes | 5 |
| non-canonical `e` | `e + ℓ` | 5 |
| non-canonical point | `y + p` encodings; `0x01‖00..‖0x80`; `y = −1` with sign bit | 2/4 |
| duplicate recipient | same id twice; same point re-encoded | 2 |
| unsorted wraps | valid set, two entries exchanged | 2 |
| hidden recipient | wrap for an id not in `readers ∪ pinned` | 3 |
| missing recipient | reader without a wrap | 3 |
| transplanted proof | valid wrap set with `group_id` or `dek_version` changed | 6 |
| Δ-shift | `c_i + Δ` for all `i`, proof kept | 6 (strong FS); document that a weak-FS transcript would pass |
| commit mismatch | honest wrap set with `dek_commit` of a different `M` | reader step 5 (and 12 if `dek_version` unchanged) |
| bad signature | body altered after signing; sig by a non-author; small-order `R` | 8 |
| author not authorised | author absent from `admins(head.acl) ∪ head.pinned` | 13 |
| chain break | wrong `prev`; `epoch ≠ head + 1`; changed `group_id` | 10/11 |
| `reencrypted` inconsistency | zero digest with bumped `dek_version` and vice versa | 12 |
| wrong-key decryption | reader with a key not in the set opens a neighbour's wrap | reader step 5 |
| `r` reuse | two wrap sets from the same `M` MUST have different `E` | property test |

Positive controls: `n = 1`; a carried-over wrap set in a pure ACL epoch verifies with the
new `epoch`/`prev`; a wrap set produced by an `x25519`-compat recipient decrypts on the
`−A⁺` branch; torsion-free check accepts all honestly generated keys (property test over
1,000 random seeds). A cross-implementation test: the Go client re-derives `e` from the
pinned transcript bytes and verifies the pinned `sig`.

## 12. Answers to section 5 of the brief

### 12.1 Who may do what (verifier-enforced)

- **Author of epoch `n`** must be in `admins(acl_{n−1}) ∪ pinned_{n−1}`. Pinned keys are
  the group's root of recovery (the offline backup key; in server-recipient mode also the
  server's operational key). Recommended default: **an admin may kick another admin**,
  including revoking read. Rationale: an admin already holds `M` and can read and rewrite
  everything; forbidding admin-kicks-admin would not reduce what a compromised admin key
  can do to confidentiality, only slow down the honest response to that compromise. What
  the design adds is that the kick is signed, chained and public, so it is always
  attributable and reversible by any remaining admin or by the backup key.
- **Last-admin rule** (step 15): every epoch must leave at least one admin who is also a
  reader, unless the author is a pinned key. An admin without read cannot rotate (no
  `M`), so "admin ∧ reader" is the unit that keeps a group manageable.
- **Moving key material** (new generation, or any new recipient) requires the author to
  be a recipient of the new epoch (step 7); a pure `w`/`a` edit does not.
- **Service admin**: no implicit epoch authority. It keeps `CreateGroup`, identity
  registration/removal and the service flag; it can author epochs only for groups where
  it holds an explicit admin row. Recovery of an orphaned group is the backup key's job,
  or `db grant` with the service stopped as today — the latter now means "sign an epoch
  with the backup key locally".
- **Lockout**: cannot happen cryptographically as long as the backup key is pinned (it
  is always a recipient and always authorised); an operator who loses the backup key
  and all admin keys has lost the group, which is the same as today.

### 12.2 Epoch 1 and replicas

Epoch 1 is minted client-side by the creator (`author` = creator, `acl` = creator with
`r|w|a`, `pinned` from server policy delivered in the `CreateGroup` reply) and submitted
with the group creation; the server checks it structurally (section 8 steps 1–9, 13, 15)
and stores it. Replicas accept epoch 1 from the authoritative node as trust-on-first-use
(exactly the trust they place in the whole ACL today, but now confined to one record) and
verify every subsequent epoch against the chain. For migrated groups (section 12.5) epoch
1 is server-authored with the authoritative endpoint key; the replica's rule is "epoch 1
author ∈ admins ∪ pinned ∪ {authoritative endpoint id}".

### 12.3 Kick + roll: existing ciphertext, atomicity, attribution

A generation change (`dek_version + 1`) **re-encrypts every retained secret version** of
the group under the new DEK (fresh nonce, AAD recomputed with the new `dek_version`,
`version` numbers unchanged). Old generations' wrap sets are pruned from live state after
the epoch commits (their bytes stay in the chain for audit; nothing decryptable remains
under a key the kicked reader held). `reencrypted = SHA-256( "secret-bunker-epoch/1
reenc" ‖ 0x00 ‖ u64be(count) ‖ Σ_{sorted by (name, version)} [ u64be(len(name)) ‖ name ‖
u64be(version) ‖ u64be(dek_version) ‖ nonce(12) ‖ SHA-256(ciphertext) ] )`. Atomicity: the
client uploads the re-encrypted versions in one `SubmitEpoch` request (or a staged
upload keyed by the pending `epoch_hash`, then a commit) and the server applies epoch +
versions + pruning in one SQLite transaction with a compare-and-set on
`(group_id, head_epoch)`; a concurrent epoch loses and is answered `EpochConflict{head}`.
Attribution: the `author` signature covers `reencrypted`, so "who last re-encrypted" is
the author of the newest epoch with a non-zero `reencrypted`. Rotation without a kick is
the same operation with an unchanged ACL. Add-reader is `dek_version` unchanged, fresh `r`,
same `dek_commit`, no re-encryption.

### 12.4 Server, backup key, service admins, replicas, write-only identities; modes

Two deployment modes, chosen per bunker and visible in every epoch's `pinned` list:

- **Server-recipient mode** (drop-in for today's clients): the server holds a dedicated
  Ed25519 *operational* key (not its endpoint key, preserving independent rotation of
  transport identity and at-rest key), pinned in every epoch. It can serve plaintext
  `Get`, accept plaintext `Put` from write-only identities, and run kicks/rotations on a
  service admin's behalf (`RemoveIdentity` keeps its "always works" semantics). Threat
  model: unchanged against the operator; gained: a compromised authoritative node can no
  longer forge ACL changes that replicas accept, and every rotation is attributed.
- **End-to-end mode**: the server is not a recipient. Only readers can decrypt; only
  admin-readers can rotate; `Put` must carry ciphertext produced by a recipient, so
  **write implies recipient** (a write-only identity is granted `r|w` and appears in the
  wraps). `RemoveIdentity` by a service admin removes the row (immediate transport
  denial) and marks affected groups "rotation pending" until an admin-reader submits the
  kicking epoch. Gained: the operator cannot read secrets; lost: plaintext reads for
  legacy clients and server-side rotation on revoke.

The **backup key** is pinned in both modes and is the only party that can always author
an epoch; it never comes online except for recovery, which now means "sign a recovery
epoch offline, submit it". **Replicas** verify the chain (section 8) before applying a
`Group` state; a compromised authoritative node degrades to withholding. **Service
admins** lose implicit read in E2E mode and keep it in server-recipient mode (through the
operational key, as today).

### 12.5 Storage, protocol, migration

Storage: new table `group_epoch (group_id, epoch, hash BLOB(32), prev BLOB(32), author
TEXT, dek_version, dek_commit BLOB(32), body BLOB, sig BLOB(64), created_at, PRIMARY KEY
(group_id, epoch), UNIQUE (group_id, hash))`; `secret_group` gains `group_id_bytes
BLOB(32)` and `head_epoch`; `group_dek` gains `epoch` (the epoch that introduced the
generation) and `dek_commit`; `dek_wrap` survives only for pre-migration generations
and is dropped once every group has re-encrypted. Wraps live inside the epoch body; no
per-recipient wrap rows.

Protocol (`secret-bunker/1`, additive): `SubmitEpoch { group, record: bytes,
versions: [...] }` → `Ok | EpochConflict { head_epoch, head_hash } | Failed`;
`GetEpochs { group, since: uint }` → `Epochs { records: [bytes] }`; `CreateGroup`'s reply
carries the pinned set. `Grant`/`RotateDek` remain for server-recipient mode (the server
authors the epoch with its operational key) and answer `Failed` in E2E mode.
`secret-bunker-sync/1` (additive): `Group` gains `epochs: [bytes]` (full chain on first
sight, tail on `Changed`); the replica derives ACL and its own wrap from the verified
head instead of from `acl`/`deks`, which stay populated for one release and then become
optional. Golden vectors in `proto`/`sync` tests gain the new variants.

Migration per group, on first start of the new binary (or an explicit `db migrate-epochs`):
the server unwraps the current DEK with the operational key, generates `M`, re-encrypts
every retained version under `KDF(M)`, mints epoch 1 with `author` = authoritative
endpoint id, `acl` = current rows, `pinned` = {backup, operational} (X25519-compat or
newly generated Ed25519 keys per operator choice), commits, and deletes the group's
`dek_wrap` rows. Databases that never migrate keep working on the old path; a group is
on exactly one path, decided by the presence of `group_epoch` rows.

### 12.6 What the DLEQ buys over "age wraps + author signature"

The simpler alternative (sign today's record: ACL + per-recipient age wraps) already
delivers attribution and unforgeable ACL changes toward replicas. What it cannot deliver:

1. **Prevention rather than detection of a split view.** With age wraps a rogue admin can
   address a different key — or garbage — to one reader; only that reader notices, and
   nobody else can verify its complaint without its private key (age wraps are opaque to
   third parties). With the wrap set, the server, every replica and every client
   verifies "all recipients get the same key" **before storing** the epoch, without any
   key. Inconsistent epochs never exist in the system.
2. **A keyless verifier.** The server can validate rotations without an operational key
   at all — the precondition for the E2E mode and for "the service admin is not root".
   Age wraps give the verifier nothing to check.
3. **Compactness and fewer moving parts.** 32 bytes per recipient + 64 bytes total,
   versus ~200 bytes per age file; no age header parsing, no Bech32 round-trips, no
   Edwards→Montgomery conversion in the wrap path.

What it does not buy: protection from a malicious admin who holds `M` (they can leak,
rewrite, or DoS — all attributable, none preventable); anything about the correctness of
`M` (section 9.3). If the threat model were only "hostile server, honest admins", age
wraps + signature would suffice and would be roughly a fifth of the implementation work.
The user's stated goal — any admin can kick and roll, and the result is publicly checkable
— is precisely the split-view guarantee, which is item 1.

## 13. Open questions for the user

1. Backup key: rotate to a new offline Ed25519 key at migration (recommended), or keep the
   existing X25519 age backup key via the compat recipient mode (section 6)?
2. Default deployment mode for the existing bunker: server-recipient (no client changes,
   operator remains root) or end-to-end (operator loses read; write-only identities
   become readers; `RemoveIdentity` becomes two-phase)?
3. Admin-kicks-admin allowed by default (recommended) — confirm.
4. Should old generations' wrap sets be retained in live state for a grace period (lets
   any previous reader recover from a garbage rotation without the backup key) or
   pruned immediately (strictly smaller exposure after a kick)? Recommended: prune
   immediately; the chain keeps the bytes for audit.
5. Genesis for new groups minted client-side (true E2E from creation) versus
   server-minted (simpler client): recommended client-side.

## Key decisions

- Stay on the Ed25519 Edwards curve; do not map into Ristretto (no public EdwardsPoint->RistrettoPoint constructor in curve25519-dalek 5, and Ed25519 keys are not Ristretto encodings). Instead every decoded point must be canonically encoded (recompress-and-compare, because `decompress` accepts the 19 y>=p encodings and the x=0/sign-bit encodings) and exactly torsion-free (`is_torsion_free` = l*P == O). Torsion is rejected, never cleared, because cofactored verification would let readers disagree by a torsion point and because a torsion component permits an ~8-try grinding forgery of the proof.
- Multi-recipient ElGamal with one shared ephemeral r (E = r*B, c_i = M + r*A_i, M = m*B random), proven consistent by ONE batched Schnorr response with the shared witness r (generalised Chaum-Pedersen over n bases): 64 bytes total for any n, and strictly stronger than n independent DLEQs because special soundness extracts a single r satisfying all equations. Anchor = smallest endpoint id in sorted order.
- Strong Fiat-Shamir: the SHA-512 transcript hashes the full statement (domain tag `secret-bunker-epoch/1 dleq\0`, group_id, dek_version, dek_commit, n, E, every (A_i, c_i) in sorted order) before the commitments R_0..R_{n-1}; challenge reduced with Scalar::from_bytes_mod_order_wide. Epoch number, prev, ACL and author are deliberately outside the transcript (signature scope) so a pure ACL edit can carry a wrap set verbatim.
- Key derivation: HKDF-SHA256(ikm = M.compress(), salt = 'secret-bunker-epoch/1 dek', info = group_id || u64be(dek_version)) -> 64 bytes; DEK = first 32, dek_commit = last 32 (independent PRF outputs). group_id is 32 random bytes chosen at epoch 1, not hash(epoch 1), to avoid circularity. Existing secret AAD and ChaCha20-Poly1305 are unchanged; no key-committing AEAD is needed because the proof excludes readers holding different keys.
- Reader decryption uses ed25519-dalek's `SigningKey::to_scalar()` (clamped, reduced) and M = c_i - a*E, followed by a constant-time dek_commit check that fails loudly and attributably. Torsion-free E is what makes the mod-l reduction harmless. Optional X25519-compat recipient mode (MontgomeryPoint::to_edwards(0), holder picks the +/-A branch deterministically) lets the existing age backup/operational keys participate; recommendation is new Ed25519 pinned keys.
- Author signature: pure Ed25519 by the endpoint key over 'secret-bunker-epoch/1 sig' || 0x00 || body_bytes, verified with verify_strict; the signed object is the exact CBOR bytes received (decoder is strict, deny_unknown_fields, no re-canonicalisation), and epoch_hash = SHA-256('secret-bunker-epoch/1 hash' || 0x00 || body || sig). The signature, not the proof, binds ACL, pinned set, chain position, reencrypted digest and authorship; the proof alone is freely producible by anyone for any M.
- Randomness rules: r MUST be fresh per wrap set (reuse across generations leaks M_new - M_old to a kicked reader); prover nonce k is hedged-deterministic (SHA-512 over r, statement hash, 32 fresh random bytes). Avoid Scalar::from_hash / Scalar::random / hash_to_curve because curve25519-dalek 5 is bound to digest 0.11 / rand_core 0.10 while the project pins sha2 0.10 / rand 0.8; use from_bytes_mod_order_wide with OsRng and sha2 0.10 output.
- Authorization defaults: author of epoch n must be in admins(acl_{n-1}) or pinned_{n-1}; admins may kick admins; every epoch must leave an admin who is also a reader unless authored by a pinned key; moving key material requires the author to be a recipient; the service admin gets no implicit epoch authority; the offline backup key (pinned, Ed25519) is the recovery root and the only party that can always author an epoch.
- Kick/rotate re-encrypts every retained version under the new DEK in one CAS-guarded server transaction, with a `reencrypted` digest covered by the signature; add-reader keeps dek_version and dek_commit with a fresh r and no re-encryption. Two deployment modes (server-recipient with a dedicated Ed25519 operational key, or end-to-end where write implies recipient) are visible in each epoch's pinned list.

## Risks

- The proof guarantees consistency, not correctness: a malicious admin can commit to one M and wrap another, or wrap a garbage M, producing an attributable denial of service that only readers (via dek_commit or AEAD failure) can detect; no keyless party can. Pruning old wrap sets immediately means recovery from such a rotation depends on the backup key.
- Any registered EndpointId with a torsion component (accepted by iroh's decoder) becomes unusable as a recipient or author under the strict decode_point rule; honest keys are never affected, but the failure surfaces at epoch verification rather than at AddIdentity unless the server also validates there.
- Signing the exact received CBOR bytes avoids canonicalisation bugs but means semantically identical records from different encoders (e.g. a Go client with different map-key order) have different epoch_hash values; the chain must reference stored bytes, and the strict decoder (deny_unknown_fields) makes body format evolution require a version bump.
- Verification cost is ~3n scalar multiplications (2n+1 exact torsion checks plus n multiscalar muls); fine at tens to hundreds of recipients, but a group with thousands of readers would want per-key caching of torsion-freeness and possibly a faster subgroup check.
- Joint use of one Ed25519 key for TLS signing, epoch signing, X25519 (age) and Edwards ElGamal rests on Thormarker's ROM/Gap-DH joint-security result plus the domain prefix; the ElGamal decryption exposes a plaintext-checking oracle to authorised epoch authors, covered by the Gap-DH argument but a stronger assumption than plain DDH.
- The X25519-compat recipient mode requires extracting the raw clamped scalar from an age x25519::Identity via its Bech32 string; age 0.11 exposes no direct accessor, so this path needs careful zeroization and a golden vector of its own.
- In end-to-end mode, write-only identities collapse into readers and RemoveIdentity becomes two-phase (row removal now, rotation when an admin-reader acts), which changes today's 'revocation always works immediately and rotates in one transaction' guarantee; in server-recipient mode the operator remains root as today.
- hkdf and curve25519-dalek must be added as direct dependencies; the digest 0.11 / rand_core 0.10 version split with the project's sha2 0.10 / rand 0.8 is a trap for anyone who reaches for Scalar::from_hash, Scalar::random or hash_to_curve.

## Open questions for the user

- Backup key: rotate to a new offline Ed25519 keypair at migration (recommended, one code path), or keep the existing X25519 age backup key through the X25519-compat recipient mode?
- Default deployment mode for the existing bunker: server-recipient (drop-in for today's clients, operator remains root, dedicated Ed25519 operational key pinned) or end-to-end (operator loses read; write-only identities become readers; RemoveIdentity becomes two-phase)?
- Confirm that an admin may kick another admin by default (recommended: allowed, attributable, reversible by any remaining admin or the backup key), with the last-admin rule being 'at least one admin who is also a reader' unless a pinned key authors the epoch.
- Prune previous generations' wrap sets immediately after a kick (recommended; the chain keeps the bytes for audit) or retain them in live state for a grace period so any former reader can recover from a garbage rotation without the backup key?
- Genesis for new groups minted client-side by the creator (true end-to-end from creation, recommended) or server-minted (simpler client, server briefly knows M)?
- Should identity names be excluded from the signed epoch body (recommended: keys only; names stay transport metadata as today) even though replicas then display unauthenticated names?
