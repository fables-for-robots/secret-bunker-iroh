# Signed DEK epochs: authorization rules and threat model

Angle: what a verifier (authoritative server, replica, offline auditor) enforces on an epoch record, who may author what, how the group survives a rogue or lost key, what attribution means, and exactly what changes in the threat model of `design/crypto-design.md`. Every item of section 5 of the brief is answered; the crypto is specified only as far as the rules need it to be unambiguous.

Normative words: MUST / MUST NOT / SHOULD / MAY. "Verifier" means any of the three parties above unless a rule is prefixed `S` (server only) or `P` (replica only).

## 1. Objects

**Keys.** Every participant key is an Ed25519 public key `A = a·B`, where `B` is the Ed25519 basepoint (prime order `ℓ`) and `a` is the clamped scalar (`ed25519_dalek::SigningKey::to_scalar()`). Client identities are iroh EndpointIds, as today. Two server-side keys join them and are also Ed25519 (new key files, iroh `SecretKey` format):

- `backup`: offline, replaces the X25519 age backup key for new material.
- `service`: the server's operational recipient, replaces the X25519 age operational key for new material. Distinct from the endpoint key, for the same rotate-independently reason as today.

**Epoch record** (`EpochRecord`), one chain per group. Storage and wire form is CBOR (`serde_bytes` for the 32/64-byte fields), but the hash and the signature are computed over a fixed binary layout so no CBOR canonicalisation is involved:

```
magic       "secret-bunker-iroh/epoch/1"     26 bytes, no length prefix
group_id    32   random, chosen at genesis; HKDF salt and storage key
epoch       u64  1 for genesis; see C2/C3 for the successor rule
prev        32   SHA-256 of the previous record's layout; zero for genesis
kind        u8   1 genesis, 2 acl, 3 rotate, 4 recovery, 5 service-rekey
dek_gen     u64  DEK generation; 1 at genesis; +1 whenever M changes
n_acl       u32  then n_acl × (key 32 || perms u8), strictly ascending by key
n_pinned    u32  then n_pinned × (key 32 || role u8), strictly ascending; role 1 backup, 2 service
c0          32   r·B
n_wraps     u32  then n_wraps × (key 32 || c 32), strictly ascending by key; c = M + r·A_key
proof_e     32   DLEQ challenge scalar
proof_s     32   DLEQ response scalar
dek_commit  32   key-check value of this generation (section 2)
reencrypted 32   digest of the ciphertext set installed with this record (section 4)
author      32   Ed25519 key that signs
at          i64  author's clock, unix seconds, advisory only
sig         64   Ed25519 over everything above, magic included
```

`hash(rec) = SHA-256(layout without sig)`. `perms` bits are today's `r=1 w=2 a=4`. `reencrypted` is `SHA-256("secret-bunker-iroh/reenc/1" || n u32 || leaves)` over leaves `SHA-256(len(name) u64 || name || version u64 || dek_gen u64 || nonce || ciphertext)` sorted by `(name, version)`; the empty set hashes with `n = 0`, so the field is never zero for a rotate.

**Recipients** of a record: `readers(rec) = {k : (k,p) ∈ acl, p & 1 ≠ 0}`; `recipients(rec) = readers(rec) ∪ keys(pinned)`.

**Registry.** The server's `identity` table (EndpointId → name, service-admin flag) stays outside the chain. The chain speaks raw keys; names are a server-attested display layer, exactly as replicas already treat them.

## 2. Wrap and proof scheme (brief item 1)

**Generation.** Author picks `m, r ← Scalar::random`, sets `M = m·B` (torsion-free by construction), `c0 = r·B`, and for every recipient key `A_i`, `c_i = M + r·A_i`. `r` and `m` are zeroized after signing; nobody ever stores them.

**DEK derivation.**

```
K   = HKDF-SHA256-Extract(salt = group_id, ikm = M.compress())
DEK = HKDF-Expand(K, "secret-bunker-iroh/dek/1", 32)
dek_commit = HKDF-Expand(K, "secret-bunker-iroh/dek-commit/1", 32)
```

Secret values stay ChaCha20-Poly1305 with `secret_aad(group, name, version, dek_gen)` — `dek_version` in the AAD becomes `dek_gen`, same u64 slot, same bytes. ChaCha20-Poly1305 is not key-committing, but nothing requires it to be: the DLEQ guarantees a single `M` per record and `dek_commit` tells a decryptor whether its `M` is that one, so the "two keys, two plaintexts" attack has no second key to use.

**Decryption** (recipient with scalar `a`): `M = c_i − a·c0`, derive `K`, check `dek_commit`, else fail closed and report ("epoch is malformed"); never fall through to the AEAD.

**Proof.** One batched Chaum–Pedersen proof that a single `r` underlies `c0` and every difference `c_i − c_1 = r·(A_i − A_1)`, `i ≥ 2`, recipients in the sorted order of `wraps`:

```
prover:  k ← random; T0 = k·B; T_i = k·(A_i − A_1)
         e = Scalar::from_hash(SHA-512("secret-bunker-iroh/dleq/1" || group_id || dek_gen
               || n u32 || A_1..A_n || c0 || c_1..c_n || T0 || T_2..T_n))
         s = k − e·r  (mod ℓ)
verifier: T0' = s·B + e·c0                       (vartime_double_scalar_mul_basepoint)
          T_i' = s·(A_i − A_1) + e·(c_i − c_1)   (vartime multiscalar)
          recompute e' from the same transcript with T0', T_i'; accept iff e' == e
```

Cost: 2 + 2(n−1) variable-time scalar multiplications per record; proof is 64 bytes regardless of n. The transcript binds `group_id` and `dek_gen` but deliberately not `epoch`, so an `acl` epoch whose recipient set is unchanged MAY carry `c0`, `wraps` and `proof` verbatim from its predecessor (rule R5). Adding a recipient requires `M`, not `r`: the author re-randomises with a fresh `r'` and re-proves.

**Point hygiene (rules E3/E4, the cofactor caveat).** Every 32-byte point in the record — each `A` in `acl`, `pinned` and `wraps`, `c0`, every `c_i` — MUST decompress, MUST re-compress to the identical bytes (canonical encoding), MUST NOT be the identity, and MUST satisfy `is_torsion_free()`. Verification MUST be exact in the full group; a verifier MUST NOT multiply by the cofactor. Rationale: if `8·(c_i − c_1) = 8r·(A_i − A_1)` were accepted, an author could add a distinct 8-torsion point `T_i` to each `c_i`; the proof would pass and recipient `i` would recover `M + T_i` — a different DEK per recipient, which is precisely what the proof exists to exclude. With all inputs torsion-free and an exact check, `M = c_1 − r·A_1` is itself torsion-free, so all recipients recover the same `M`. Ristretto is not used because recipient keys are Ed25519 points, not Ristretto encodings; torsion-freeness plus exact verification is the equivalent guarantee.

**Security argument.**
- *Confidentiality of M* (hence the DEK) against anyone holding none of the recipient scalars: multi-recipient ElGamal with shared randomness is IND-CPA under DDH in the prime-order subgroup (randomness-reuse result for ElGamal); HKDF on `M` makes it a hashed KEM in effect. Using the signing scalar also as the decryption scalar is the same joint signing + DH use the current design already relies on for the age bridge, with the same analysis.
- *Consistency*: the DLEQ is a Σ-protocol with special soundness (two accepting transcripts with different `e` yield the same `r` for every relation simultaneously) made non-interactive by Fiat–Shamir; it is honest-verifier zero-knowledge, so it leaks nothing about `r` or `M`. Given E3/E4, an accepting proof implies every listed recipient decrypts to the same `M`.
- *Authorship*: Ed25519 EUF-CMA over the layout; the magic prefix separates it from iroh's TLS signatures.
- *Binding of the ciphertext set*: `reencrypted` under the signature commits the author to the exact bytes installed; the server checks this at commit (S4).

**What is NOT proven** (and is claimed by nothing here): that the ciphertexts were produced under this DEK — that is checked per secret by the AEAD at decryption time, or by the server in mode S (S5), never by the proof; that the author knew the plaintext or acted wisely; that `at` is honest; that the server delivered the newest record (liveness); that a key in `acl` belongs to the human the registry names; anything about data a recipient already fetched under an earlier generation; forward secrecy (section 7).

## 3. Who may do what (brief item 2)

### 3.1 Well-formedness and chain rules

- **E1** The layout MUST parse exactly, with no trailing bytes, known `kind` and `role` values, and `perms ⊆ 7`. `at` MUST NOT be used to accept or reject a record; a verifier MAY log a warning if `at < head.at`.
- **E2** `acl`, `pinned` and `wraps` MUST be strictly ascending by key — no duplicates. (Duplicate recipients would make `A_i − A_1` the identity for some `i` and give a degenerate relation.)
- **E3/E4** As in section 2. Scalars `e`, `s` MUST be canonical (`< ℓ`).
- **C1** Genesis: `epoch = 1`, `prev = 0`, `dek_gen = 1`, `kind = genesis`. A verifier with no head for `group_id` MUST accept only a genesis record; a verifier with a head MUST NOT accept another genesis.
- **C2** Non-recovery successor: `group_id = head.group_id`, `prev = hash(head)`, `epoch = head.epoch + 1`.
- **C3** Recovery successor: `prev = hash(head)`, `epoch ≥ head.epoch + 1` (a jump is allowed; the recovery tool sets `epoch = max(head.epoch + 1, at)`, section 5).
- **C4** Signature MUST verify under `author`.

### 3.2 Recipient rules

- **R1** `pinned` MUST contain exactly one `backup` entry and at most one `service` entry.
- **R2** `keys(wraps) == recipients(rec)` as sets, exactly: no missing recipient, no extra. An extra wrap is a hidden reader; a missing one is a silently broken reader or — worst — a broken backup.
- **R3** DLEQ verifies (section 2).
- **R4** Generation continuity: for `acl` and `service-rekey`, `dek_gen = head.dek_gen`, `dek_commit = head.dek_commit`, `reencrypted = head.reencrypted`. For `rotate`, `dek_gen = head.dek_gen + 1`, `dek_commit ≠ head.dek_commit`, `c0 ≠ head.c0`. For `recovery`, either branch, chosen by `dek_gen`. Rationale: `dek_commit` continuity is how a verifier without a key knows an `acl` epoch re-wrapped the *same* `M` — an author who does not know `M` cannot produce a fresh wrap set with the old commit.
- **R5** Verbatim carry-over of `(c0, wraps, proof)` is allowed only when `recipients(rec) == recipients(head)`; otherwise R3 will fail anyway because the transcript changes.

### 3.3 Authorship rules

- **A1 genesis**: `author ∈ acl` with the admin bit, or `author` is the `service` pinned key (server-minted genesis: migration and the mode-S compatibility path, section 8). The *server* additionally requires that the wire caller is a service admin (S1) — that check is not chain-verifiable and replicas do not attempt it.
- **A2 acl, rotate**: `author` MUST hold the admin bit in **`head.acl`** (the previous epoch). Being added as admin in the same record does not qualify. A record signed by a reader, a writer, an unregistered key, the service key or the backup key with these kinds MUST be refused.
- **A3 recovery**: `author == head.pinned[backup]`. Nothing else may author a recovery epoch — not a service admin, not the operational key, not an operator with a shell (see 3.6).
- **A4 service-rekey**: `author == head.pinned[service]`; `acl == head.acl`; `pinned` differs from `head.pinned` only in the `service` entry; the author's own wrap is the only new one and the rest are re-randomised over the same `M` (R4/R5). This is operational-key rotation. It needs no backup ceremony because the operational key is already a recipient — it cannot gain anything by this record that it does not already have.
- **S2 (server)** The submitting connection's EndpointId MUST equal `author`, except `recovery`, which MAY be submitted by a service admin over the wire or locally with the service stopped. Audit rows then read cleanly: the submitter is the signer.

### 3.4 Governance rules

- **G1 admin implies read.** Every `acl` entry with the admin bit MUST have the read bit. Rationale: every key operation an admin exists for (adding a reader, rotating, kicking) needs `M`; an admin that cannot open the group cannot do any of them and would be an "admin" only in name. This changes today's independent bits for exactly one combination (`admin` without `read`); migration adds `read` to such rows and audits it. Alternative, if the user prefers to keep the bits independent: replace G1 by "author of `acl`-with-new-reader and of `rotate` MUST hold read in `head.acl`", accepting that such admins can only edit `w`/`a` bits. Recommended: G1.
- **G2 last admin.** `acl` MUST contain at least one admin. Applies to every kind including `recovery` (a recovery that leaves no admin would need a second ceremony to be useful) and `genesis`.
- **G3 no silent read removal.** An `acl` epoch MUST satisfy `readers(rec) ⊇ readers(head)` and `pinned == head.pinned`. Taking read away from anyone is a `rotate` (fresh `M`, re-encryption). Rationale: after an `acl` epoch every reader of the previous epoch still knows `M`; leaving them out of `wraps` while keeping `M` would be revocation theatre, and a replica that saw such a record would treat the identity as revoked while it can still decrypt everything.
- **G4 pinned set is immutable except by recovery** (and the service entry by `service-rekey`). A `rotate` MUST carry `pinned == head.pinned`. The backup key is therefore in every generation's recipient set by construction: no admin can author a record that the operator cannot open, and R2 + R3 make a sabotaged backup wrap impossible rather than merely detectable at disaster time.
- **G5 self-promotion**: impossible by A2 — an author must already be an admin in the previous epoch, and there is nothing above admin. An admin MAY give itself the write bit; today's admins can already grant themselves anything.
- **G6 self-removal**: an admin MAY drop its own admin bit (to `rw`, `w`, or out entirely) subject to G2, and dropping its own read bit is a `rotate` like any other read removal (G3). Rationale for allowing it: forced resignation-by-ceremony helps nobody.
- **G7 reviving a kicked key**: no rule. A later `acl` epoch by any admin MAY re-add it; it receives the current `M` and, because everything is re-encrypted on each rotate, it reads current data and retained history alike — exactly like a brand-new reader. What it can never do is *replay* the epoch in which it was still a recipient: C2/C3 and P2 refuse anything that does not extend the head.
- **G8 mode E only**: if `pinned` has no `service` entry, every `acl` entry with the write bit MUST have the read bit — without the DEK a writer cannot produce ciphertext (section 6).

### 3.5 Admin kicks admin — options and the recommended default

Today (`server.rs::grant`) any group admin can already set another admin to `perms = 0`; only the *last* admin bit is guarded. So "single compromised admin key = takes the group" is the status quo, and the service admin's implicit root is how it is undone. The options for the chain:

| Option | Rogue admin can | Legit admins can | Cost |
|---|---|---|---|
| **Forbid** (an `acl`/`rotate` MUST NOT clear another key's admin bit) | read everything, add readers, rotate, but not lock others out | not remove a compromised peer either — only the backup ceremony can | rogue key keeps *silent, persistent* read until the ceremony |
| **Allow** (recommended) | lock the others out in one epoch, loudly and attributably | recover via the backup key (section 5), or via a surviving admin if the rogue forgot one | lockout is possible, but visible in the chain and reversible |
| **k-of-n co-signatures** (`cosigs` list; threshold in the record; changing the threshold needs the old threshold) | nothing alone once threshold ≥ 2 | need to collect signatures over the exact canonical bytes before submit | a propose/sign workflow, a pending-epoch store on the server, degenerate for 1–2 admin groups; every rotate, not just kicks, becomes multi-party |
| **Service-admin or backup co-signature** | nothing alone | need the operator for every kick | the backup key is offline (ceremony per kick); the service-admin flag is not chain-verifiable, so it would have to become a pinned `service-root` key — a new root the user did not ask for |

**Recommended default: allow**, because (a) it is the current semantics, (b) the damage a rogue admin key can do beyond what any rogue *reader* key already does is availability — lockout — and the chain makes it attributable (`author`) and reversible (recovery epoch), whereas "forbid" converts a loud, reversible event into silent persistent access, and (c) the two alternatives with co-signatures add a multi-party workflow that the ask does not require. Guards that ship with "allow": G2 (someone is always admin), G4 (the backup key can always open the group and author the fix), and audit/notification: the server SHOULD audit an epoch that clears any other key's admin bit with outcome `admin-removed` and operators SHOULD alert on it. Groups that want the co-signature model later can get it by a new `kind` without changing anything here; no field is reserved for it now (YAGNI).

### 3.6 What the service admin can and cannot do any more

| Capability | Today | New |
|---|---|---|
| Register / remove identities, toggle the flag | yes | yes, unchanged (registry, server-local) |
| Create groups | yes | yes: authorises `CreateGroup`; the genesis record is signed by the creator (A1) |
| Implicit admin on every group (grant, revoke, rotate) | yes | **no**. Cannot author epochs for groups it is not an admin of; `Grant`/`RotateDek` wire requests are answered `Failed{reason: "this bunker uses signed epochs"}` |
| Implicit read/write on every group | yes, through the operational key | mode S: yes, unchanged (the server holds the DEK and the flag is a server-side authorisation rule); mode E: **no** |
| Recover an orphaned / hijacked group | `db grant` with the service stopped | **no**; that is the backup key's recovery epoch (section 5). `db grant` is removed |
| `RemoveIdentity` | cascades ACL rows and rotates every readable group | removes the registry row; the server stops *serving* that key (transport-level denial, as today) but **cannot** remove it from any chain. The key stays a recipient until a group admin issues a `rotate`. The server SHOULD flag such groups (`ListGroups` gains an optional `stale_recipients` count; admins' tooling prompts) |

Rationale: the ask is that group admins act without the privileged party; making the flag chain-relevant would require pinning a service-root key, i.e. reintroducing the privileged party under another name. Policy option for the user: in mode S, service admins MAY keep themselves as explicit admins on groups where rogue-admin recovery without a ceremony is wanted; they are then ordinary recipients and can be kicked like anyone.

### 3.7 Epoch CAS, races and forks

- **S3 (server)** `SubmitEpoch` is evaluated under the store lock: C2/C3 against the *current* head. On mismatch the answer is `EpochConflict{head_epoch, head_hash}` and nothing changes. Two admins racing produce exactly one winner; the loser refetches the head, rebuilds (its ACL edits reapplied on top, its `M` regenerated if it was a rotate) and resubmits. There are no forks on the authoritative node.
- **S4 (server, rotate/recovery-with-rotate)** The staged ciphertext set for `(group, hash(rec))` MUST cover every `(name, version)` retained at the moment of the CAS check and MUST hash to `reencrypted`; staged rows for versions deleted meanwhile are ignored; uncovered versions (written between export and submit) are reported back as `Failed{reason: "uncovered: name@version, …"}` and the admin re-encrypts just those and resubmits. No write freeze is offered; the CAS loop is the concurrency control, as it is for `Put`.
- **Rollback / replay.** A replayed old record has `epoch ≤ head.epoch` and fails C2. A record from a different group fails on `group_id`. A rewound *authoritative database* (restore from an old snapshot) is now detected by every replica that has seen a later epoch (P2) — today's sync silently follows it (apply rule 3, "wrap blob differs → replace"). The operator resolves a legitimate restore with a recovery epoch (section 5).
- **Equivocation.** A hostile server can serve replica X a chain that diverges from the one it serves replica Y, as long as each branch is admin-signed and the divergence point is a real race loser it kept. Each replica individually sees a valid, monotone history; the fork is detectable only by comparing heads across replicas or with the admin who submitted. That is a liveness/consistency residual, not a forgery, and is out of scope (no gossip). The submitting admin's client SHOULD verify, on its next request, that the head it is served is its own record or a descendant of it.

### 3.8 Replica rules

- **P1** A replica MUST persist `(epoch, hash)` of the last accepted record per `group_id` and MUST verify every record it receives with E/C/R/A/G rules before applying anything from it.
- **P2** It MUST accept only records that extend its head, except a `recovery` record signed by its head's `backup` key with `epoch > head.epoch`, which re-roots the chain; the re-root MUST be audited (`sync-reroot`, target = group, outcome carries both hashes). A recovery record whose backup key is unknown to the replica (the backup key itself was rotated by a recovery it never saw) cannot be accepted; the operator drops the group locally and lets it resync from genesis.
- **P3** If the replica's own key is not in `wraps`, the group has been revoked for it: drop it locally, as today on `SyncDenied`.
- **P4** It MUST derive `DEK` from its own wrap and check `dek_commit` before decrypting anything; on mismatch it MUST keep the previous generation's material and refuse the record.
- **P5** The mirrored ACL MUST be taken from the accepted record, never from a server-supplied roster; identity *names* MAY be taken from the server (`identities` map in the `Group` message) and are display data.

## 4. What kick + rotate does to ciphertext, and how it stays atomic and attributable (brief item 3)

**Invariant: one generation per group.** After any accepted `rotate`, every retained `secret_version` of the group is encrypted under the new generation. There are no retained old DEKs, no per-version DEK mix, and a record carries wraps for exactly one `M`. This is the SOPS semantics the ask presumes ("roll the single random data key") and it is what makes a record small and the rules above simple: a kicked key's wraps are not merely deleted, the material they protected no longer exists in the database.

**Procedure (kick / explicit rotate / recovery-with-rotate), all client-side by the admin:**

1. `GroupEpochs{group, since}` → the chain tail; verify locally; derive current `DEK_old` from own wrap.
2. `ExportGroup{group, after}` (admin bit required; paginated) → every retained `(name, version, dek_gen, nonce, ciphertext, created_at, created_by, author?, put_sig?)`.
3. For each row: decrypt with `DEK_old` and `secret_aad(group, name, version, dek_gen_old)`, re-encrypt with `DEK_new` and `secret_aad(group, name, version, dek_gen_new)` and a fresh nonce; keep `created_at`, `created_by`, `author`, `put_sig` verbatim (a put signature is over the plaintext digest, so it survives re-encryption — section 6).
4. Build the record (`kind = rotate`, new `M`, `wraps` for the new recipient set, proof, `reencrypted` digest), sign.
5. `StageEpoch{group, epoch_hash, versions: […]}` repeatedly (≤ 4 MiB frames; the stage table is keyed by `(group, epoch_hash, submitter)` and expires after one hour).
6. `SubmitEpoch{group, record}` → `Ok` | `EpochConflict` | `Failed{uncovered…}`.

**Server commit (one SQLite transaction):** verify E/C/R/A/G; S1–S4; in mode S also S5: open own wrap, check `dek_commit`, decrypt every staged row with the new DEK and AAD and refuse the whole record if any fails (an admin cannot brick a mode-S group with garbage). Then: insert `group_epoch`; replace `(nonce, ciphertext, dek_version)` of every `secret_version` from the stage; insert the `group_dek` registry row for the new generation; delete the stage; audit `epoch-submit` (target `group@epoch#hash[..16]`); publish `Changed{group}`.

**History.** Retained versions are kept and re-encrypted, not dropped; rotation cost is proportional to the group's total retained ciphertext, which for this system's payloads (Kubernetes secrets, tokens) is small. A retention policy is a separate feature and is not proposed here.

**Attribution.** "Who last re-encrypted the secrets" = `author` of the latest record whose `dek_gen` differs from its predecessor's (`rotate`, `recovery` with rotate, or `genesis`). "Who last changed membership" = `author` of the head. Both are verifiable by anyone with the chain and no key.

## 5. Recovery path with the offline backup key

Triggers: hijack by a rogue admin, all admins lost their keys, suspected `service`-key compromise, authoritative database restored from a snapshot behind the replicas, backup key rotation.

1. Obtain the group's chain (`GroupEpochs` by any registered identity, or the SQLite file) and, when rotating, the export (ciphertext only — the backup key opens its own wrap; the plaintext never leaves the offline machine).
2. On the offline machine: build `kind = recovery`, `prev = hash(head)`, `epoch = max(head.epoch + 1, at)`, the intended `acl` (G1/G2 apply), `pinned` (may replace the backup entry — the *old* key signs, the *new* key is the recipient — and/or the service entry), and either the same `M` (pure membership fix; needs `M`, which the backup wrap yields) or a fresh `M` with a full re-encryption (compromise suspected).
3. Submit locally (`db submit-epoch --db … --record … --stage …`, service stopped) or hand the files to a service admin who submits over the wire (S2). The wire path is preferred for live systems; the local path for restores.

Why the unix-time jump in C3: a restored database is behind whatever replicas have seen; a recovery record numbered `restored_head + 1` would be rejected by them (P2). `max(head + 1, now)` is strictly greater than any counter the group can plausibly have reached and stays monotone across repeated recoveries; ordinary epochs continue from there. Normal epochs are still exactly `+1`.

The backup key is the group's root: whoever holds it can author any membership and read everything. That is already true today (it opens every DEK; with database access it can rewrite ACL rows). New, and explicit: it is the *only* root — no operator shell command reaches the chain without it.

## 6. Roles, deployment modes, threat-model delta (brief item 4)

### 6.1 Modes

The mode is the `pinned` set fixed at genesis; operationally a server-wide `meta.epoch_mode` decides what `CreateGroup` pins.

**Mode S — server is a recipient (recommended default, v1).** `pinned = {backup, service}`. `Get`/`Put`/`List` and the Go client work unchanged: the server derives the group DEK from its own wrap and caches it per `(group, dek_gen)`. Write-only identities work (the server encrypts). Service-admin implicit read/write persists. What is gained is verifiable, admin-authored, admin-attributed membership and rotation that the server cannot forge and replicas check; what is not gained is confidentiality against the operator, which was a stated non-goal already.

**Mode E — end to end.** `pinned = {backup}`. The server verifies, stores and relays; it holds no DEK. Additional requirements, specified so the pinned set can be chosen now but not built in v1: `Put` carries ciphertext (`PutSealed{group, name, expected_version, dek_gen, nonce, ciphertext, put_sig}`; the server rejects a `dek_gen` that is not the head's with `EpochConflict`); `Get` returns `SealedSecret{…, epoch_hash}`; G8 (write implies read); no service-admin implicit read; every client must be upgraded; the server can no longer verify staged ciphertext (S5 is skipped) so a malicious admin can install garbage — equivalent to `Put`ting garbage, which admins can do anyway.

### 6.2 Where each party sits

| Party | Holds | In the chain as | Can author |
|---|---|---|---|
| Group admin | own iroh key | `acl` entry `r?wa` (G1: with `r`) | `acl`, `rotate` |
| Reader | own iroh key | `acl` entry with `r`; recipient | nothing |
| Writer (mode S) | own iroh key | `acl` entry with `w`, no wrap | nothing; `Put` plaintext via server |
| Replica | own iroh key | reader | nothing; verifies everything |
| Service admin | own iroh key, flag in registry | nothing unless also granted | genesis (as creator); submits recovery on the operator's behalf |
| Server | endpoint key + `service` key | pinned `service` (mode S) | `service-rekey`; server-minted genesis (compat/migration) |
| Operator, offline | `backup` key | pinned `backup` | `recovery` |

### 6.3 Threat-model delta versus `design/crypto-design.md`

| Threat | Today | New (mode S unless noted) |
|---|---|---|
| **Hostile / compromised authoritative server** | Out of scope; can read everything, rewrite ACLs, forge `created_by`, feed replicas any roster | Still reads everything in mode S (not in mode E). **Cannot** forge membership, kicks or rotations for replicas or auditors: every record is admin-signed, and it holds no admin key. Can withhold records, serve a stale chain, equivocate between replicas, lie about names, and fabricate a *new* group under a server-minted genesis (harmless beyond what it can do already). With put signatures (6.5) it cannot forge per-version authorship either. |
| **Compromised admin key** | Reads the group if it had `r`; can strip any other admin except the last; service admin undoes it | Reads the group (G1 makes every admin a reader — a widening for the few `a`-without-`r` rows). Can lock everyone out, **loudly**: the record names it. Undone by recovery epoch or a surviving admin. The delta is where recovery lives (backup key, not the service-admin flag). |
| **Compromised reader key** | Reads its groups; after revocation, forward protection only; old ciphertext under old DEKs stays readable from any copy | Same until kicked. **After a `rotate`, a database or mirror snapshot taken later is opaque to it** — nothing in the database is under a generation it knew. Copies it took *before* the kick are unaffected (section 7). |
| **Stolen SQLite (authoritative)** | Opaque to non-recipients; readable by any reader/operational/backup key of the retained DEK versions | Same class, narrower: readable only by keys in the *current* record's `wraps` (plus old records' wraps for an `M` that protects nothing any more). Chain history — who was in, who was kicked, who did it — is now in the file in signed form; treat it as metadata of the same sensitivity as the ACL today. |
| **Stolen replica database** | Roster + ciphertext; ciphertext needs the replica key | Same, plus the chain history above. |
| **Replica lag / partition** | Serves last mirror, no staleness bound, silently follows a rewound authoritative node | Unchanged bound. **Cannot be fed a forged ACL**; **detects a rewound authoritative node** (P2) and holds its last verified state until a recovery record arrives. |
| **Database write access (operator)** | Out of scope: can roll back versions, redirect wraps to own key | Rolling back a *secret version* is still possible (CAS pointers are unauthenticated, as today). Redirecting wraps or editing membership is **not**: a record with the operator's key as an extra recipient fails R2/C4 on every replica and auditor. |
| **Compromised operational (`service`) key** | Reads everything; recovery re-wraps via backup key | Same read; can author `service-rekey` to hand itself to an attacker key — visible; fixed by a recovery epoch replacing the service entry plus a rotate. |
| **Compromised backup key** | Reads everything from any snapshot | Same, and can author recovery epochs. It was the root already; now it is the only one. |
| **Malicious admin sabotaging recoverability** (bad backup wrap) | Not possible today — the server mints wraps; would be possible in "age wraps + signature" | **Impossible by R2/R3/G4**, checked at submit by a party with no key. |

## 7. What the DLEQ buys over "keep age wraps, add an author signature" (brief item 6)

With age wraps + signature, a verifier without a key learns *who* produced the wrap set and *which recipients* are listed; it cannot learn whether the wraps agree. With ElGamal + DLEQ + signature it learns, in addition, that every listed recipient recovers the same `M`. Concretely:

| Property | age wraps + author signature | ElGamal + DLEQ + signature |
|---|---|---|
| Who authored the membership change / rotation | yes | yes |
| Hidden extra recipient | excluded by the signed recipient list | excluded (R2) |
| Recipient list vs wrap list agree | yes | yes |
| A listed recipient's wrap opens to the group DEK | only that recipient can tell, when it next decrypts | anyone, at submit time |
| The **offline backup key's** wrap opens to the group DEK | nobody can tell until disaster recovery is attempted | anyone, at submit time |
| Two recipients get different DEKs (split view) | possible; each victim sees "wrong key" (with a key-check value) or garbage (without) | impossible |
| Server can accept a rotation it cannot open (mode E) safely | no way to check what it stores | checks R2/R3 without a key |

So the proof pays for exactly one thing, and pays for it well: **the wrap set is validated by parties that hold no key, before it is accepted, for every recipient including the ones that never exercise their wrap** — the backup key first of all, then readers that are offline, then the server in mode E. Without it, the admin-driven design would move DEK wrapping from a trusted server to an untrusted admin with no check between them; the failure would surface at the worst moment (recovery day, or the first read by the targeted reader) and look like corruption, not like an attack.

What it does **not** buy, and no design here claims: anything about data already fetched or mirrored before a kick — a kicked reader keeps what it had, and the server-side re-encryption protects only *later* snapshots; forward secrecy — a recipient key leaked in the future opens every record it appears in, and since old records are kept (their signatures cover their wraps; pruning would break auditability), a leaked *old* reader key plus an *old* ciphertext snapshot decrypts that snapshot, which is exactly today's exposure; protection from a rogue admin, who is trusted for integrity in both designs; liveness against a withholding server; correctness of registry names.

Cost side of the ledger: `curve25519-dalek` becomes a direct dependency; ~200 lines of point arithmetic with the E3/E4 discipline (the only sharp edge, and it is a unit-testable one: feed a torsion-tweaked `c_i` and assert rejection); the backup and operational keys become Ed25519 (one ceremony); verification is 2+2n scalar multiplications per record. If the user's priority is only attribution and admin autonomy and they accept "a bad backup wrap is found at recovery time", the age-plus-signature variant is a legitimate cheaper answer; the recommendation here is the proof, because the property it adds is the one that is invisible until it matters.

### 7.1 Should puts be signed?

Recommended: yes, as an optional field, because it costs 64 bytes and makes per-version attribution survive both a hostile server and re-encryption. `Put` gains `sig` (backwards compatible: unknown fields are ignored; the Go client keeps sending none):

```
"secret-bunker-iroh/put/1" || group_id 32 || len(name) u64 || name || version u64 || SHA-256(plaintext) 32 || at i64
```

signed with the writer's endpoint key; `version` is `expected_version + 1`, or `1` when `expected_version = 0`. The server MUST verify it against the plaintext it received and refuse a mismatch; it stores `author` (32 bytes) and `put_sig` alongside `created_by`. A reader verifies after decryption. A re-encrypted version keeps `author`/`put_sig` unchanged (step 3 of section 4). Server-stamped `created_by` remains what it is today: a display name attested by the server, trustworthy exactly as far as the server is, and marked *verified* in responses only when a signature is present and checks. Signing the plaintext digest rather than the ciphertext is what lets mode S have this at all: the writer never sees the ciphertext.

## 8. Storage, protocol, migration (brief item 5)

**Schema (v3).**

```
group_epoch (group_id, epoch, hash BLOB, prev BLOB, kind, dek_gen, author BLOB, at, record BLOB, received_at,
             PRIMARY KEY (group_id, epoch))            -- full layout bytes in `record`
epoch_stage (group_id, epoch_hash BLOB, submitter, name, version, nonce, ciphertext, staged_at)
secret_group  + epoch_group_id BLOB UNIQUE            -- the 32-byte group_id
secret_version + author BLOB NULL, put_sig BLOB NULL  -- section 7.1
group_dek     unchanged; `version` == dek_gen (registry of generations, mode-S DEK cache key)
dek_wrap      legacy only; empty after migration; dropped in v4
meta          + backup_pubkey_ed25519, service_pubkey_ed25519, epoch_mode
```

**Client protocol (`secret-bunker/1`, additive).** New requests `GroupEpochs{group, since}` (any bit on the group), `ExportGroup{group, after}` (admin), `StageEpoch{group, epoch_hash, versions}` (admin), `SubmitEpoch{group, record}` (author, S2); new responses `Epochs{epochs: [bytes], identities: [(endpoint_id, name)]}`, `Export{versions, next}`, `EpochConflict{head_epoch, head_hash}`. `Put` gains optional `sig`; `Secret` gains optional `created_by`, `author`, `verified`. `Grant` and `RotateDek` answer `Failed` on an epoch-mode bunker. `CreateGroup` gains optional `genesis: bytes`; absent, mode S mints one (A1). An old client that sends a new request to an old server gets the uniform `Denied`, which is the existing rule for undecodable frames.

**Sync (`secret-bunker-sync/2`).** `Group` drops `deks` and gains `epochs: [bytes]` (records since the replica's head; the whole chain on first sight) and `identities`; `acl` is dropped — a replica MUST take the ACL from the verified head (P5). Apply rules 1–2 read from the record; rule 3 becomes "derive own DEK, check `dek_commit`, insert the `group_dek` row"; rules 4–5 unchanged. `SecretData` gains `author`, `put_sig`. `ScopeChanged` and `Changed` unchanged. Mixed-version pairs fail at ALPN, as the compatibility section of the sync spec already prescribes.

**Migration (`db migrate-epochs`, run once with the service stopped, or automatically at first `serve` of the new binary).**

1. Operator generates the `backup` Ed25519 key offline and the `service` Ed25519 key for the server; records both public keys in `meta`. The age keys stay valid for pre-migration database backups and are otherwise retired.
2. Per group, in one transaction: unwrap the retained DEK versions with the operational age key; pick `M`; re-encrypt every retained `secret_version` under `dek_gen = 1` (the one-generation invariant from day one); build `genesis` with `acl` = today's `group_acl` with G1 applied (`a` ⇒ `r`, audited as `migrate-admin-read`), `pinned` per `epoch_mode`, `author = service` key (A1); insert the record; delete the group's `dek_wrap` rows; audit `epoch-genesis`.
3. Replicas: a v1 mirror cannot follow a v2 authoritative node (ALPN); upgrade replicas, which resync from genesis. The operator embedding the replica engine is upgraded in the same release.

Alternative for step 1 the user may prefer: derive the Ed25519 public points from the *existing* age secrets (`clamp(secret)·B`), keeping one backup key. It works for decryption but the backup and service keys must also *sign* (recovery, service-rekey), which needs an Ed25519 expanded key built from a raw scalar via dalek's hazmat API. Fresh keys avoid that; recommended.

## 9. Summary of rules by verifier

| Rule | Server | Replica | Auditor |
|---|---|---|---|
| E1–E4 layout, canonical points, torsion-free, no cofactor clearing | ✓ | ✓ | ✓ |
| C1–C4 genesis, chain continuity, recovery jump, signature | ✓ | ✓ (+P2 re-root) | ✓ |
| R1–R5 pinned shape, exact recipient set, DLEQ, generation continuity | ✓ | ✓ | ✓ |
| A1–A4 authorship by kind, from the previous epoch's ACL | ✓ | ✓ | ✓ |
| G1–G8 admin⇒read, last admin, no silent read removal, immutable pinned, mode-E write⇒read | ✓ | ✓ | ✓ |
| S1 caller is service admin (genesis), keys are registered | ✓ | — | — |
| S2 submitter == author (recovery: service admin or local) | ✓ | — | — |
| S3 CAS on head under the store lock | ✓ | — | — |
| S4 staged set covers all retained versions, digest matches | ✓ | — | — |
| S5 mode S: own wrap opens, `dek_commit` matches, every staged ciphertext decrypts | ✓ | — | — |
| P1–P5 persisted head, extend-or-reroot, own wrap present, `dek_commit`, ACL from record | — | ✓ | — |

## Key decisions

- Hash and signature are over a fixed binary layout with a magic prefix, not canonical CBOR; CBOR remains the wire/storage container only.
- Multi-recipient ElGamal on Edwards25519 with one batched Chaum-Pedersen proof (single k, single (e,s), 64 bytes); verification is exact in the full group with canonical-encoding, non-identity and torsion-free checks on every point, and no cofactor multiplication. Ristretto is not used because recipient keys are Ed25519 points.
- DEK and dek_commit are both HKDF outputs of M salted by a random 32-byte group_id chosen at genesis (avoids the circular dependency on the genesis hash); ChaCha20-Poly1305 stays as is, no key-committing AEAD needed.
- One DEK generation per group at all times: every rotate (kick, explicit rotate, recovery-with-rotate) re-encrypts all retained secret versions client-side; old wraps are not merely deleted, the material they protected no longer exists in the database. Old epoch records are kept in full (no pruning) for auditability.
- Atomicity via a staging protocol (StageEpoch chunks keyed by epoch hash, then SubmitEpoch) with CAS on the head under the store lock; uncovered versions written mid-rotation are reported and re-encrypted incrementally, no write freeze.
- Authorship: acl/rotate epochs must be signed by an admin of the PREVIOUS epoch's ACL; genesis by the creator (or the pinned service key for server-minted compat/migration); recovery only by the pinned backup key; service-rekey only by the pinned service key and may change nothing but its own entry.
- G1: admin implies read (verifier-enforced), because every admin operation requires knowing M; migration adds read to the few admin-without-read rows and audits it.
- G3: an acl epoch may never drop a reader; any read removal is a rotate with fresh M. Pinned set is immutable except by a recovery epoch (service entry also by service-rekey); the backup key is a recipient of every generation by construction.
- Admin-kicks-admin default: ALLOW (it is today's semantics), guarded by last-admin, immutable pinned set, and an admin-removed audit outcome; forbid / k-of-n / service-or-backup co-signature are documented and rejected for v1.
- The service-admin flag stays a server-side registry concept: it no longer has implicit group-admin power, cannot author epochs, and `db grant` is removed; orphan/hijack recovery is exclusively the backup key's recovery epoch. In mode S its implicit read/write via the server persists. RemoveIdentity becomes transport-level denial plus a stale-recipient flag; cryptographic revocation is a group admin's rotate.
- Recovery epochs may jump the epoch number (max(head+1, unix now)) so a restored authoritative database can be re-rooted at replicas; replicas persist their head, accept only extending chains, and accept a re-root only from their head's pinned backup key with a higher epoch number.
- Backup and operational keys become fresh Ed25519 keys (iroh SecretKey format); the age keys are retired to pre-migration backups. Migration re-encrypts every group into generation 1 with a server-minted genesis.
- Mode S (server pinned as recipient) is the v1 default so Get/Put/Go client/write-only identities/service-admin implicit read keep working; mode E is specified by the pinned set and its extra rules (write implies read, sealed puts) but not built.
- Put signatures over (group_id, name, version, SHA-256(plaintext), at) are recommended as an optional backward-compatible field: verifiable by readers after decryption, survive re-encryption, and make created_by a verified claim rather than a server attestation.
- Legacy Grant/RotateDek wire requests are refused with Failed on an epoch-mode bunker rather than being silently server-authored; sync bumps to secret-bunker-sync/2 with the Group message carrying the epoch chain and replicas taking the ACL only from the verified head.

## Risks

- Rotation cost is proportional to the group's total retained ciphertext and flows through the admin's client; a group with heavy concurrent writes could make the export/stage/submit CAS loop retry repeatedly (no write freeze is offered).
- Recovery from a rogue or lost admin key now requires the offline backup-key ceremony where today a service admin fixes it over the wire; operational burden and time-to-recover increase, and loss of the backup key means no chain-level recovery at all.
- RemoveIdentity no longer revokes cryptographically: a removed identity remains a recipient in every chain until a group admin rotates; a removed replica keeps decrypting new pushes only if it can still connect, but the exposure window depends on admin diligence.
- Cofactor and canonical-encoding discipline (E3/E4) is the one sharp edge of the crypto; a single missed check (e.g. cofactor clearing, non-canonical point accepted) reopens the split-view attack. Needs explicit negative tests.
- A hostile authoritative server can still equivocate between replicas and withhold epochs; nothing in the design cross-checks heads between replicas or with the submitting admin.
- The unix-time epoch jump for recovery records is a pragmatic hack; ordering breaks if a group ever legitimately exceeds ~1.7e9 epochs or if a recovery is issued on a badly skewed clock earlier than a previous recovery.
- Migration is a one-shot full re-encryption of every group at first boot of the new binary, with the sync ALPN bumped: authoritative node, all replicas and the Kubernetes operator must be upgraded in lockstep, and the operator must have generated two new Ed25519 keys beforehand.
- The Go client's Grant/RotateDek calls (if any are used) start returning Failed; Get/Put/List are unaffected.
- Signed epoch chains put the full membership history (who was kicked, when, by whom) into every replica database and the authoritative file; this is a metadata widening relative to today's current-roster-only disclosure.
- G1 (admin implies read) widens read access for any existing admin-without-read rows; if the user rejects G1 the alternative rule leaves such admins unable to add readers or kick.
- Reusing the Ed25519 signing scalar for ElGamal decryption is the same joint-use class the age bridge already relies on, but the analysis cited covers hashed DH KEMs; the design hashes M via HKDF to stay in that class, and this should be reviewed by whoever owns the crypto sign-off.

## Open questions for the user

- Accept G1 (admin implies read, verifier-enforced) or keep the bits independent with the weaker rule that only read-holding admins may add readers or rotate?
- Confirm the admin-kicks-admin default of ALLOW (status quo, loud and reversible via the backup key) over forbid or k-of-n co-signatures.
- Confirm that the service-admin flag loses implicit group-admin power and that `db grant` is removed, with the backup-key recovery epoch as the only orphan/hijack recovery path. Should service admins be automatically added as explicit admin recipients at genesis in mode S (they would then hold key material and be kickable like anyone)?
- Fresh Ed25519 backup and operational keys (recommended, one ceremony), or derive Edwards public keys from the existing age X25519 secrets and sign with a hazmat-constructed expanded key to keep a single backup key?
- Is mode S (server remains a recipient; Go client, write-only identities and service-admin implicit read keep working) the intended v1 deployment, with mode E deferred?
- Refuse legacy Grant/RotateDek with Failed on an epoch-mode bunker, or is a transition flag that lets the server author epochs with the service key (weaker attribution) needed for a rollout period?
- Is the recovery-epoch numbering rule max(head+1, unix_now) acceptable for re-rooting replicas after an authoritative restore, or would you rather have replicas be manually re-initialised after a restore?
- Include put signatures (optional Put.sig over the plaintext digest, verified by the server and by readers) in v1, or defer to a follow-up?
- Rotate re-encrypts all retained history versions (SOPS semantics, recommended for the one-generation invariant); do you want a retention/prune option alongside it, or is that a separate feature?
- Keep every old epoch record in full (auditability; small) despite it recording the complete membership history in every replica, or prune wraps of superseded generations and keep only hashes?
