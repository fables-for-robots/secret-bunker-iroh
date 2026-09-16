# Brief: verifiable, admin-driven DEK rotation for secret-bunker-iroh

This is the brief that was handed to the design panel (four independent designers,
twelve adversarial critics, one completeness critic). Repository paths are relative
to the repository root.

## 1. The ask (verbatim from the user)

> I would like to design a system that uses Chaum-Pedersen/DLEQ allowing for all
> admins on the group to 'kick out' other users and roll the single random data key
> without the need for the master admin to do that. It will also give us an idea who
> was the last one to 're-encrypt' the secrets.

"Master admin" is not a term in this codebase. Read it as: the party that today
holds the privileged key material and does the re-keying on everyone's behalf — the
server process with its *operational* age key (and, by extension, the service
admin / operator). The user wants group admins to be able to do the kick + re-key
themselves, with their own iroh key, and wants the result to be publicly verifiable
and attributable.

## 2. Background the user shared (paraphrased)

1. In SOPS, a single random data key encrypts the body; that data key is wrapped
   separately for every master key. Anyone holding any one master key can decrypt
   everything, rewrite any value, re-encrypt, and produce a valid new version; the
   integrity MAC is keyed by the data key, so it is recomputable. A "different
   plaintext per recipient" attack is impractical (AES-GCM is not key-committing,
   so one ciphertext can verify under two keys, but the attacker chooses only one
   plaintext; the other side gets garbage). The real weakness: every key holder is a
   fully trusted, *anonymous* author.
2. On Ed25519 (iroh) keys, a generic ZK proof that every recipient can decrypt the
   same data key is a slog (curve arithmetic inside a circuit, per recipient).
   Instead, make the wrap algebraic — multi-recipient ElGamal with shared
   randomness: pick random scalar r and random point M; publish c0 = r·G and, per
   recipient, c_i = M + r·pk_i. Derive DK = H(M). Encrypt the body with a
   key-committing AEAD or append H(DK) so a wrong key fails loudly. For each i > 1,
   publish a DLEQ (Chaum-Pedersen) proof that log_G(c0) = log_{pk_i − pk_1}(c_i − c_1).
   Anyone — including a party with no key — can then check every c_i hides the same
   M under the same r, hence the same DK, hence identical plaintext for everyone.
   Prover cost: a handful of scalar mults; ~64 bytes of proof per recipient.
   Caveats: do it on the Edwards form directly (skip the Montgomery conversion) and
   deal with the cofactor — use Ristretto for the ephemeral/M points, or multiply by
   8 / check subgroup membership, since a small-subgroup component would let the
   DLEQ pass while the decrypted M differs by a torsion point.
3. The part worth more than the proof: sign the canonical (metadata + ciphertext)
   bytes with the writer's node key so every reader can verify who produced the
   version. Combined: "written by node X, and every listed recipient decrypts the
   same thing."

## 3. The current system (the ground truth the panel read)

- `README.md` — overview.
- `design/crypto-design.md` — full crypto design, threat model, non-goals. Key
  facts: per-group DEK (ChaCha20-Poly1305, AAD binds (group, name, version,
  dek_version)); DEK versions are retained (old secret versions stay under old
  DEKs; rotation does NOT re-encrypt existing ciphertext); each DEK version is
  wrapped with **age** (X25519) to three kinds of recipients: `operational`
  (server, online, serves plaintext reads), `backup` (offline age key, disaster
  recovery), and every identity holding an explicit `read` grant (age recipient
  derived from its Ed25519 EndpointId via Edwards→Montgomery, `src/agebridge.rs`).
  Revoking `read` deletes that identity's wraps and auto-rotates the DEK in one
  transaction. Granting `read` to a new identity re-wraps every retained DEK
  version to it — which needs the operational key to unwrap them first.
- `docs/protocol.md` — client wire protocol (CBOR, externally tagged enums; variant
  and field NAMES are the contract; a Go client exists and must keep working).
- `docs/sync-protocol.md` — read-only replicas mirror groups they hold `read` on:
  the `Group` message carries the full ACL roster and the caller's own DEK wraps;
  replicas authorize their own clients from the mirrored ACL and decrypt with the
  age identity derived from their own endpoint key. Replicas TRUST the
  authoritative node for the ACL today.
- `src/crypto.rs`, `src/agebridge.rs`, `src/store.rs`, `src/server.rs`,
  `src/replica.rs`, `src/sync.rs` — implementation.
- Authorization today: group `admin` may edit the group's ACL and rotate its DEK
  (server does the crypto). The **service admin** flag is root: implicit
  read|write|admin everywhere, registers identities, creates groups, removes
  identities. A `Grant` that would leave a group with no admin is refused;
  `RemoveIdentity` is never blocked. Recovery path for an orphaned group: local
  `db grant` with the service stopped.
- Deployed: one authoritative bunker; a Kubernetes operator embeds the replica
  engine and renders k8s Secrets from its mirror (needs ONLY its own endpoint key).
- Dependencies available: ed25519-dalek 3 (re-exports curve25519-dalek 5), age
  0.11, chacha20poly1305 0.10, sha2 0.10, ciborium, serde_bytes, zeroize, iroh 1.

## 4. Preliminary design skeleton handed to the panel (attack, improve or replace)

The unit of key management becomes a signed, self-verifying **epoch record** per
group, replacing today's server-minted age wraps: `{group_genesis, epoch, prev,
acl, pinned, c0, wraps, proof (batched Chaum-Pedersen), dek_commit, reencrypted,
author, at, sig}`; DEK = HKDF(M, group); verification needs no key (encodings,
torsion-free points, proof, author ∈ admins(head), pinned recipients present,
readers ⊆ wraps, chain continuity, signature); operations (kick/rotate = new M +
re-encrypt every retained version; add reader = same M re-wrapped; ACL edit =
wraps carried verbatim) are all client-side by a group admin holding read; the
server verifies and serializes (CAS), never needs a private key to accept a
rotation; replicas verify the chain themselves.

Known tensions listed for the panel: admin must hold read to rotate; write-only
identities in an E2E mode; admin-kicks-admin and last-admin; how the offline
backup key participates (age X25519 today vs Ed25519 for ElGamal); granting a new
reader without the operational key; client-side re-encryption bandwidth and
atomicity; service-admin "root" semantics; migration from age wraps; sync-protocol
changes.

## 5. What every design had to answer

1. The exact wrapping + proof scheme and verification algorithm, with the security
   argument (what is proven, under what assumption, and what is NOT proven).
2. Who may do what (authorization rules the verifier enforces), including the
   admin-kicks-admin question and last-admin/lockout, with a recommended default.
3. What "kick + roll the data key" does to existing ciphertext and how the
   operation is made atomic and attributable.
4. How the server, the offline backup key, service admins, replicas, and write-only
   identities fit; which deployment modes exist; what the threat model gains/loses.
5. Storage, protocol, and migration changes, in enough detail to be planned.
6. Trade-offs vs. the simpler alternative "keep today's age wraps and just add an
   author signature" — what does the DLEQ actually buy here?
