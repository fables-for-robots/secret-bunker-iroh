# Probe results (throwaway; curve25519-dalek 5.0.0 / ed25519-dalek 3.0.0, real Ed25519 keys, Apple Silicon, release build)

Two runs were made on 2026-09-07. The first probe implemented the shared-randomness
construction from the brief (one `r`, one batched Chaum-Pedersen response); the second
(`src/main.rs` as kept here) implements the per-recipient-randomness construction the
spec adopts and demonstrates why.

## Run 1 — shared randomness `c0 = r·B`, `c_i = M + r·A_i`, one batched (e, s)

```
OK  honest epoch: batched proof verifies, all 5 readers recover the same M
OK  different M for one reader: rejected even without torsion checks
OK  torsion grinding on c_j: passes WITHOUT torsion checks after 10 tries, reader 2 gets M+T (a different DEK); torsion-free check rejects it
OK  torsion in c0: passes WITHOUT torsion checks after 1 tries; clamped readers unaffected=false; a non-clamped reader would recover M: false
OK  swapped c_i between recipients: rejected
OK  n=1: proof still verifies (Schnorr on c0)
!!  duplicate recipient with a different M in the duplicate slot verifies=false (must be rejected by a duplicate check)
OK  50 recipients: prove 1.321125ms, verify 4.438208ms
```

Notes:
- Readers decrypt with `c_i − SigningKey::to_scalar()·c0`; dalek's `to_scalar()` is the
  clamped scalar reduced mod ℓ, and `vk == to_scalar()·B` holds.
- Torsion in `c0`: with dalek's mod-ℓ-reduced scalars, clamping does NOT annihilate the
  torsion, so even clamped readers recover a wrong `M`. The torsion-free check on every
  point is therefore load-bearing, not defense in depth.
- The difference-based batched proof already forces a duplicate recipient's `c_i` to equal
  the anchor's; duplicates are still rejected for ACL hygiene.

## Run 2 — per-recipient randomness (the adopted construction)

```
!!  SHARED r: registering A' = -A_v (sign-bit flip of a hex id) lets ANYONE compute M = (c_v + c')/2 from the public record
!!  SHARED r: A' = A_u + A_v leaks M = c_u + c_v - c'  (c0 shared = 5e304a34)
OK  PER-RECIPIENT r_i: c_v + c' - 2M = (r_v - r')*A_v, a fresh DH value; no leak without a recipient scalar
OK  per-recipient: proof (e + 5 responses = 192 bytes) verifies; all readers recover M
OK  per-recipient: different M for one reader rejected
OK  per-recipient: torsion grinding passes without checks (9 tries), rejected with is_torsion_free
OK  identity-point recipient publishes M verbatim -> must be rejected at registration and verification
OK  per-recipient: duplicate recipient with different M verifies=false (rejected: relation forces equal M)
OK  per-recipient, 50 recipients: prove 5.332875ms, verify 12.167708ms (incl. torsion checks)
```

Conclusion carried into the spec (D1): with a shared nonce, a registered key that is an
affine function of another reader's key makes `M` computable by everyone from the
public record with a valid proof; independent randomness per recipient closes this by
construction at the cost of 64 bytes per recipient and about 2× the millisecond-scale
verification time.

## Dependency note

`curve25519-dalek 5` uses `digest 0.11` / `rand_core 0.10`; the repository pins
`sha2 0.10` / `rand 0.8`. Feed hashes and randomness in as bytes via
`Scalar::from_bytes_mod_order_wide(&[u8; 64])`, and build `SigningKey::from_bytes`
from iroh's secret bytes, to avoid the trait-version coupling.
