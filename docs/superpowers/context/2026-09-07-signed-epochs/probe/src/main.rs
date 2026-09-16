//! THROWAWAY numeric probe (kept as context for the signed-epochs spec):
//! (1) the related-key leak of multi-recipient ElGamal with SHARED randomness;
//! (2) the per-recipient-randomness variant with an AND-composed Chaum-Pedersen
//!     proof (one challenge, n responses) — the construction the spec adopts;
//! (3) the negative cases every verifier must reject (torsion grinding, identity
//!     recipient, different M for one reader, duplicate recipient);
//! (4) a cost measurement for 50 recipients.
//!
//! Real Ed25519 keys are used throughout: a reader decrypts with
//! `SigningKey::to_scalar()` (the clamped scalar reduced mod l), exactly as the
//! spec prescribes.
use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT as B, EIGHT_TORSION};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};

// curve25519-dalek 5 binds Scalar::random / from_hash to rand_core 0.10 / digest
// 0.11 while this probe (like the repo) pins rand 0.8 / sha2 0.10: feed bytes in.
fn rand_scalar() -> Scalar { let mut b = [0u8; 64]; OsRng.fill_bytes(&mut b); Scalar::from_bytes_mod_order_wide(&b) }
fn rand_seed() -> [u8; 32] { let mut b = [0u8; 32]; OsRng.fill_bytes(&mut b); b }

/// Per-recipient randomness: wrap_i = (c0_i = r_i*B, c_i = M + r_i*A_i)
struct Epoch { pks: Vec<EdwardsPoint>, c0: Vec<EdwardsPoint>, cs: Vec<EdwardsPoint>, e: Scalar, s: Vec<Scalar> }

fn challenge(pks: &[EdwardsPoint], c0: &[EdwardsPoint], cs: &[EdwardsPoint], t: &[EdwardsPoint], v: &[EdwardsPoint]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"secret-bunker-iroh/epoch-proof/v2");
    h.update((pks.len() as u32).to_be_bytes());
    for i in 0..pks.len() { h.update(pks[i].compress().as_bytes()); h.update(c0[i].compress().as_bytes()); h.update(cs[i].compress().as_bytes()); }
    for p in t { h.update(p.compress().as_bytes()); }
    for p in v { h.update(p.compress().as_bytes()); }
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

fn prove(pks: &[EdwardsPoint], c0: &[EdwardsPoint], cs: &[EdwardsPoint], rs: &[Scalar]) -> (Scalar, Vec<Scalar>) {
    let ks: Vec<Scalar> = (0..pks.len()).map(|_| rand_scalar()).collect();
    let t: Vec<_> = ks.iter().map(|k| k * B).collect();
    let v: Vec<_> = (1..pks.len()).map(|i| ks[i] * pks[i] - ks[0] * pks[0]).collect();
    let e = challenge(pks, c0, cs, &t, &v);
    (e, ks.iter().zip(rs).map(|(k, r)| k + e * r).collect())
}

fn verify(ep: &Epoch, torsion_checks: bool) -> bool {
    let n = ep.pks.len();
    if ep.s.len() != n || ep.c0.len() != n || ep.cs.len() != n { return false; }
    if torsion_checks {
        for p in ep.pks.iter().chain(&ep.c0).chain(&ep.cs) { if !p.is_torsion_free() || p.is_identity() { return false; } }
    }
    let t: Vec<_> = (0..n).map(|i| ep.s[i] * B - ep.e * ep.c0[i]).collect();
    let v: Vec<_> = (1..n).map(|i| ep.s[i] * ep.pks[i] - ep.s[0] * ep.pks[0] - ep.e * (ep.cs[i] - ep.cs[0])).collect();
    challenge(&ep.pks, &ep.c0, &ep.cs, &t, &v) == ep.e
}

fn decrypt(sk: &SigningKey, c0: &EdwardsPoint, c: &EdwardsPoint) -> EdwardsPoint { c - sk.to_scalar() * c0 }

fn main() {
    let n = 5;
    let sks: Vec<SigningKey> = (0..n).map(|_| SigningKey::from_bytes(&rand_seed())).collect();
    let pks: Vec<EdwardsPoint> = sks.iter().map(|k| k.verifying_key().to_edwards()).collect();
    let big_m = rand_scalar() * B;

    // ---- (1) SHARED randomness: related-key leak. Attacker registers A' = -A_v (no secret needed).
    let r = rand_scalar();
    let c0_shared = r * B;
    let neg = -pks[1];
    let c_v = big_m + r * pks[1];
    let c_neg = big_m + r * neg;
    let two_inv = Scalar::from(2u64).invert();
    let leaked = (c_v + c_neg) * two_inv;
    assert_eq!(leaked, big_m);
    println!("!!  SHARED r: registering A' = -A_v (sign-bit flip of a hex id) lets ANYONE compute M = (c_v + c')/2 from the public record");
    let sum = pks[1] + pks[2];
    let c_sum = big_m + r * sum;
    let c_u = big_m + r * pks[2];
    assert_eq!(c_v + c_u - c_sum, big_m);
    println!("!!  SHARED r: A' = A_u + A_v leaks M = c_u + c_v - c'  (c0 shared = {})", hex::encode(c0_shared.compress().as_bytes())[..8].to_string());

    // ---- (2) PER-RECIPIENT randomness: same related keys, no algebraic cancellation.
    let rs: Vec<Scalar> = (0..3).map(|_| rand_scalar()).collect();
    let keys = [pks[1], pks[2], neg];
    let c0s: Vec<_> = rs.iter().map(|r| r * B).collect();
    let cs: Vec<_> = keys.iter().zip(&rs).map(|(a, r)| big_m + r * a).collect();
    let _ = c0s;
    // The attacker's best algebra: (c_v + c') = 2M + (r_v - r')*A_v ; without r's this is a DH value.
    let residual = cs[0] + cs[2] - big_m - big_m;
    assert_eq!(residual, (rs[0] - rs[2]) * pks[1]);
    println!("OK  PER-RECIPIENT r_i: c_v + c' - 2M = (r_v - r')*A_v, a fresh DH value; no leak without a recipient scalar");

    // ---- honest per-recipient epoch + AND-composed proof
    let rs: Vec<Scalar> = (0..n).map(|_| rand_scalar()).collect();
    let c0: Vec<_> = rs.iter().map(|r| r * B).collect();
    let cs: Vec<_> = pks.iter().zip(&rs).map(|(a, r)| big_m + r * a).collect();
    let (e, s) = prove(&pks, &c0, &cs, &rs);
    let ep = Epoch { pks: pks.clone(), c0: c0.clone(), cs: cs.clone(), e, s: s.clone() };
    assert!(verify(&ep, true));
    for (i, sk) in sks.iter().enumerate() { assert_eq!(decrypt(sk, &c0[i], &cs[i]), big_m); }
    println!("OK  per-recipient: proof (e + {n} responses = {} bytes) verifies; all readers recover M", 32 * (n + 1));

    // different M for one reader
    let mut bad = cs.clone(); bad[2] = rand_scalar() * B + rs[2] * pks[2];
    assert!(!verify(&Epoch { pks: pks.clone(), c0: c0.clone(), cs: bad, e, s: s.clone() }, false));
    println!("OK  per-recipient: different M for one reader rejected");

    // torsion grinding on c_j: add an 8-torsion point and regrind until 8 | e
    let t = EIGHT_TORSION.iter().find(|p| !(*p * Scalar::from(4u64)).is_identity()).copied().unwrap();
    let mut cs_t = cs.clone(); cs_t[2] = cs[2] + t;
    let mut tries = 0;
    let ground = loop {
        tries += 1;
        let ks: Vec<Scalar> = (0..n).map(|_| rand_scalar()).collect();
        let tt: Vec<_> = ks.iter().map(|k| k * B).collect();
        let v: Vec<_> = (1..n).map(|i| ks[i] * pks[i] - ks[0] * pks[0]).collect();
        let e = challenge(&pks, &c0, &cs_t, &tt, &v);
        if (e * t).is_identity() { break Epoch { pks: pks.clone(), c0: c0.clone(), cs: cs_t.clone(), e, s: ks.iter().zip(&rs).map(|(k, r)| k + e * r).collect() }; }
        if tries > 10_000 { panic!() }
    };
    assert!(verify(&ground, false) && !verify(&ground, true));
    println!("OK  per-recipient: torsion grinding passes without checks ({tries} tries), rejected with is_torsion_free");

    // identity recipient: c = M + r*O = M, public. Must be rejected.
    let id_pk = EdwardsPoint::identity();
    assert_eq!(big_m + rand_scalar() * id_pk, big_m);
    println!("OK  identity-point recipient publishes M verbatim -> must be rejected at registration and verification");

    // duplicate recipient with different M in the duplicate slot
    let dpks = vec![pks[0], pks[0]]; let drs = vec![rand_scalar(), rand_scalar()];
    let dc0: Vec<_> = drs.iter().map(|r| r * B).collect();
    let dcs = vec![big_m + drs[0] * pks[0], rand_scalar() * B + drs[1] * pks[0]];
    let (de, ds) = prove(&dpks, &dc0, &dcs, &drs);
    println!("OK  per-recipient: duplicate recipient with different M verifies={} (rejected: relation forces equal M)", verify(&Epoch { pks: dpks, c0: dc0, cs: dcs, e: de, s: ds }, true));

    // timing 50 recipients
    let n2 = 50;
    let pks2: Vec<EdwardsPoint> = (0..n2).map(|_| SigningKey::from_bytes(&rand_seed()).verifying_key().to_edwards()).collect();
    let rs2: Vec<Scalar> = (0..n2).map(|_| rand_scalar()).collect();
    let c02: Vec<_> = rs2.iter().map(|r| r * B).collect();
    let cs2: Vec<_> = pks2.iter().zip(&rs2).map(|(a, r)| big_m + r * a).collect();
    let t0 = std::time::Instant::now();
    let (e2, s2) = prove(&pks2, &c02, &cs2, &rs2);
    let tp = t0.elapsed();
    let t0 = std::time::Instant::now();
    assert!(verify(&Epoch { pks: pks2, c0: c02, cs: cs2, e: e2, s: s2 }, true));
    println!("OK  per-recipient, {n2} recipients: prove {:?}, verify {:?} (incl. torsion checks)", tp, t0.elapsed());
}
