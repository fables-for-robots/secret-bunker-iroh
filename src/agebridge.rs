//! Ed25519 → X25519 bridge: every iroh EndpointId doubles as an age
//! recipient, and the corresponding iroh secret key yields the matching
//! age identity. No second keypair, no registration.
//!
//! The conversion is the birational Edwards→Montgomery map (public side)
//! and the SHA-512 scalar clamp (secret side) — the same construction as
//! ssh-to-age and libsodium's crypto_sign_ed25519_*_to_curve25519. Joint
//! security of signing + X25519 ECDH under one key is analyzed in
//! Thormarker, "On using the same key pair for Ed25519 and an X25519
//! based KEM", ePrint 2021/509. age 0.11 exposes only Bech32-string
//! constructors for x25519 types, hence the bech32 round-trips.
//! Deliberately NOT age's `ssh` feature: its ssh-ed25519 stanzas add an
//! HKDF tweak and would not interoperate with this native derivation.

use std::str::FromStr;

use anyhow::{Context, Result};
use bech32::{ToBase32, Variant};

/// Anyone can compute this from a public EndpointId.
pub fn recipient_for_endpoint(id: &iroh::EndpointId) -> Result<age::x25519::Recipient> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(id.as_bytes())
        .context("EndpointId is not a valid ed25519 point")?;
    let montgomery = vk.to_montgomery();
    let encoded = bech32::encode("age", montgomery.as_bytes().to_base32(), Variant::Bech32)
        .context("bech32-encoding derived recipient")?;
    age::x25519::Recipient::from_str(&encoded).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn recipient_for_endpoint_hex(hex: &str) -> Result<age::x25519::Recipient> {
    let id: iroh::EndpointId = hex.parse().context("parsing endpoint id")?;
    recipient_for_endpoint(&id)
}

/// Only the holder of the iroh secret key can compute this.
pub fn identity_from_secret(secret: &iroh::SecretKey) -> Result<age::x25519::Identity> {
    let signing = ed25519_dalek::SigningKey::from_bytes(&secret.to_bytes());
    // The SHA-512-expanded scalar half; dalek documents it as the valid
    // X25519 StaticSecret for the converted public key (x25519 clamps
    // during ECDH).
    let scalar = signing.to_scalar_bytes();
    let encoded = bech32::encode("age-secret-key-", scalar.to_base32(), Variant::Bech32)
        .context("bech32-encoding derived identity")?
        .to_uppercase();
    age::x25519::Identity::from_str(&encoded).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_identity_matches_derived_recipient() {
        let secret = iroh::SecretKey::generate();
        let recipient = recipient_for_endpoint(&secret.public()).unwrap();
        let identity = identity_from_secret(&secret).unwrap();
        assert_eq!(identity.to_public().to_string(), recipient.to_string());
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let secret = iroh::SecretKey::generate();
        let recipient = recipient_for_endpoint(&secret.public()).unwrap();
        let identity = identity_from_secret(&secret).unwrap();
        let ct = crate::crypto::age_encrypt(&recipient, b"payload").unwrap();
        let pt = crate::crypto::age_decrypt(&identity, &ct).unwrap();
        assert_eq!(pt, b"payload");
    }

    #[test]
    fn hex_form_matches_endpoint_form() {
        let secret = iroh::SecretKey::generate();
        let id = secret.public();
        let via_hex = recipient_for_endpoint_hex(&id.to_string()).unwrap();
        let via_id = recipient_for_endpoint(&id).unwrap();
        assert_eq!(via_hex.to_string(), via_id.to_string());
    }

    /// Golden vector: pins the derivation so it can never silently change.
    /// The recipient string below was produced by this very code at
    /// implementation time from the fixed seed; a mismatch later means the
    /// derivation changed and every stored wrap is unreadable.
    #[test]
    fn derivation_golden_vector() {
        let secret = iroh::SecretKey::from_bytes(&[7u8; 32]);
        let recipient = recipient_for_endpoint(&secret.public()).unwrap();
        assert_eq!(
            recipient.to_string(),
            "age1wcwc3myrqsfer807n4x364h30ejneryegzpd7kcn0wg2ptnwma6qfgnx5h"
        );
        let identity = identity_from_secret(&secret).unwrap();
        assert_eq!(identity.to_public().to_string(), recipient.to_string());
    }
}
