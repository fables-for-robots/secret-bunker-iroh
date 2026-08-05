//! At-rest cryptography: group DEKs, age wrapping, secret encryption.
//!
//! See design/crypto-design.md sections 4 (Encryption at Rest) and 6.

use std::io::{Read, Write};

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEK_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// A group data-encryption key. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek(pub(crate) [u8; DEK_LEN]);

impl Dek {
    pub fn generate() -> Self {
        let mut bytes = [0u8; DEK_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Dek(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; DEK_LEN] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("DEK must be {DEK_LEN} bytes"))?;
        Ok(Dek(arr))
    }
}

/// Encrypt `plaintext` to a single age recipient, returning a binary age file.
pub fn age_encrypt(recipient: &dyn age::Recipient, plaintext: &[u8]) -> Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient))
        .context("building age encryptor")?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).context("age wrap_output")?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(out)
}

/// Decrypt a binary age file with a single identity.
pub fn age_decrypt(identity: &dyn age::Identity, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let decryptor = age::Decryptor::new(ciphertext).context("parsing age file")?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity))
        .context("age decrypt")?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

/// Wrap a DEK to one public key (operational or backup).
pub fn wrap_dek(dek: &Dek, recipient: &dyn age::Recipient) -> Result<Vec<u8>> {
    age_encrypt(recipient, &dek.0)
}

/// Unwrap a DEK with a private identity (operational or backup).
pub fn unwrap_dek(wrapped: &[u8], identity: &dyn age::Identity) -> Result<Dek> {
    let mut bytes = age_decrypt(identity, wrapped)?;
    let dek = Dek::from_bytes(&bytes)?;
    bytes.zeroize();
    Ok(dek)
}

/// Associated data binding a ciphertext to its logical location, so an
/// attacker with database write access cannot transplant ciphertexts
/// between secrets or versions. Length-prefixed to be unambiguous for
/// arbitrary group/secret names.
pub fn secret_aad(group: &str, name: &str, version: u64, dek_version: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + group.len() + name.len());
    aad.extend_from_slice(b"secret-bunker-iroh/1");
    for part in [group.as_bytes(), name.as_bytes()] {
        aad.extend_from_slice(&(part.len() as u64).to_be_bytes());
        aad.extend_from_slice(part);
    }
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&dek_version.to_be_bytes());
    aad
}

/// Encrypt a secret value with a DEK. Returns (nonce, ciphertext).
pub fn encrypt_secret(dek: &Dek, aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek.0));
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("secret encryption failed"))?;
    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt a secret value with a DEK, verifying the associated data.
pub fn decrypt_secret(dek: &Dek, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek.0));
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce must be {NONCE_LEN} bytes"))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("secret decryption failed (wrong key or tampered data)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dek_wrap_unwrap_roundtrip() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let dek = Dek::generate();
        let wrapped = wrap_dek(&dek, &recipient).unwrap();
        let unwrapped = unwrap_dek(&wrapped, &identity).unwrap();
        assert_eq!(dek.0, unwrapped.0);
    }

    #[test]
    fn dek_unwrap_wrong_identity_fails() {
        let identity = age::x25519::Identity::generate();
        let other = age::x25519::Identity::generate();
        let dek = Dek::generate();
        let wrapped = wrap_dek(&dek, &identity.to_public()).unwrap();
        assert!(unwrap_dek(&wrapped, &other).is_err());
    }

    #[test]
    fn secret_encrypt_decrypt_roundtrip() {
        let dek = Dek::generate();
        let aad = secret_aad("prod", "db-password", 3, 1);
        let (nonce, ct) = encrypt_secret(&dek, &aad, b"hunter2").unwrap();
        let pt = decrypt_secret(&dek, &aad, &nonce, &ct).unwrap();
        assert_eq!(pt, b"hunter2");
    }

    #[test]
    fn secret_decrypt_rejects_transplanted_ciphertext() {
        let dek = Dek::generate();
        let aad = secret_aad("prod", "db-password", 3, 1);
        let (nonce, ct) = encrypt_secret(&dek, &aad, b"hunter2").unwrap();
        // Same DEK, different logical location: must fail.
        let other_aad = secret_aad("prod", "api-token", 3, 1);
        assert!(decrypt_secret(&dek, &other_aad, &nonce, &ct).is_err());
    }

    #[test]
    fn aad_is_unambiguous() {
        // ("ab", "c") and ("a", "bc") must not collide.
        assert_ne!(secret_aad("ab", "c", 1, 1), secret_aad("a", "bc", 1, 1));
    }
}
