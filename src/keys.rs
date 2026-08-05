//! Key file handling: iroh endpoint secret keys (lowercase hex) and age
//! X25519 identities (native age format).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result};
use iroh::{EndpointId, SecretKey};

fn write_private(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Generate an iroh endpoint secret key, write it hex-encoded, and return
/// the public EndpointId.
pub fn generate_endpoint_key(path: &Path) -> Result<EndpointId> {
    anyhow::ensure!(!path.exists(), "{} already exists", path.display());
    let secret = SecretKey::generate();
    let hex = data_encoding::HEXLOWER.encode(&secret.to_bytes());
    write_private(path, &format!("{hex}\n"))?;
    Ok(secret.public())
}

pub fn load_endpoint_key(path: &Path) -> Result<SecretKey> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading endpoint key {}", path.display()))?;
    SecretKey::from_str(contents.trim())
        .map_err(|e| anyhow::anyhow!("parsing endpoint key {}: {e}", path.display()))
}

/// Generate an age X25519 identity, write it in native age format, and
/// return the public recipient string (`age1...`).
pub fn generate_age_identity(path: &Path) -> Result<String> {
    anyhow::ensure!(!path.exists(), "{} already exists", path.display());
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    write_private(path, &format!("{}\n", identity.to_string().expose_secret()))?;
    Ok(recipient)
}

pub fn load_age_identity(path: &Path) -> Result<age::x25519::Identity> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading age identity {}", path.display()))?;
    let line = contents
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow::anyhow!("{} contains no identity", path.display()))?;
    age::x25519::Identity::from_str(line)
        .map_err(|e| anyhow::anyhow!("parsing age identity {}: {e}", path.display()))
}

pub fn parse_age_recipient(s: &str) -> Result<age::x25519::Recipient> {
    age::x25519::Recipient::from_str(s.trim())
        .map_err(|e| anyhow::anyhow!("parsing age recipient: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_key_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoint.key");
        let id = generate_endpoint_key(&path).unwrap();
        let loaded = load_endpoint_key(&path).unwrap();
        assert_eq!(loaded.public(), id);
        // Refuses to overwrite.
        assert!(generate_endpoint_key(&path).is_err());
    }

    #[test]
    fn age_identity_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.age");
        let recipient = generate_age_identity(&path).unwrap();
        let identity = load_age_identity(&path).unwrap();
        assert_eq!(identity.to_public().to_string(), recipient);
        assert!(parse_age_recipient(&recipient).is_ok());
    }
}
