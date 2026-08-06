//! Key file handling: iroh endpoint secret keys (lowercase hex) and age
//! X25519 identities (native age format).
//!
//! Keys live under the XDG data directory by default
//! (`$XDG_DATA_HOME/secret-bunker-iroh`, falling back to
//! `~/.local/share/secret-bunker-iroh`) and are auto-generated there on
//! first use. Explicitly supplied paths are never auto-generated: a typo'd
//! path silently minting a fresh identity would change the endpoint's
//! EndpointId.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result};
use iroh::SecretKey;

/// The keys the CLI manages in the XDG data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum KeyRole {
    /// Iroh endpoint key the `client` subcommand connects with.
    Client,
    /// Iroh endpoint key the bunker serves with (its EndpointId).
    Server,
    /// Age identity that wraps/unwraps group DEKs.
    Operational,
    /// Age identity for disaster recovery; keep its secret half offline.
    Backup,
}

impl KeyRole {
    pub fn filename(self) -> &'static str {
        match self {
            KeyRole::Client => "client.key",
            KeyRole::Server => "server.key",
            KeyRole::Operational => "operational.age",
            KeyRole::Backup => "backup.age",
        }
    }

    pub fn is_age(self) -> bool {
        matches!(self, KeyRole::Operational | KeyRole::Backup)
    }
}

fn data_dir_from(xdg_data_home: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    if let Some(dir) = xdg_data_home.filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join("secret-bunker-iroh"));
    }
    let home = home.filter(|h| !h.is_empty()).context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("secret-bunker-iroh"))
}

/// `$XDG_DATA_HOME/secret-bunker-iroh`, or `~/.local/share/secret-bunker-iroh`.
pub fn data_dir() -> Result<PathBuf> {
    data_dir_from(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))
}

pub fn default_key_path(role: KeyRole) -> Result<PathBuf> {
    Ok(data_dir()?.join(role.filename()))
}

pub(crate) fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        // Created 0700 from the start (mode applies to every new directory);
        // the set_permissions repairs pre-existing lax directories.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write secret key material 0600 from the moment the file exists — never
/// via a create-then-chmod window in which another local user could read
/// it. Overwrites (import --force) recreate the file for the same reason.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    ensure_parent(path)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut file = match opts.open(path) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(path)?;
            opts.open(path)
        }
        other => other,
    }
    .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Warn when a key file is readable by group/others (à la OpenSSH).
fn warn_if_lax_permissions(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                "key file {} has mode {mode:03o}, readable by other users; consider chmod 600",
                path.display()
            );
        }
    }
}

/// Generate an iroh endpoint secret key, write it hex-encoded, and return it.
pub fn generate_endpoint_key(path: &Path) -> Result<SecretKey> {
    anyhow::ensure!(!path.exists(), "{} already exists", path.display());
    let secret = SecretKey::generate();
    write_private(path, &format!("{}\n", encode_endpoint_key(&secret)))?;
    Ok(secret)
}

pub fn encode_endpoint_key(secret: &SecretKey) -> String {
    data_encoding::HEXLOWER.encode(&secret.to_bytes())
}

pub fn load_endpoint_key(path: &Path) -> Result<SecretKey> {
    warn_if_lax_permissions(path);
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading endpoint key {}", path.display()))?;
    SecretKey::from_str(contents.trim())
        .map_err(|e| anyhow::anyhow!("parsing endpoint key {}: {e}", path.display()))
}

/// Load the key at `path`, generating it first when missing.
/// Returns `(key, freshly_generated)`.
pub fn load_or_generate_endpoint_key(path: &Path) -> Result<(SecretKey, bool)> {
    if path.exists() {
        Ok((load_endpoint_key(path)?, false))
    } else {
        Ok((generate_endpoint_key(path)?, true))
    }
}

/// Generate an age X25519 identity, write it in native age format, and
/// return it.
pub fn generate_age_identity(path: &Path) -> Result<age::x25519::Identity> {
    anyhow::ensure!(!path.exists(), "{} already exists", path.display());
    let identity = age::x25519::Identity::generate();
    write_private(path, &format!("{}\n", identity.to_string().expose_secret()))?;
    Ok(identity)
}

pub fn load_age_identity(path: &Path) -> Result<age::x25519::Identity> {
    warn_if_lax_permissions(path);
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading age identity {}", path.display()))?;
    parse_age_identity(&contents)
        .map_err(|e| anyhow::anyhow!("parsing age identity {}: {e}", path.display()))
}

pub fn parse_age_identity(contents: &str) -> Result<age::x25519::Identity> {
    let line = contents
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow::anyhow!("no identity found"))?;
    age::x25519::Identity::from_str(line).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Load the identity at `path`, generating it first when missing.
/// Returns `(identity, freshly_generated)`.
pub fn load_or_generate_age_identity(path: &Path) -> Result<(age::x25519::Identity, bool)> {
    if path.exists() {
        Ok((load_age_identity(path)?, false))
    } else {
        Ok((generate_age_identity(path)?, true))
    }
}

pub fn parse_age_recipient(s: &str) -> Result<age::x25519::Recipient> {
    age::x25519::Recipient::from_str(s.trim())
        .map_err(|e| anyhow::anyhow!("parsing age recipient: {e}"))
}

/// Validate imported key material for `role` and return it in canonical
/// file form (single line + newline).
pub fn canonicalize_key_material(role: KeyRole, contents: &str) -> Result<String> {
    if role.is_age() {
        let identity = parse_age_identity(contents).context("invalid age identity")?;
        Ok(format!("{}\n", identity.to_string().expose_secret()))
    } else {
        // SecretKey::from_str takes lowercase hex or base32 (case-insensitive),
        // so lowercase first to let uppercase hex import too.
        let secret = SecretKey::from_str(&contents.trim().to_lowercase())
            .map_err(|e| anyhow::anyhow!("invalid endpoint key: {e}"))?;
        Ok(format!("{}\n", encode_endpoint_key(&secret)))
    }
}

/// Public identifier for the key stored at `path` (EndpointId or age
/// recipient), for display.
pub fn public_identifier(role: KeyRole, path: &Path) -> Result<String> {
    if role.is_age() {
        Ok(load_age_identity(path)?.to_public().to_string())
    } else {
        Ok(load_endpoint_key(path)?.public().to_string())
    }
}

/// Import key material into `path` (canonicalized, mode 0600).
pub fn import_key(role: KeyRole, path: &Path, contents: &str, force: bool) -> Result<()> {
    anyhow::ensure!(
        force || !path.exists(),
        "{} already exists (use --force to overwrite)",
        path.display()
    );
    let canonical = canonicalize_key_material(role, contents)?;
    write_private(path, &canonical)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_key_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoint.key");
        let secret = generate_endpoint_key(&path).unwrap();
        let loaded = load_endpoint_key(&path).unwrap();
        assert_eq!(loaded.public(), secret.public());
        // Refuses to overwrite.
        assert!(generate_endpoint_key(&path).is_err());
    }

    #[test]
    fn age_identity_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.age");
        let identity = generate_age_identity(&path).unwrap();
        let loaded = load_age_identity(&path).unwrap();
        assert_eq!(
            loaded.to_public().to_string(),
            identity.to_public().to_string()
        );
    }

    #[test]
    fn data_dir_resolution() {
        assert_eq!(
            data_dir_from(Some("/x/data".into()), Some("/home/u".into())).unwrap(),
            PathBuf::from("/x/data/secret-bunker-iroh")
        );
        // Empty XDG_DATA_HOME falls back to HOME, per the basedir spec.
        assert_eq!(
            data_dir_from(Some("".into()), Some("/home/u".into())).unwrap(),
            PathBuf::from("/home/u/.local/share/secret-bunker-iroh")
        );
        assert_eq!(
            data_dir_from(None, Some("/home/u".into())).unwrap(),
            PathBuf::from("/home/u/.local/share/secret-bunker-iroh")
        );
        assert!(data_dir_from(None, None).is_err());
    }

    #[test]
    fn load_or_generate_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("client.key");
        let (first, generated) = load_or_generate_endpoint_key(&path).unwrap();
        assert!(generated);
        let (second, generated) = load_or_generate_endpoint_key(&path).unwrap();
        assert!(!generated);
        assert_eq!(first.public(), second.public());
        // Parent directory created with restrictive permissions.
        let mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn import_validates_and_canonicalizes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.key");
        let secret = SecretKey::generate();
        // Uppercase hex with surrounding whitespace imports fine...
        let sloppy = format!("  {}  \n", encode_endpoint_key(&secret).to_uppercase());
        import_key(KeyRole::Client, &path, &sloppy, false).unwrap();
        assert_eq!(load_endpoint_key(&path).unwrap().public(), secret.public());
        // ...but garbage does not, and existing keys need --force.
        assert!(import_key(KeyRole::Client, &path, "not-a-key", true).is_err());
        assert!(import_key(KeyRole::Client, &path, &sloppy, false).is_err());
        import_key(KeyRole::Client, &path, &sloppy, true).unwrap();

        let age_path = dir.path().join("op.age");
        let identity = age::x25519::Identity::generate();
        let material = format!("# comment line\n{}\n", identity.to_string().expose_secret());
        import_key(KeyRole::Operational, &age_path, &material, false).unwrap();
        assert_eq!(
            load_age_identity(&age_path)
                .unwrap()
                .to_public()
                .to_string(),
            identity.to_public().to_string()
        );
    }
}
