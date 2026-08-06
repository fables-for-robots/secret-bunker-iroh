//! Named server aliases, stored as a plain-text file in the XDG data dir
//! (`servers`: one `alias endpoint-id` pair per line, `#` comments).
//!
//! `resolve` is the single entry point the CLI uses for `--server`: a raw
//! EndpointId is taken as-is, anything else is looked up as an alias, and
//! an omitted value falls back to the alias named "default".

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use iroh::EndpointId;

use crate::keys;

pub const DEFAULT_ALIAS: &str = "default";

fn servers_path() -> Result<PathBuf> {
    Ok(keys::data_dir()?.join("servers"))
}

fn parse(contents: &str) -> Vec<(String, EndpointId)> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (name, id) = line.split_once(char::is_whitespace)?;
            Some((name.to_string(), id.trim().parse().ok()?))
        })
        .collect()
}

fn load_at(path: &Path) -> Result<Vec<(String, EndpointId)>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(parse(&contents))
}

fn store_at(path: &Path, entries: &[(String, EndpointId)]) -> Result<()> {
    keys::ensure_parent(path)?;
    let mut out = String::new();
    for (name, id) in entries {
        out.push_str(&format!("{name} {id}\n"));
    }
    fs::write(path, out).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn add_at(path: &Path, name: &str, id: EndpointId, force: bool) -> Result<()> {
    anyhow::ensure!(!name.is_empty(), "alias must not be empty");
    anyhow::ensure!(
        !name.contains(char::is_whitespace),
        "alias must not contain whitespace"
    );
    anyhow::ensure!(
        name.parse::<EndpointId>().is_err(),
        "'{name}' parses as an EndpointId; that would make lookups ambiguous"
    );
    let mut entries = load_at(path)?;
    if let Some(entry) = entries.iter_mut().find(|(n, _)| n == name) {
        anyhow::ensure!(
            force,
            "alias '{name}' already exists (currently {}); use --force to replace",
            entry.1
        );
        entry.1 = id;
    } else {
        entries.push((name.to_string(), id));
        entries.sort_by(|a, b| a.0.cmp(&b.0));
    }
    store_at(path, &entries)
}

fn remove_at(path: &Path, name: &str) -> Result<bool> {
    let mut entries = load_at(path)?;
    let before = entries.len();
    entries.retain(|(n, _)| n != name);
    if entries.len() == before {
        return Ok(false);
    }
    store_at(path, &entries)?;
    Ok(true)
}

fn resolve_at(path: &Path, server: Option<&str>) -> Result<EndpointId> {
    let entries = load_at(path)?;
    let lookup = |name: &str| entries.iter().find(|(n, _)| n == name).map(|(_, id)| *id);
    match server {
        Some(s) => {
            if let Ok(id) = s.parse::<EndpointId>() {
                return Ok(id);
            }
            lookup(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "'{s}' is neither an EndpointId nor a known alias (see `server ls`)"
                )
            })
        }
        None => lookup(DEFAULT_ALIAS).ok_or_else(|| {
            anyhow::anyhow!(
                "no --server given and no '{DEFAULT_ALIAS}' alias configured \
                 (add one with `server add {DEFAULT_ALIAS} <endpoint-id>`)"
            )
        }),
    }
}

pub fn list() -> Result<Vec<(String, EndpointId)>> {
    load_at(&servers_path()?)
}

pub fn add(name: &str, id: EndpointId, force: bool) -> Result<()> {
    add_at(&servers_path()?, name, id, force)
}

pub fn remove(name: &str) -> Result<bool> {
    remove_at(&servers_path()?, name)
}

/// Resolve a `--server` argument (raw EndpointId or alias); `None` falls
/// back to the "default" alias.
pub fn resolve(server: Option<&str>) -> Result<EndpointId> {
    resolve_at(&servers_path()?, server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn id() -> EndpointId {
        SecretKey::generate().public()
    }

    #[test]
    fn add_list_remove_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers");
        let (a, b) = (id(), id());
        add_at(&path, "prod", a, false).unwrap();
        add_at(&path, "default", b, false).unwrap();
        assert_eq!(
            load_at(&path).unwrap(),
            vec![("default".into(), b), ("prod".into(), a)]
        );
        assert!(remove_at(&path, "prod").unwrap());
        assert!(!remove_at(&path, "prod").unwrap());
        assert_eq!(load_at(&path).unwrap(), vec![("default".into(), b)]);
    }

    #[test]
    fn add_refuses_duplicates_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers");
        let (a, b) = (id(), id());
        add_at(&path, "prod", a, false).unwrap();
        assert!(add_at(&path, "prod", b, false).is_err());
        add_at(&path, "prod", b, true).unwrap();
        assert_eq!(load_at(&path).unwrap(), vec![("prod".into(), b)]);
    }

    #[test]
    fn add_rejects_ambiguous_and_invalid_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers");
        // A name that parses as an EndpointId would shadow raw-id lookups.
        assert!(add_at(&path, &id().to_string(), id(), false).is_err());
        assert!(add_at(&path, "", id(), false).is_err());
        assert!(add_at(&path, "two words", id(), false).is_err());
    }

    #[test]
    fn resolve_prefers_raw_id_then_alias_then_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers");
        let (raw, aliased, fallback) = (id(), id(), id());
        add_at(&path, "bunker", aliased, false).unwrap();
        add_at(&path, "default", fallback, false).unwrap();

        assert_eq!(resolve_at(&path, Some(&raw.to_string())).unwrap(), raw);
        assert_eq!(resolve_at(&path, Some("bunker")).unwrap(), aliased);
        assert_eq!(resolve_at(&path, None).unwrap(), fallback);
        assert!(resolve_at(&path, Some("nope")).is_err());
    }

    #[test]
    fn resolve_without_default_alias_errors_helpfully() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("servers");
        let err = resolve_at(&path, None).unwrap_err().to_string();
        assert!(err.contains("server add default"), "unhelpful error: {err}");
    }
}
