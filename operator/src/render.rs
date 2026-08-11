//! Pure mapping pipeline: bunker bytes in, k8s Secret data map out.
//! No kube types, no replica handle — everything here is unit-testable.

use std::collections::BTreeMap;

use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

use crate::crd::{BunkerSecretSpec, DataFromEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    MissingGroup,
    MissingSecret,
    /// Mirror has the entry but cannot serve it yet (DEK wrap race) — retryable.
    NotYetSynced(String),
    Other(String),
}

pub trait SecretSource {
    fn list(&self, group: &str) -> Result<Vec<String>, SourceError>;
    fn get(&self, group: &str, name: &str) -> Result<Vec<u8>, SourceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    MissingGroup {
        group: String,
    },
    MissingSecret {
        group: String,
        name: String,
    },
    NotYetSynced {
        group: String,
        name: String,
        msg: String,
    },
    InvalidKey {
        keys: Vec<String>,
    },
    Json {
        group: String,
        name: String,
        msg: String,
    },
    Pointer {
        group: String,
        name: String,
        pointer: String,
    },
    NotObject {
        group: String,
        name: String,
    },
}

pub fn valid_key(k: &str) -> bool {
    !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// "sha256:<hex>" over length-prefixed sorted (key, value) pairs.
pub fn content_hash(data: &BTreeMap<String, Vec<u8>>) -> String {
    let mut h = Sha256::new();
    for (k, v) in data {
        h.update((k.len() as u64).to_le_bytes());
        h.update(k.as_bytes());
        h.update((v.len() as u64).to_le_bytes());
        h.update(v);
    }
    format!("sha256:{}", HEXLOWER.encode(&h.finalize()))
}

fn source_err(e: SourceError, group: &str, name: &str) -> RenderError {
    match e {
        SourceError::MissingGroup => RenderError::MissingGroup {
            group: group.into(),
        },
        SourceError::MissingSecret => RenderError::MissingSecret {
            group: group.into(),
            name: name.into(),
        },
        SourceError::NotYetSynced(msg) => RenderError::NotYetSynced {
            group: group.into(),
            name: name.into(),
            msg,
        },
        SourceError::Other(msg) => RenderError::NotYetSynced {
            group: group.into(),
            name: name.into(),
            msg,
        },
    }
}

fn parse_json(group: &str, name: &str, bytes: &[u8]) -> Result<serde_json::Value, RenderError> {
    serde_json::from_slice(bytes).map_err(|e| RenderError::Json {
        group: group.into(),
        name: name.into(),
        msg: e.to_string(),
    })
}

/// A resolved JSON string becomes raw UTF-8 bytes; any other value is compact JSON.
fn json_value_bytes(v: &serde_json::Value) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.clone().into_bytes(),
        other => other.to_string().into_bytes(),
    }
}

pub fn render(
    spec: &BunkerSecretSpec,
    source: &dyn SecretSource,
) -> Result<BTreeMap<String, Vec<u8>>, RenderError> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut invalid: Vec<String> = Vec::new();

    // 1. dataFrom, in list order; later entries overwrite earlier on collision.
    for entry in &spec.data_from {
        match entry {
            DataFromEntry::Group(g) => {
                let names = source
                    .list(&g.name)
                    .map_err(|e| source_err(e, &g.name, ""))?;
                for name in names {
                    let value = source
                        .get(&g.name, &name)
                        .map_err(|e| source_err(e, &g.name, &name))?;
                    let key = g
                        .rewrite
                        .iter()
                        .find(|r| r.source == name)
                        .map(|r| r.target.clone())
                        .unwrap_or_else(|| name.clone());
                    if !valid_key(&key) {
                        invalid.push(key);
                        continue;
                    }
                    out.insert(key, value);
                }
            }
            DataFromEntry::Extract(e) => {
                let value = source
                    .get(&e.group, &e.name)
                    .map_err(|err| source_err(err, &e.group, &e.name))?;
                let json = parse_json(&e.group, &e.name, &value)?;
                let obj = json.as_object().ok_or_else(|| RenderError::NotObject {
                    group: e.group.clone(),
                    name: e.name.clone(),
                })?;
                for (k, v) in obj {
                    if !valid_key(k) {
                        invalid.push(k.clone());
                        continue;
                    }
                    out.insert(k.clone(), json_value_bytes(v));
                }
            }
        }
    }

    // 2. data, always wins.
    for d in &spec.data {
        let r = &d.remote_ref;
        let value = source
            .get(&r.group, &r.name)
            .map_err(|e| source_err(e, &r.group, &r.name))?;
        let bytes = match &r.property {
            None => value,
            Some(pointer) => {
                let json = parse_json(&r.group, &r.name, &value)?;
                let v = json.pointer(pointer).ok_or_else(|| RenderError::Pointer {
                    group: r.group.clone(),
                    name: r.name.clone(),
                    pointer: pointer.clone(),
                })?;
                json_value_bytes(v)
            }
        };
        if !valid_key(&d.secret_key) {
            invalid.push(d.secret_key.clone());
            continue;
        }
        out.insert(d.secret_key.clone(), bytes);
    }

    if !invalid.is_empty() {
        invalid.sort();
        invalid.dedup();
        return Err(RenderError::InvalidKey { keys: invalid });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Fixture(BTreeMap<(String, String), Vec<u8>>);

    impl Fixture {
        fn new(entries: &[(&str, &str, &[u8])]) -> Self {
            Fixture(
                entries
                    .iter()
                    .map(|(g, n, v)| ((g.to_string(), n.to_string()), v.to_vec()))
                    .collect(),
            )
        }
    }

    impl SecretSource for Fixture {
        fn list(&self, group: &str) -> Result<Vec<String>, SourceError> {
            let names: Vec<String> = self
                .0
                .keys()
                .filter(|(g, _)| g == group)
                .map(|(_, n)| n.clone())
                .collect();
            if names.is_empty() {
                return Err(SourceError::MissingGroup);
            }
            Ok(names)
        }
        fn get(&self, group: &str, name: &str) -> Result<Vec<u8>, SourceError> {
            if !self.0.keys().any(|(g, _)| g == group) {
                return Err(SourceError::MissingGroup);
            }
            self.0
                .get(&(group.to_string(), name.to_string()))
                .cloned()
                .ok_or(SourceError::MissingSecret)
        }
    }

    fn spec(yaml: &str) -> crate::crd::BunkerSecretSpec {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn data_verbatim_bytes() {
        let src = Fixture::new(&[("g", "pw", b"hunter2\xff")]); // binary-safe
        let out = render(
            &spec("data: [{secretKey: PW, remoteRef: {group: g, name: pw}}]"),
            &src,
        )
        .unwrap();
        assert_eq!(out["PW"], b"hunter2\xff".to_vec());
    }

    #[test]
    fn property_extracts_json_string_as_raw_bytes() {
        let src = Fixture::new(&[("g", "cfg", br#"{"smtp":{"password":"s3cr3t"}}"#)]);
        let out = render(
            &spec("data: [{secretKey: P, remoteRef: {group: g, name: cfg, property: /smtp/password}}]"),
            &src,
        )
        .unwrap();
        assert_eq!(out["P"], b"s3cr3t".to_vec());
    }

    #[test]
    fn property_reserializes_non_string_compactly() {
        let src = Fixture::new(&[("g", "cfg", br#"{"port": 25, "hosts": ["a","b"]}"#)]);
        let out = render(
            &spec("data: [{secretKey: H, remoteRef: {group: g, name: cfg, property: /hosts}}]"),
            &src,
        )
        .unwrap();
        assert_eq!(out["H"], br#"["a","b"]"#.to_vec());
    }

    #[test]
    fn property_miss_is_pointer_error() {
        let src = Fixture::new(&[("g", "cfg", br#"{"a":1}"#)]);
        let err = render(
            &spec("data: [{secretKey: X, remoteRef: {group: g, name: cfg, property: /nope}}]"),
            &src,
        )
        .unwrap_err();
        assert!(matches!(err, RenderError::Pointer { .. }));
    }

    #[test]
    fn property_on_non_json_is_json_error() {
        let src = Fixture::new(&[("g", "blob", b"\xff\xfe not json")]);
        let err = render(
            &spec("data: [{secretKey: X, remoteRef: {group: g, name: blob, property: /a}}]"),
            &src,
        )
        .unwrap_err();
        assert!(matches!(err, RenderError::Json { .. }));
    }

    #[test]
    fn extract_fans_out_object_keys() {
        let src = Fixture::new(&[("g", "cfg", br#"{"user":"u","port":25}"#)]);
        let out = render(&spec("dataFrom: [{extract: {group: g, name: cfg}}]"), &src).unwrap();
        assert_eq!(out["user"], b"u".to_vec());
        assert_eq!(out["port"], b"25".to_vec());
    }

    #[test]
    fn extract_non_object_is_not_object_error() {
        let src = Fixture::new(&[("g", "cfg", br#"[1,2]"#)]);
        let err = render(&spec("dataFrom: [{extract: {group: g, name: cfg}}]"), &src).unwrap_err();
        assert!(matches!(err, RenderError::NotObject { .. }));
    }

    #[test]
    fn group_fan_out_with_rewrite() {
        let src = Fixture::new(&[("g", "db-password", b"pw"), ("g", "api_key", b"k")]);
        let out = render(
            &spec("dataFrom: [{group: {name: g, rewrite: [{source: db-password, target: DB_PASSWORD}]}}]"),
            &src,
        )
        .unwrap();
        assert_eq!(out["DB_PASSWORD"], b"pw".to_vec());
        assert_eq!(out["api_key"], b"k".to_vec());
        assert!(!out.contains_key("db-password"));
    }

    #[test]
    fn precedence_later_data_from_wins_then_data_overrides() {
        let src = Fixture::new(&[
            ("g1", "k", b"from-g1"),
            ("g2", "k", b"from-g2"),
            ("g3", "explicit", b"from-data"),
        ]);
        let out = render(
            &spec(
                "dataFrom: [{group: {name: g1}}, {group: {name: g2}}]\n\
                 data: [{secretKey: k, remoteRef: {group: g3, name: explicit}}]",
            ),
            &src,
        )
        .unwrap();
        // g2 overwrote g1; data overrode both.
        assert_eq!(out["k"], b"from-data".to_vec());
    }

    #[test]
    fn invalid_keys_fail_whole_render_listing_offenders() {
        let src = Fixture::new(&[("g", "bad/name", b"v"), ("g", "ok", b"v")]);
        let err = render(&spec("dataFrom: [{group: {name: g}}]"), &src).unwrap_err();
        match err {
            RenderError::InvalidKey { keys } => assert_eq!(keys, vec!["bad/name".to_string()]),
            other => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[test]
    fn missing_group_and_secret_errors() {
        let src = Fixture::new(&[("g", "a", b"v")]);
        assert!(matches!(
            render(&spec("dataFrom: [{group: {name: nope}}]"), &src).unwrap_err(),
            RenderError::MissingGroup { .. }
        ));
        assert!(matches!(
            render(
                &spec("data: [{secretKey: X, remoteRef: {group: g, name: nope}}]"),
                &src
            )
            .unwrap_err(),
            RenderError::MissingSecret { .. }
        ));
    }

    #[test]
    fn content_hash_is_stable_and_order_independent() {
        let mut a = BTreeMap::new();
        a.insert("x".to_string(), b"1".to_vec());
        a.insert("y".to_string(), b"2".to_vec());
        let h1 = content_hash(&a);
        assert!(h1.starts_with("sha256:"));
        // Same logical content, different insertion order → same hash (BTreeMap sorts).
        let mut b = BTreeMap::new();
        b.insert("y".to_string(), b"2".to_vec());
        b.insert("x".to_string(), b"1".to_vec());
        assert_eq!(h1, content_hash(&b));
        // Key/value boundary ambiguity must matter: ("ab","c") != ("a","bc").
        let mut c = BTreeMap::new();
        c.insert("ab".to_string(), b"c".to_vec());
        let mut d = BTreeMap::new();
        d.insert("a".to_string(), b"bc".to_vec());
        assert_ne!(content_hash(&c), content_hash(&d));
    }

    #[test]
    fn valid_key_charset() {
        assert!(valid_key("a-b_c.D9"));
        assert!(!valid_key("a/b"));
        assert!(!valid_key(""));
        assert!(!valid_key("a b"));
    }
}
