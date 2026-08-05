//! Wire protocol: one request per bidirectional QUIC stream, CBOR-encoded
//! (serde's externally-tagged enum representation: unit variants are text
//! strings, others are single-entry maps keyed by the variant name).
//!
//! Authentication is the transport's job (iroh handshake); these messages
//! carry no signatures, timestamps, or client identity fields. See
//! design/crypto-design.md section 5.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// ALPN identifier for the bunker protocol.
pub const ALPN: &[u8] = b"secret-bunker/1";

/// Maximum encoded message size accepted on a stream (either direction).
pub const MAX_MSG: usize = 4 * 1024 * 1024;

// WIRE CONTRACT: variant and field NAMES are the CBOR encoding. Non-Rust
// clients (github.com/fables-for-robots/go-secret-bunker-iroh) match them
// as strings — never rename a variant or field; adding variants is fine.
// Guarded by the wire_format_is_stable test below.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Get {
        group: String,
        name: String,
    },
    /// `expected_version` 0 means "create; must not exist yet".
    Put {
        group: String,
        name: String,
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
        expected_version: u64,
    },
    Delete {
        group: String,
        name: String,
        expected_version: u64,
    },
    List {
        group: String,
    },
    CreateGroup {
        name: String,
    },
    AddIdentity {
        name: String,
        endpoint_id: String,
        service_admin: bool,
    },
    RemoveIdentity {
        name: String,
    },
    ListIdentities,
    /// Set the permission bitmask (0 revokes) for `identity` on `group`.
    Grant {
        group: String,
        identity: String,
        perms: u8,
    },
    RotateDek {
        group: String,
    },
    /// Groups visible to the caller: those it holds permissions on, or
    /// every group when the caller is a service admin.
    ListGroups,
    /// The ACL of a group; requires `admin` on that group.
    GroupAcl {
        group: String,
    },
}

impl Request {
    /// Short operation name for the audit log.
    pub fn op(&self) -> &'static str {
        match self {
            Request::Get { .. } => "get",
            Request::Put { .. } => "put",
            Request::Delete { .. } => "delete",
            Request::List { .. } => "list",
            Request::CreateGroup { .. } => "create-group",
            Request::AddIdentity { .. } => "add-identity",
            Request::RemoveIdentity { .. } => "remove-identity",
            Request::ListIdentities => "list-identities",
            Request::Grant { .. } => "grant",
            Request::RotateDek { .. } => "rotate-dek",
            Request::ListGroups => "list-groups",
            Request::GroupAcl { .. } => "group-acl",
        }
    }

    /// Audit-log target description.
    pub fn target(&self) -> String {
        match self {
            Request::Get { group, name }
            | Request::Put { group, name, .. }
            | Request::Delete { group, name, .. } => format!("{group}/{name}"),
            Request::List { group }
            | Request::RotateDek { group }
            | Request::GroupAcl { group } => group.clone(),
            Request::CreateGroup { name } => name.clone(),
            Request::AddIdentity { name, .. } | Request::RemoveIdentity { name } => name.clone(),
            Request::ListIdentities | Request::ListGroups => String::new(),
            Request::Grant {
                group, identity, ..
            } => format!("{group}:{identity}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Response {
    /// Uniform denial: unknown identity, insufficient permission, or
    /// nonexistent target. Deliberately carries no detail.
    Denied,
    Ok,
    Secret {
        #[serde(with = "serde_bytes")]
        value: Vec<u8>,
        version: u64,
    },
    /// Returned after a successful Put (the new version).
    Version {
        version: u64,
    },
    /// CAS precondition failed. Only sent after the ACL check passed.
    VersionConflict {
        current: u64,
    },
    Names(Vec<(String, u64)>),
    Identities(Vec<IdentityInfo>),
    /// Reply to ListGroups: the caller's role plus the groups it can see,
    /// each with the caller's own permission bitmask on it.
    Groups {
        service_admin: bool,
        groups: Vec<GroupInfo>,
    },
    /// Reply to GroupAcl: (identity name, permission bitmask) pairs.
    Acl(Vec<(String, u8)>),
    /// Operation failed after authorization succeeded. Never sent to
    /// unauthorized callers (they get `Denied`), so the reason may be
    /// informative.
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInfo {
    pub name: String,
    /// The requesting caller's permission bitmask on this group.
    pub perms: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityInfo {
    pub name: String,
    pub endpoint_id: String,
    pub service_admin: bool,
}

/// Render a permission bitmask as "rwa" flags (e.g. "r--", "rw-", "rwa").
pub fn perms_str(perms: u8) -> String {
    let flag = |bit: u8, c: char| if perms & bit != 0 { c } else { '-' };
    format!("{}{}{}", flag(1, 'r'), flag(2, 'w'), flag(4, 'a'))
}

/// Parse "r", "rw", "rwa", "none" (or "-") into a permission bitmask.
pub fn parse_perms(s: &str) -> anyhow::Result<u8> {
    let s = s.trim();
    if s == "none" || s == "-" {
        return Ok(0);
    }
    let mut perms = 0u8;
    for c in s.chars() {
        perms |= match c {
            'r' => 1,
            'w' => 2,
            'a' => 4,
            _ => anyhow::bail!("invalid permission '{c}' (use r, w, a, or \"none\")"),
        };
    }
    Ok(perms)
}

pub fn encode<T: Serialize>(msg: &T) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(msg, &mut out)?;
    Ok(out)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    Ok(ciborium::de::from_reader(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CBOR golden vectors shared with the Go client
    /// (go-secret-bunker-iroh/proto_test.go). A failure here means the
    /// wire format changed and every non-Rust client breaks.
    #[test]
    fn wire_format_is_stable() {
        let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                encode(&Request::Get {
                    group: "prod".into(),
                    name: "db".into(),
                })
                .unwrap(),
                "a163476574a26567726f75706470726f64646e616d65626462",
            ),
            (
                encode(&Request::Put {
                    group: "g".into(),
                    name: "n".into(),
                    value: vec![1, 2, 255],
                    expected_version: 300,
                })
                .unwrap(),
                "a163507574a46567726f75706167646e616d65616e6576616c7565430102ff7065787065637465645f76657273696f6e19012c",
            ),
            (
                encode(&Request::ListGroups).unwrap(),
                "6a4c69737447726f757073",
            ),
            (
                encode(&Request::Grant {
                    group: "g".into(),
                    identity: "id".into(),
                    perms: 7,
                })
                .unwrap(),
                "a1654772616e74a36567726f75706167686964656e74697479626964657065726d7307",
            ),
            (encode(&Response::Denied).unwrap(), "6644656e696564"),
            (
                encode(&Response::Secret {
                    value: b"hi".to_vec(),
                    version: 128,
                })
                .unwrap(),
                "a166536563726574a26576616c75654268696776657273696f6e1880",
            ),
            (
                encode(&Response::Names(vec![("a".into(), 1), ("b".into(), 2)])).unwrap(),
                "a1654e616d6573828261610182616202",
            ),
            (
                encode(&Response::Groups {
                    service_admin: true,
                    groups: vec![GroupInfo {
                        name: "g".into(),
                        perms: 5,
                    }],
                })
                .unwrap(),
                "a16647726f757073a26d736572766963655f61646d696ef56667726f75707381a2646e616d656167657065726d7305",
            ),
            (
                encode(&Response::Failed {
                    reason: "no".into(),
                })
                .unwrap(),
                "a1664661696c6564a166726561736f6e626e6f",
            ),
            (
                encode(&Response::VersionConflict { current: 65535 }).unwrap(),
                "a16f56657273696f6e436f6e666c696374a16763757272656e7419ffff",
            ),
        ];
        for (bytes, expected) in cases {
            assert_eq!(hex(&bytes), expected);
        }
    }

    #[test]
    fn request_roundtrip() {
        let req = Request::Put {
            group: "prod".into(),
            name: "db-password".into(),
            value: b"hunter2".to_vec(),
            expected_version: 3,
        };
        let bytes = encode(&req).unwrap();
        let back: Request = decode(&bytes).unwrap();
        assert_eq!(back.op(), "put");
        assert_eq!(back.target(), "prod/db-password");
    }

    #[test]
    fn response_roundtrip() {
        let resp = Response::Secret {
            value: b"v".to_vec(),
            version: 7,
        };
        let bytes = encode(&resp).unwrap();
        assert_eq!(decode::<Response>(&bytes).unwrap(), resp);
    }
}
