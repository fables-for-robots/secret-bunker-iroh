//! Wire protocol: one request per bidirectional QUIC stream, postcard-encoded.
//!
//! Authentication is the transport's job (iroh handshake); these messages
//! carry no signatures, timestamps, or client identity fields. See
//! design/crypto-design.md section 5.

use serde::{Deserialize, Serialize};

/// ALPN identifier for the bunker protocol.
pub const ALPN: &[u8] = b"secret-bunker/1";

/// Maximum encoded message size accepted on a stream (either direction).
pub const MAX_MSG: usize = 4 * 1024 * 1024;

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
    Ok(postcard::to_stdvec(msg)?)
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> anyhow::Result<T> {
    Ok(postcard::from_bytes(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
