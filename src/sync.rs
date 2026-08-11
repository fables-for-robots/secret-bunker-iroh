//! Wire protocol for `secret-bunker-sync/1`: replica-to-authoritative
//! group/secret synchronization over a single long-lived bidirectional QUIC
//! stream. Unlike `proto` (one request per stream, whole-stream read), a
//! sync stream carries a sequence of independent CBOR messages, so each is
//! length-prefixed: a 4-byte big-endian `u32` byte count followed by the
//! CBOR body (see [`frame`]/[`deframe`]).
//!
//! Authentication is the transport's job (iroh handshake), as with `proto`.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::proto;

/// ALPN identifier for the replication protocol.
pub const SYNC_ALPN: &[u8] = b"secret-bunker-sync/1";

/// Strictly above the client protocol's 4 MiB MAX_MSG so any legal secret
/// fits one SecretData frame (ciphertext = plaintext + 16B tag + metadata).
pub const SYNC_MAX_MSG: usize = 8 * 1024 * 1024;

// WIRE CONTRACT: variant and field NAMES are the CBOR encoding. No
// non-Rust implementation of this protocol exists yet, but any that
// appears will match them as strings — never rename a variant or field;
// adding variants is fine. Guarded by the wire_format_is_stable test
// below.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncRequest {
    Hello,
    FetchGroup { group: String },
    FetchSecrets { group: String, names: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncMessage {
    /// Uniform denial: unregistered peer, unauthorized or unknown group.
    SyncDenied,
    Group {
        name: String,
        acl: Vec<AclEntry>,
        deks: Vec<DekEntry>,
    },
    GroupSecrets {
        group: String,
        secrets: Vec<SecretEntry>,
    },
    ManifestDone,
    FetchDone,
    Changed {
        group: String,
    },
    ScopeChanged,
    SecretData {
        name: String,
        version: u64,
        dek_version: u64,
        #[serde(with = "serde_bytes")]
        nonce: Vec<u8>,
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
        created_at: i64,
        created_by: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AclEntry {
    pub identity_name: String,
    pub endpoint_id: String,
    pub perms: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DekEntry {
    pub version: u64,
    #[serde(with = "serde_bytes")]
    pub wrapped: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEntry {
    pub name: String,
    pub current_version: u64,
    pub dek_version: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

/// The latest received state of one group — the manifest's `Group` and
/// `GroupSecrets` messages assembled into the target a replica's local
/// mirror converges onto (see [`crate::store::Store::apply_group_sync`]).
/// Not a wire type: it is only ever built locally from received messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupSyncState {
    pub name: String,
    pub acl: Vec<AclEntry>,
    pub deks: Vec<DekEntry>,
    pub secrets: Vec<SecretEntry>,
}

/// One secret's full current version as fetched from the authoritative
/// node: the payload of a [`SyncMessage::SecretData`], ready to apply.
/// Still ciphertext — sync never decrypts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedSecret {
    pub name: String,
    pub version: u64,
    pub dek_version: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub created_at: i64,
    pub created_by: String,
}

/// Rejects a body length declaring more than [`SYNC_MAX_MSG`] bytes. Shared
/// by [`frame`] (checked on the encoded body, before send) and [`deframe`]
/// and [`read_msg`] (checked on the declared length, before allocating a
/// buffer to read the body into).
fn check_cap(len: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        len <= SYNC_MAX_MSG,
        "sync frame of {len} bytes exceeds {SYNC_MAX_MSG}-byte cap"
    );
    Ok(())
}

/// Encodes `msg` as a length-prefixed frame: 4-byte big-endian `u32` byte
/// count followed by the CBOR body. Errors (without producing any output)
/// if the encoded body would exceed [`SYNC_MAX_MSG`].
pub fn frame<T: Serialize>(msg: &T) -> anyhow::Result<Vec<u8>> {
    let body = proto::encode(msg)?;
    check_cap(body.len())?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parses one length-prefixed frame from the front of `bytes`, returning
/// the decoded message and the total number of bytes consumed (4 + body
/// length). Errors if the declared length exceeds [`SYNC_MAX_MSG`] or
/// `bytes` doesn't hold a complete frame.
pub fn deframe<T: DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<(T, usize)> {
    anyhow::ensure!(
        bytes.len() >= 4,
        "sync frame: truncated length prefix ({} of 4 bytes)",
        bytes.len()
    );
    let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    check_cap(len)?;
    anyhow::ensure!(
        bytes.len() >= 4 + len,
        "sync frame: truncated body ({} of {len} bytes)",
        bytes.len() - 4
    );
    let msg = proto::decode(&bytes[4..4 + len])?;
    Ok((msg, 4 + len))
}

/// Writes one length-prefixed message to `send`. The [`SYNC_MAX_MSG`] cap
/// is enforced before anything is written to the stream.
pub async fn write_msg<T: Serialize>(
    send: &mut iroh::endpoint::SendStream,
    msg: &T,
) -> anyhow::Result<()> {
    let bytes = frame(msg)?;
    send.write_all(&bytes).await?;
    Ok(())
}

/// Reads one length-prefixed message from `recv`. Returns `Ok(None)` on a
/// clean end-of-stream (no bytes at all before the next message would have
/// started). The [`SYNC_MAX_MSG`] cap is enforced on the declared length
/// before a buffer is allocated to hold the body.
pub async fn read_msg<T: DeserializeOwned>(
    recv: &mut iroh::endpoint::RecvStream,
) -> anyhow::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(iroh::endpoint::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    check_cap(len)?;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    Ok(Some(proto::decode(&body)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn golden_group_secrets() -> SyncMessage {
        SyncMessage::GroupSecrets {
            group: "g".into(),
            secrets: vec![SecretEntry {
                name: "n".into(),
                current_version: 1,
                dek_version: 2,
                nonce: vec![9, 9, 9],
            }],
        }
    }

    /// One `AclEntry` and one `DekEntry`, the two struct types nested
    /// inside a `Group` message that had no byte-level pin of their own.
    fn golden_group() -> SyncMessage {
        SyncMessage::Group {
            name: "g".into(),
            acl: vec![AclEntry {
                identity_name: "a".into(),
                endpoint_id: "e".into(),
                perms: 1,
            }],
            deks: vec![DekEntry {
                version: 1,
                wrapped: vec![0xAB],
            }],
        }
    }

    fn golden_secret_data() -> SyncMessage {
        SyncMessage::SecretData {
            name: "n".into(),
            version: 1,
            dek_version: 1,
            nonce: vec![0x01],
            ciphertext: vec![0x02],
            created_at: 5,
            created_by: "c".into(),
        }
    }

    /// CBOR golden vectors pinning the sync wire format. A failure here
    /// means the format changed and every non-Rust implementation breaks.
    /// Self-contained for now: unlike `proto`'s vectors these have no
    /// counterpart in another language yet, and should gain one in
    /// lockstep once a non-Rust replica exists.
    #[test]
    fn wire_format_is_stable() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (proto::encode(&SyncRequest::Hello).unwrap(), "6548656c6c6f"),
            (
                proto::encode(&SyncRequest::FetchGroup { group: "g".into() }).unwrap(),
                "a16a466574636847726f7570a16567726f75706167",
            ),
            (
                proto::encode(&SyncMessage::SyncDenied).unwrap(),
                "6a53796e6344656e696564",
            ),
            (
                proto::encode(&SyncMessage::Changed { group: "g".into() }).unwrap(),
                "a1674368616e676564a16567726f75706167",
            ),
            (
                proto::encode(&golden_group_secrets()).unwrap(),
                "a16c47726f757053656372657473a26567726f75706167677365637265747381a4646e616d65616e6f63757272656e745f76657273696f6e016b64656b5f76657273696f6e02656e6f6e636543090909",
            ),
            (
                proto::encode(&golden_group()).unwrap(),
                "a16547726f7570a3646e616d6561676361636c81a36d6964656e746974795f6e616d6561616b656e64706f696e745f69646165657065726d73016464656b7381a26776657273696f6e01677772617070656441ab",
            ),
            (
                proto::encode(&golden_secret_data()).unwrap(),
                "a16a53656372657444617461a7646e616d65616e6776657273696f6e016b64656b5f76657273696f6e01656e6f6e636541016a6369706865727465787441026a637265617465645f6174056a637265617465645f62796163",
            ),
        ];
        for (bytes, expected) in cases {
            assert_eq!(hex(&bytes), expected);
        }
    }

    #[test]
    fn sync_request_roundtrip() {
        for req in [
            SyncRequest::Hello,
            SyncRequest::FetchGroup { group: "g".into() },
            SyncRequest::FetchSecrets {
                group: "g".into(),
                names: vec!["a".into(), "b".into()],
            },
        ] {
            let bytes = proto::encode(&req).unwrap();
            assert_eq!(proto::decode::<SyncRequest>(&bytes).unwrap(), req);
        }
    }

    #[test]
    fn sync_message_roundtrip() {
        for msg in [
            SyncMessage::SyncDenied,
            SyncMessage::Group {
                name: "g".into(),
                acl: vec![AclEntry {
                    identity_name: "alice".into(),
                    endpoint_id: "abcd".into(),
                    perms: 7,
                }],
                deks: vec![DekEntry {
                    version: 1,
                    wrapped: vec![1, 2, 3],
                }],
            },
            golden_group_secrets(),
            SyncMessage::ManifestDone,
            SyncMessage::FetchDone,
            SyncMessage::Changed { group: "g".into() },
            SyncMessage::ScopeChanged,
            SyncMessage::SecretData {
                name: "n".into(),
                version: 3,
                dek_version: 1,
                nonce: vec![1, 2, 3],
                ciphertext: vec![4, 5, 6, 7],
                created_at: 1_700_000_000,
                created_by: "alice".into(),
            },
        ] {
            let bytes = proto::encode(&msg).unwrap();
            assert_eq!(proto::decode::<SyncMessage>(&bytes).unwrap(), msg);
        }
    }

    #[test]
    fn frame_prefixes_with_big_endian_length() {
        let msg = SyncRequest::FetchGroup { group: "g".into() };
        let body = proto::encode(&msg).unwrap();
        let framed = frame(&msg).unwrap();
        assert_eq!(framed.len(), 4 + body.len());
        assert_eq!(
            u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize,
            body.len()
        );
        assert_eq!(&framed[4..], &body[..]);
    }

    #[test]
    fn deframe_roundtrips_frame() {
        let msg = SyncMessage::Changed { group: "g".into() };
        let framed = frame(&msg).unwrap();
        // Extra trailing bytes simulate a second frame following in the
        // same buffer; deframe must report exactly how much it consumed.
        let mut buf = framed.clone();
        buf.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let (decoded, consumed): (SyncMessage, usize) = deframe(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn frame_rejects_oversize_message() {
        let msg = SyncMessage::SecretData {
            name: "n".into(),
            version: 1,
            dek_version: 1,
            nonce: vec![0; 12],
            ciphertext: vec![0u8; SYNC_MAX_MSG + 1],
            created_at: 0,
            created_by: "x".into(),
        };
        let err = frame(&msg).unwrap_err();
        assert!(
            err.to_string().contains("frame"),
            "error should mention \"frame\": {err}"
        );
    }

    #[test]
    fn deframe_rejects_oversize_length_prefix() {
        let mut buf = ((SYNC_MAX_MSG + 1) as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 8]); // irrelevant trailing bytes
        let err = deframe::<SyncRequest>(&buf).unwrap_err();
        assert!(
            err.to_string().contains("frame"),
            "error should mention \"frame\": {err}"
        );
    }

    #[test]
    fn deframe_rejects_truncated_length_prefix() {
        let err = deframe::<SyncRequest>(&[0, 0]).unwrap_err();
        assert!(
            err.to_string().contains("frame"),
            "error should mention \"frame\": {err}"
        );
    }

    #[test]
    fn deframe_rejects_truncated_body() {
        let framed = frame(&SyncRequest::Hello).unwrap();
        let err = deframe::<SyncRequest>(&framed[..framed.len() - 1]).unwrap_err();
        assert!(
            err.to_string().contains("frame"),
            "error should mention \"frame\": {err}"
        );
    }
}
