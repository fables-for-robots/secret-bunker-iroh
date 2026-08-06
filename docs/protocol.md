# The secret-bunker Wire Protocol

This document specifies how a client talks to a `secret-bunker-iroh`
server: the transport, the framing, the CBOR message encoding, every
request and response, and the compatibility rules. The reference
implementations are the Rust crate in this repository (`src/proto.rs`,
`src/server.rs`, `src/client.rs`) and the Go client in
[go-secret-bunker-iroh](https://github.com/fables-for-robots/go-secret-bunker-iroh).

## 1. Transport

All communication runs over an [iroh](https://www.iroh.computer)
connection — QUIC with TLS 1.3 Raw Public Keys, dialed by the server's
EndpointId — under the ALPN:

```
secret-bunker/1
```

There is no application-layer authentication. The QUIC handshake mutually
proves possession of both ed25519 keys, so by the time application data
flows the server knows the client's EndpointId and vice versa. That
EndpointId **is** the client's identity: the server looks it up in its
identity table and checks its ACLs on every request. Messages therefore
carry no signatures, session tokens, timestamps, or identity fields.

Anyone may connect. A peer whose EndpointId is unknown to the server can
open streams and send requests, but every one of them is answered with the
uniform `"Denied"` response (section 6).

## 2. Framing

One request/response exchange per **bidirectional QUIC stream**:

1. The client opens a bi-directional stream.
2. It writes exactly one CBOR-encoded `Request` and half-closes its send
   side (QUIC FIN). The stream EOF is the frame delimiter — there is no
   length prefix.
3. The server reads to EOF, processes the request, writes exactly one
   CBOR-encoded `Response`, and finishes its send side.
4. The client reads to EOF.

Streams are independent; a client may run many requests concurrently on
one connection, and a connection stays usable for any number of requests.
Either side rejects messages larger than **4 MiB** (`MAX_MSG`).

Permission changes take effect immediately: the identity is re-checked on
every request, so revoking an ACL entry affects the very next stream on an
already-open connection.

## 3. Message encoding

Messages are [CBOR](https://www.rfc-editor.org/rfc/rfc8949) documents in
serde's **externally-tagged enum representation**:

- A variant **without fields** is a bare text string:

  ```
  "ListGroups"
  ```

- A variant **with fields** is a map with exactly one entry, keyed by the
  variant name; the value is a map of the fields:

  ```
  {"Get": {"group": "prod", "name": "db"}}
  ```

- Field values use the natural CBOR types: text strings, unsigned
  integers (shortest form), booleans, arrays. Secret values (`value` in
  `Put` and `Secret`) are CBOR **byte strings** (major type 2), so they
  are binary-safe.

- Rust tuples encode as fixed-length arrays: the `(name, version)` pairs
  in `Names` are two-element arrays, as are the `(identity, perms)` pairs
  in `Acl`.

**Variant and field names are the wire contract.** Decoders match them as
strings; unknown variants are an error, unknown fields inside a known
variant should be ignored. See section 7.

Examples below use CBOR diagnostic notation, with `h'..'` for byte
strings.

## 4. An annotated exchange

Client fetches `db` from group `prod` — the encoded request is
`{"Get": {"group": "prod", "name": "db"}}`:

```
a1                      # map(1)               — the variant envelope
   63 476574            #   text(3) "Get"      — variant name
   a2                   #   map(2)             — the fields
      65 67726f7570     #     text(5) "group"
      64 70726f64       #     text(4) "prod"
      64 6e616d65       #     text(4) "name"
      62 6462           #     text(2) "db"
```

Server replies `{"Secret": {"value": h'6869', "version": 128}}`:

```
a1                      # map(1)
   66 536563726574      #   text(6) "Secret"
   a2                   #   map(2)
      65 76616c7565     #     text(5) "value"
      42 6869           #     bytes(2) h'6869'  — the plaintext, "hi"
      67 76657273696f6e #     text(7) "version"
      18 80             #     unsigned(128)
```

Had the caller lacked `read` on `prod` — or had the group or secret not
existed — the reply would have been the seven bytes of `"Denied"`:

```
66 44656e696564         # text(6) "Denied"
```

## 5. Requests

Permissions are per-group bitmasks: `read` (1), `write` (2), `admin` (4).
Service-level operations require the caller's identity to carry the
**service-admin** flag. "→" lists the success responses; every request can
also produce `Denied` or `Failed` (section 6).

### Secrets

| Request | Requires | → |
|---|---|---|
| `Get` | `read` | `Secret` |
| `Put` | `write` | `Version`, `VersionConflict` |
| `Delete` | `write` | `Ok`, `VersionConflict` |
| `List` | `read` | `Names` |

```
{"Get":    {"group": "prod", "name": "db"}}
{"Put":    {"group": "prod", "name": "db", "value": h'68756e74657232',
            "expected_version": 3}}
{"Delete": {"group": "prod", "name": "db", "expected_version": 4}}
{"List":   {"group": "prod"}}
```

Writes are compare-and-set: `expected_version` must equal the secret's
current version, with `0` meaning "create; must not exist yet". On
mismatch the server replies `VersionConflict` with the current version and
changes nothing. This is concurrency control between legitimate writers —
transport replay is already impossible at the QUIC layer.

### Groups and ACLs

| Request | Requires | → |
|---|---|---|
| `ListGroups` | any registered identity | `Groups` |
| `GroupAcl` | `admin` on the group | `Acl` |
| `ListIdentityNames` | `admin` on the group | `IdentityNames` |
| `Grant` | `admin` on the group | `Ok` |
| `RotateDek` | `admin` on the group | `Ok` |
| `CreateGroup` | service admin | `Ok` |

```
"ListGroups"
{"GroupAcl":           {"group": "prod"}}
{"ListIdentityNames":  {"group": "prod"}}
{"Grant":              {"group": "prod", "identity": "ci", "perms": 3}}
{"RotateDek":          {"group": "prod"}}
{"CreateGroup":        {"name": "prod"}}
```

`ListIdentityNames` exists so a group admin can pick `Grant` targets
without service-admin rights: it returns every registered identity's
name — and only the name, no endpoint ids or service-admin flags
(contrast `ListIdentities`).

`Grant` sets the full bitmask (`perms: 0` revokes). Creating a group
grants the creator `read|write|admin` on it, so every group has a group
admin from the moment it exists. A `Grant` that would strip the `admin`
bit from a group's only admin fails (`Failed`), so a group can never be
left unmanageable through the protocol; `RemoveIdentity` is deliberately
*not* guarded this way — revoking a compromised identity always works,
and an orphaned group is recovered with the server-local `db grant`
command.

### Identities

All three require service admin.

```
{"AddIdentity":    {"name": "ci",
                    "endpoint_id": "1a984b…(64 hex chars)…27b6",
                    "service_admin": false}}
{"RemoveIdentity": {"name": "ci"}}
"ListIdentities"
```

EndpointIds are the 64-character lowercase-hex encoding of the ed25519
public key.

## 6. Responses

```
"Denied"
"Ok"
{"Secret":          {"value": h'68756e74657232', "version": 4}}
{"Version":         {"version": 5}}
{"VersionConflict": {"current": 4}}
{"Names":           [["api-token", 2], ["db-password", 4]]}
{"Identities":      [{"name": "admin",
                      "endpoint_id": "c535…(hex)…b2c1",
                      "service_admin": true}]}
{"Groups":          {"service_admin": false,
                     "groups": [{"name": "prod", "perms": 3}]}}
{"Acl":             [["admin", 7], ["ci", 1]]}
{"IdentityNames":   ["admin", "ci"]}
{"Failed":          {"reason": "group 'prod' already exists"}}
```

Notes:

- **`Denied` is deliberately uniform.** Unknown identity, insufficient
  permission, and nonexistent group/secret are indistinguishable, so a
  connected-but-unauthorized peer cannot enumerate anything, and even an
  authorized reader cannot distinguish "deleted" from "never existed".
  A frame that does not decode as a `Request` gets the same `Denied`.
- **`Failed` is only sent after authorization succeeded**, so its
  `reason` may be informative. Unauthorized callers never see it.
- **`VersionConflict` is sent after only the `write` check**, and it
  reports the current version. Holding `write` on a group therefore
  implies seeing which secrets exist there and at what version, even
  without `read`; `read` gates values and `List`.
- `Groups.service_admin` reports the *caller's* role; each entry's
  `perms` is the caller's own bitmask on that group (service admins see
  all groups, including ones where their bitmask is 0).
- `Version` answers a successful `Put`; `Ok` answers the other mutations.

## 7. Compatibility

- Variant and field **names are the contract** — never rename them.
  Adding new variants or fields is backwards-compatible; decoders must
  treat an unknown *response* variant as an error and should ignore
  unknown fields within known variants.
- Both implementations pin the encoding with shared golden vectors:
  `proto::tests::wire_format_is_stable` here and `proto_test.go` in the
  Go client. Change the format only by updating both in lockstep.
- Protocol revisions that break these rules must bump the ALPN
  (`secret-bunker/2`), not mutate `secret-bunker/1`.

## 8. What the protocol does *not* do

For the security model — encryption at rest, key lifecycle, threat model,
and why there is no application-layer crypto in these messages — see
[`../design/crypto-design.md`](../design/crypto-design.md). In short: the
transport provides authentication, confidentiality, integrity, and replay
protection; the messages themselves are plaintext *inside* that encrypted
channel and never leave it.
