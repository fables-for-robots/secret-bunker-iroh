# Cryptography & Security Principles

This document describes the cryptographic design and security properties of
`secret-bunker-iroh`. It is intended for implementers and operators and
assumes familiarity with public-key cryptography, the age ecosystem, and
[iroh](https://www.iroh.computer) peer-to-peer QUIC transport.

`secret-bunker-iroh` is a re-design of `secret-bunker` on top of iroh. The
transport-layer properties of iroh (mutually authenticated, end-to-end
encrypted QUIC connections dialed by public key) replace the application-layer
signing and envelope encryption that the original design needed to survive
TLS-terminating middleboxes. Encryption at rest is unchanged.

## 1. Overview

`secret-bunker-iroh` stores secrets (tokens, passwords, configuration files)
on behalf of clients and serves them back over iroh connections. All secret
material is encrypted at rest with keys that the database alone cannot
reveal. The database is recoverable from an offline backup key in the event
of operational key compromise.

The security model of the network surface is:

> **Anyone may connect to the bunker over iroh. A connected peer can do
> nothing — not read, not write, not enumerate, not distinguish "denied"
> from "does not exist" — unless its iroh key has been granted access to
> some secrets.**

The service is single-tenant in its trust model: clients trust the operator
to run the binary correctly. It is not designed to defend clients from a
hostile operator.

## 2. Threat Model

### In scope

- Theft of the SQLite database file. An attacker who obtains the file alone
  cannot read any secret.
- Network adversaries between client and server, passive or active. iroh
  connections are end-to-end encrypted (QUIC / TLS 1.3) and mutually
  authenticated by ed25519 endpoint keys; there is nothing to eavesdrop on
  or modify.
- Untrusted relay servers. When a connection falls back to an iroh relay,
  the relay forwards opaque QUIC ciphertext. It cannot read or modify
  requests or responses. (It does learn connection metadata; see
  Non-Goals.)
- Probing by arbitrary peers. Because any iroh endpoint can dial the
  bunker, unauthorized peers must learn nothing: every request from an
  identity without the relevant permission receives the same uniform
  denial, whether the identity is unknown, known-but-unauthorized, or the
  target does not exist.
- Replay of captured traffic. QUIC's transport encryption binds application
  data to a connection's negotiated keys; captured packets cannot be
  replayed into a new session. Write requests additionally carry a
  version-CAS precondition, which serves concurrency control.
- Stolen client credentials. A revoked client identity loses access
  immediately via ACL change.
- Operational key compromise. Recovery from an offline backup keypair is
  supported.

### Out of scope

- A hostile server operator. The operational private key is online and the
  server decrypts secrets in memory to serve reads, so the operator can in
  principle read all secrets.
- *Write* access to the database file (as opposed to theft of a copy).
  The associated data binding stops ciphertext transplantation, but the
  current-version pointers and the recorded backup pubkey are plain
  unauthenticated rows: a writer can silently roll a secret back to an
  older retained version, or redirect future DEK wrapping to a key they
  hold. Whoever can write the SQLite file is the operator.
- Compromise of an authorized client's iroh secret key prior to revocation.
  Anything that client could fetch, the attacker can fetch.
- Side-channel attacks on the host running the service.
- Denial of service against the endpoint or its relays.
- Metadata privacy against relay and discovery infrastructure (see
  Non-Goals).

## 3. Identities and Keys

Every party on the wire is an iroh endpoint, identified by an
**EndpointId** — the public half of an ed25519 keypair. The same key that
identifies an endpoint authenticates its connections: iroh's handshake uses
TLS 1.3 with Raw Public Keys, so by the time application data flows, each
side has cryptographically verified the other's EndpointId.

### Server endpoint identity

A long-lived iroh ed25519 keypair. The secret key is held by the server
process, mounted from a Kubernetes Secret. The EndpointId derived from it is
the bunker's public address: clients dial it directly, and dialing it is
what authenticates the server — there is no CA, hostname, or certificate to
configure. Rotating this key changes the bunker's identity and requires all
clients to re-pin (see Key Lifecycle).

How clients *find* the addresses behind an EndpointId is a liveness
concern, not a security one — every path ends in the same mutually
authenticated handshake. The bunker announces itself three ways: its relay
URL is published to n0's DNS/pkarr discovery (dialable from anywhere, with
QUIC hole punching upgrading to a direct path when possible), it advertises
over mDNS on the local network (dialable with no internet at all), and
operators can hand out static socket addresses out of band. A wrong or
malicious discovery record can at worst deny service; it cannot redirect a
client to an impostor, because the EndpointId being dialed is the key that
must complete the handshake.

### Operational encryption identity

A long-lived X25519 keypair in native age format, distinct from the server
endpoint key. The private key is held by the server process. It is used
for:

- Unwrapping group data-encryption keys (DEKs) to serve reads.
- Wrapping new DEKs when creating a group or rotating a DEK.

It is kept separate from the endpoint key so that at-rest cryptography and
transport identity rotate independently: re-keying the node does not touch
the database, and re-wrapping DEKs does not change the bunker's address.

### Backup identity

A long-lived X25519 keypair in native age format. The **public** key is
supplied at service initialization and stored in the database. The
**private** key is held offline by the operator (paper, hardware token,
sealed envelope) and is never present on the server.

The backup public key is used to wrap every group DEK alongside the
operational pubkey. The backup private key is used only during disaster
recovery.

### Client identities

A client identity is exactly one iroh EndpointId. There is no separate
signing key, no encryption recipient, and no fingerprint scheme: the
EndpointId *is* the public key, and the transport handshake performs both
authentication and confidentiality. A client identity is registered by an
administrator and bound to a name and zero or more group ACLs.

Because the endpoint secret key must be available to the QUIC handshake,
client keys are software keys held by the client process.
Hardware-token-backed identities (FIDO2/PIV) from the original design do not
carry over; see Non-Goals.

## 4. Encryption at Rest

### Group DEK model

Each secret group has an associated 256-bit symmetric data-encryption key
(DEK). All secret values within a group are encrypted with the current DEK
using ChaCha20-Poly1305, with the tuple `(group, name, version, dek_version)`
bound as associated data so a ciphertext cannot be transplanted between
secrets or versions. The DEK is never stored in cleartext; it exists in two
wrapped forms:

- Wrapped to the operational public key (used for normal serving).
- Wrapped to the backup public key (used for disaster recovery).

Both wrappings are produced by encrypting the DEK as the body of an age
file with the two pubkeys as recipients.

DEKs are versioned. When a group DEK is rotated, the new DEK is wrapped to
both recipients and written as a new row. Old DEKs are retained because
historical secret versions remain encrypted under them.

### Storage layout

```
identity         registered EndpointId + name + service-admin flag
secret_group     group metadata
group_acl        which identities have which permissions on a group
group_dek        (group_id, version, wrapped_operational, wrapped_backup, ...)
secret           (group_id, name) — metadata only
secret_version   (secret_id, version, dek_version, nonce, ciphertext, ...)
audit_log        append-only request log with hash chain
```

The SQLite file contains EndpointIds (public material only), ACLs,
ciphertext, and wrapped DEKs. It contains no plaintext secrets and no
private keys. A leaked SQLite file is opaque to anyone without the
operational or backup private key.

## 5. Request Authentication

There is no application-layer signature scheme. Authentication is a
transport property:

- The server binds an iroh endpoint with the ALPN `secret-bunker/1` and
  accepts connections from any peer.
- iroh's handshake (TLS 1.3, Raw Public Key) proves possession of the
  peer's ed25519 secret key. The server reads the authenticated
  `EndpointId` from the connection; it cannot be spoofed without the
  corresponding secret key.
- Each request is one bidirectional QUIC stream: the client writes a
  request and closes its send side; the server responds on the return
  direction. Stream data is bound to the connection's transport keys, so
  requests cannot be captured and replayed into another session, reordered
  across connections, or attributed to the wrong peer.

Server-side processing order for every stream:

1. Read the authenticated EndpointId from the connection (already verified
   by the handshake; no parsing of attacker-controlled identity material).
2. Parse the request. A frame that fails to decode is answered with the
   same uniform `denied` response and audited (op `malformed`).
3. Look up the identity and check the ACL for the requested operation.
   Unknown identity, insufficient permission, and nonexistent target all
   produce the same `denied` response.
4. (Writes) Check the version precondition. Reject on mismatch.
5. Apply the operation and append to the audit log.

Uniformity of denials is a property of response *content*, not timing: the
denied paths do differing amounts of database work and no attempt is made
to normalize response latency (see Non-Goals).

What this removes relative to `secret-bunker`: `sshsig` envelopes,
canonical JSON, signing namespaces, timestamp windows, and the
verify-before-decrypt ordering concern — there is no client-supplied
ciphertext to decrypt and no client-supplied signature to verify.

### Replay and concurrency

Transport replay is prevented by QUIC. The `expected_version` field on
writes is retained purely as optimistic concurrency control between
legitimate writers: the server applies a write only if the current version
of the target secret equals `expected_version`.

## 6. Request and Response Confidentiality

iroh connections are end-to-end encrypted between the two endpoint keys.
There are no TLS-terminating intermediaries in the path: a relay, when
used, forwards ciphertext it cannot open. Consequently:

- Write requests carry plaintext secret values inside the encrypted
  transport, with no inner encryption envelope.
- Read responses carry plaintext secret values inside the encrypted
  transport, not wrapped to a per-client age recipient.

Plaintext secret values exist only in the memory of the two endpoint
processes. On the server, plaintext exists for the duration of one request
and is not logged. DEKs are zeroized on drop, and the request/response
buffers that carry plaintext (`Put` values, `Secret` responses) are
scrubbed after use on both server and client — best-effort hygiene, not a
guarantee: intermediate copies inside the CBOR and age libraries, and
whatever the consumer does with a fetched value, are out of reach.

The server obtains a secret's plaintext by:

1. Reading the ciphertext, nonce, and `dek_version` for the requested
   secret version.
2. Reading the wrapped DEK for that version.
3. age-decrypting the wrapped DEK with the operational identity.
4. Decrypting the secret ciphertext with the recovered DEK
   (ChaCha20-Poly1305, verifying the associated data).

## 7. Authorization

Connection is not authorization. The accept loop admits any peer; every
operation is gated on the ACL.

ACLs are per-group. Each `(identity, group)` pair carries a permission
bitmask:

- `read` (1): may fetch secrets from this group.
- `write` (2): may create, update, or delete secrets in this group.
- `admin` (4): may modify the ACL of this group and rotate its DEK.

Identities may be members of multiple groups with different permissions in
each. Service-level operations (creating groups, registering and removing
identities, toggling the service-admin flag) require the
**service-admin** flag on the caller's identity; the first service admin
is established at bootstrap. The flag also carries an implicit
`read|write|admin` on every group: a service admin is root. Granting the
flag (`AddIdentity` or `SetServiceAdmin`) therefore confers access to
all secrets, and revoking it (`SetServiceAdmin`) removes that access on
the target's next request; explicit ACL rows the identity holds survive
the revocation. Revoking the last service admin is refused, mirroring
the `RemoveIdentity` guard. Creating a group still grants the creator an
explicit `read|write|admin` on it in the same database transaction, so
every group keeps a group admin even if its creator later loses the
service-admin flag.

An *unregistered* identity — one the server has never seen — can do
nothing except open a connection and collect uniform denials. Denials do
not reveal whether a group or secret exists. Two deliberate refinements to
that uniformity, both scoped to already-authorized callers:

- A registered identity may always call `ListGroups` and receives its own
  (possibly empty) group list, so a key holder can confirm its own
  registration status. Nothing about other identities or ungranted groups
  is revealed.
- Within a group, the CAS feedback on writes (`VersionConflict` with the
  current version) is returned after the `write` check alone. `write`
  therefore implies visibility of secret existence and current versions in
  that group; `read` gates values and listing. Similarly, a *group
  admin* may list registered identity names (`ListIdentityNames`) to
  pick grant targets, and `Grant` confirms whether a target name exists;
  full identity records (endpoint ids, service-admin flags) remain
  service-admin-only.

ACL changes are themselves requests and require `admin` permission on the
target group. Because DEKs are wrapped only to the operational and backup
pubkeys — never to client identities — removing an identity from a group's
ACL takes effect immediately without re-wrapping. A subsequent DEK rotation
provides defense-in-depth against any plaintext the removed identity
captured before revocation.

A `Grant` that would leave a group with no explicit `admin` holder is
refused: an ACL edit is never urgent, and the guard keeps every group
manageable by its own admins without service-admin intervention.
Removing an *identity* is never blocked, though — revoking a compromised
key always wins, even when that orphans a group's ACL. The recovery path
for an orphaned group is the local `db grant` command, run by the operator
directly against the database (with the service stopped); it bypasses the
wire ACL checks, which is consistent with the trust model — local database
access is operator access — and it appends to the audit log like any other
mutation.

## 8. Key Lifecycle

### Initialization

A one-shot `init` command creates the SQLite file. Inputs:

- Server endpoint secret key (defaults to the XDG data directory,
  auto-generated on first use; in k8s, mounted from a Secret).
- Operational age private key (same defaulting).
- Backup public key (literal `age1...` value, supplied by the operator).
- First service-admin identity (an EndpointId, supplied by the operator).

The command records the operational pubkey, backup pubkey, and admin
identity, creates no groups, and exits. The service refuses to run `init`
against a populated database.

### Rotation

**Group DEK.** An admin issues a `rotate-dek` request for a group. The
server generates a new DEK, wraps it to operational and backup pubkeys, and
writes a new `group_dek` row. New writes use the new DEK; old secret
versions remain decryptable via the retained old DEK.

**Operational age keypair.** Generate a new keypair offline. Use the
existing operational private key (or, if unavailable, the backup private
key) to decrypt every wrapped DEK, then re-wrap to the new operational
pubkey. Replace the k8s Secret. The bunker's EndpointId is unaffected.

**Server endpoint keypair.** Generate a new iroh keypair and replace the
k8s Secret. This changes the bunker's EndpointId; every client must be told
the new id (out of band, or via a signed announcement from the old key
while it is still trusted). The database is unaffected. Plan this as a
rare, announced migration.

**Client identity.** The holder generates a new iroh keypair; a service
admin registers it as a new identity, group admins re-grant, and the old
identity is removed. There is deliberately no "replace the EndpointId on
an existing identity row" operation: it would let a service admin
silently assume an existing identity, corrupting the audit trail's
attribution of every subsequent request. Grants do not carry across the
swap for the same reason. No re-encryption is needed at any point
because DEKs are never wrapped to client identities.

### Revocation

Deleting an identity row (or its ACL rows) takes effect on the next
request. iroh connections are authenticated per-connection, not
per-session-token, so a revoked peer's existing connection can no longer
pass the ACL check on any subsequent stream.

## 9. Disaster Recovery

If the operational private key is suspected compromised:

1. Spin down the running service.
2. Generate a new operational age keypair offline.
3. On a clean machine, with the SQLite file copied offline and the backup
   private key available, run the recovery tool:
   - For every `group_dek` row, age-decrypt `wrapped_backup` with the
     backup identity.
   - Re-wrap the recovered DEK to the new operational pubkey.
   - Update `wrapped_operational` in place.
4. Replace the k8s Secret with the new operational private key.
5. Bring the service back up.

Compromise of the *endpoint* secret key does not expose stored secrets (it
grants the ability to impersonate the bunker to clients); respond by
rotating the endpoint key as in section 8.

The backup private key is the recovery root and must be stored with the
same care as a root CA key or password-manager master key. Suggested
practice: two paper copies in geographically separate safes, plus one on a
hardware token kept by the operator.

## 10. Operational Key Storage

The server holds two online secrets: the endpoint secret key and the
operational age private key. Outside Kubernetes, both (and the client's
endpoint key) default to `$XDG_DATA_HOME/secret-bunker-iroh` (falling back
to `~/.local/share/secret-bunker-iroh`), created mode 0700 with key files
mode 0600, and are auto-generated on first use. Key files are 0600 from
the moment they exist (`O_CREAT|O_EXCL` with the mode set at open) — there
is no create-then-chmod window in which another local user could read
them — and loading a key whose mode admits group/other access logs a
warning. The SQLite database is likewise forced to mode 0600 on every
open (SQLite's own default is 0644): it holds no plaintext secrets, but
its metadata — group and secret names, identity names and EndpointIds,
ACLs, the audit log — is not for other local users either. Auto-generation
applies only to these default paths: an explicitly supplied key path that
does not exist is an error, because silently minting a key there (e.g. on
a typo'd path) would change the endpoint's identity. The `key
show|generate|export|import` commands manage these files; exported material
is the raw secret and must be transported accordingly. `client put
--value` warns that argv is visible to the local process list; pipe values
via stdin instead.

In Kubernetes, mount both server secrets and protect them as follows:

- Mount as files, not as environment variables. Env vars leak through
  `/proc/<pid>/environ`, crash dumps, and child processes.
- Restrict the Secret to a dedicated namespace and ServiceAccount. Deny
  `get`/`list` on `secrets` cluster-wide via RBAC.
- Enable etcd encryption-at-rest with a KMS provider. Default base64 is
  not encryption.
- Use sealed-secrets or external-secrets pointing at an external KMS so
  cleartext private keys never sit in the gitops repo.
- Treat operational-key rotation as a routine procedure (see section 8),
  not an emergency response.

## 11. Cryptographic Primitives Summary

| Purpose | Primitive | Library |
|---|---|---|
| Transport auth + encryption | QUIC / TLS 1.3 RPK, ed25519 EndpointIds | `iroh` |
| Symmetric secret encryption (DEK) | ChaCha20-Poly1305 | `chacha20poly1305` |
| Wrapping DEKs to public keys | X25519 + ChaCha20-Poly1305 via age | `age` |
| Audit-log hash chain | SHA-256 | `sha2` |

## 12. Non-Goals

The following are explicitly not provided:

- **Defense against a hostile operator.** The server decrypts secrets in
  memory to serve reads, so the operator can read all plaintexts in
  principle.
- **Forward secrecy for stored secrets.** A future leak of the backup
  private key allows decryption of past database snapshots.
- **Multi-party / threshold key management.** A single operational private
  key and a single backup private key.
- **Hardware-backed client keys.** The iroh handshake requires the ed25519
  secret key in process memory; FIDO2/PIV tokens cannot participate. If
  hardware-bound client identity is a requirement, the original
  `secret-bunker` design serves it better.
- **Metadata privacy against infrastructure.** Relays and discovery
  services learn EndpointIds, connection timing, and traffic volume — not
  content. Anyone who learns the bunker's EndpointId can also confirm that
  an endpoint with that id is online. With mDNS enabled (the default),
  anyone on the same network segment sees the bunker's EndpointId and
  addresses announced; run with `--no-mdns` where that matters.
- **Timing-uniform denials.** The `denied` response is byte-identical
  across its causes, but the paths that produce it do different amounts of
  database work, so a patient network observer may distinguish them
  statistically. No latency normalization is attempted.
- **Audit-log integrity beyond append-only hash chaining.** The chain
  detects in-place edits, but not truncation from the tail (a shortened
  chain still verifies), and appends are best-effort — an operation is not
  rolled back if its audit insert fails. A privileged operator can rewrite
  history if the log lives in the same SQLite file as the data. `db
  audit-verify` checks the chain and prints the head `(seq, hash)`; record
  that head externally (or ship the log to an external sink) where
  truncation matters.
