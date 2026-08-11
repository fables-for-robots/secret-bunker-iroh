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
  cannot read any secret: every DEK in it is wrapped, and the file holds no
  private key. Note the recipient set has widened — see "Stolen database
  files and reader keys" below.
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
- Stolen client credentials. At the authoritative node, a revoked client
  identity loses access immediately via the ACL change, and revoking its
  `read` additionally rotates the group DEK in the same transaction, so
  nothing written after the revocation is protected by a key the revoked
  identity ever held. What it already fetched or mirrored cannot be
  clawed back, and a replica enforces the revocation only once it applies
  the sync carrying it — see "Replicas" below and section 7.
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
  Anything that client could fetch, the attacker can fetch — and, since
  DEKs are wrapped to readers, can also decrypt from any copy of the
  database or of a mirror covering those groups.
- Side-channel attacks on the host running the service.
- Denial of service against the endpoint or its relays.
- Metadata privacy against relay and discovery infrastructure (see
  Non-Goals).

### Stolen database files and reader keys

Group DEKs are wrapped to every identity holding an explicit `read` grant
on the group, not only to the operational and backup keys (section 4). Two
consequences, both accepted deliberately as the price of "any reader can
run a replica":

- A stolen SQLite file is no longer opaque to everyone but the
  operational- and backup-key holders. It is decryptable by **any
  read-granted identity's iroh secret key**, for the groups that identity
  can read. The blast radius of a leaked client key now includes the
  database file, not just the wire.
- A stolen **replica** database exposes, with no key at all, the mirrored
  metadata: group names, secret names and versions, and the full ACL
  rosters (identity names, endpoint ids, permission bits) of the groups
  the replica mirrors. Its ciphertext still needs the replica's endpoint
  secret key.

Replication also widens *live* metadata visibility: a read grant used for
sync delivers the group's whole roster to the grantee — data that on the
client protocol is admin-gated (`GroupAcl`, `ListIdentityNames`) or
service-admin-gated (endpoint ids via `ListIdentities`). The replica needs
it to authorize its own clients. See
[`../docs/sync-protocol.md`](../docs/sync-protocol.md) section 4.

### Replica trust model

A replica is a reader, and nothing more. Compromising it compromises
exactly the groups its key can read — the same blast radius as
compromising the client identity it runs as. It holds no operational key,
no backup key, and no wrap addressed to anyone else, so it cannot read a
group it was never granted, cannot mint DEK versions, and cannot be
promoted by anything in its own database (`service_admin` is pinned to 0
on every mirrored identity row).

The one property a replica does *not* inherit is revocation timeliness:
an ACL change binds there only once the replica has synced it, with no
upper bound while it is partitioned (sections 7 and 12).

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
signing key, no *registered* encryption key, and no fingerprint scheme: the
EndpointId *is* the public key, and the transport handshake performs both
authentication and confidentiality. A client identity is registered by an
administrator and bound to a name and zero or more group ACLs.

Because the endpoint secret key must be available to the QUIC handshake,
client keys are software keys held by the client process.
Hardware-token-backed identities (FIDO2/PIV) from the original design do not
carry over; see Non-Goals.

### Derived age recipients

Every identity is also an **age recipient, derived from the EndpointId it
already has** — no second keypair, no registration step, nothing to
distribute. This is what lets a group DEK be wrapped to a reader
(section 4), and hence what lets any reader run a replica.

The derivation is the standard ed25519 → X25519 conversion (`src/agebridge.rs`):

- **Recipient (public), computable by anyone** from the EndpointId stored
  in the `identity` table: the ed25519 public key is mapped to its
  Montgomery form (the birational Edwards→Montgomery map) and Bech32-encoded
  with the `age` HRP, giving an `age1…` recipient.
- **Identity (secret), computable only by the key holder**: the iroh secret
  key's SHA-512-expanded scalar half is Bech32-encoded with the
  `AGE-SECRET-KEY-` HRP. `identity.to_public()` equals the publicly derived
  recipient, so a wrap made from the EndpointId opens with the endpoint key
  and nothing else.

Three notes on why this is safe and why it is done this way:

- Reusing one ed25519 keypair for signatures *and* an X25519-based KEM is
  established practice (age's `ssh-ed25519` stanzas, ssh-to-age/sops-nix,
  libsodium) and has a formal joint-security analysis: Thormarker, *On
  using the same key pair for Ed25519 and an X25519 based KEM*, IACR ePrint
  [2021/509](https://eprint.iacr.org/2021/509). The iroh key's existing
  TLS signing use stays inside the analyzed signing + ECDH model.
- The conversion is **native X25519**, deliberately *not* age's `ssh`
  feature: ssh-ed25519 stanzas apply an extra HKDF tweak and would not
  interoperate with this derivation.
- The Bech32 round-trip is not decoration: the pinned age version exposes
  only Bech32-string constructors for its x25519 types. Only `[u8; 32]`
  arrays and Bech32 strings cross the bridge, so the two curve25519 stacks
  in the dependency tree never exchange types.

The derivation is pinned by a golden vector
(`agebridge::tests::derivation_golden_vector`): if it ever changed
silently, every stored reader wrap would become unreadable.

## 4. Encryption at Rest

### Group DEK model

Each secret group has an associated 256-bit symmetric data-encryption key
(DEK). All secret values within a group are encrypted with the current DEK
using ChaCha20-Poly1305, with the tuple `(group, name, version, dek_version)`
bound as associated data so a ciphertext cannot be transplanted between
secrets or versions. The DEK is never stored in cleartext; it exists only
as **one wrap per recipient**, each produced by encrypting the DEK as the
body of an age file addressed to that recipient:

| `dek_wrap.recipient` | Held by | Used for |
|---|---|---|
| `operational` | the server process | normal serving (unwrap to read, re-wrap on rotation) |
| `backup` | the operator, offline | disaster recovery |
| a 64-char lowercase-hex EndpointId | that identity | the identity's own reads from a mirror it replicates |

The third row type is the SOPS-style part: **every identity holding an
explicit `read` grant on the group gets its own wrap**, addressed to the
age recipient derived from its EndpointId (section 3). It is what lets a
reader mirror the group and serve it from its own database. The
service-admin flag's implicit read deliberately creates **no** wraps — it
is an authorization rule only, so that revoking a service admin does not
force rotating every group in the bunker. A service admin that should run
a replica gets explicit read grants.

DEKs are versioned. When a group DEK is rotated, the new DEK is wrapped to
the full current recipient set and written as a new version. Old DEK
versions are retained because historical secret versions remain encrypted
under them — which is also why *every retained version*, not just the
current one, is wrapped to a new reader.

### Wrap lifecycle

| Event | Effect on wraps |
|---|---|
| `CreateGroup` | DEK v1 wrapped to `operational`, `backup`, and the creator (whose grant carries `read`), in the group's creation transaction |
| `Grant` gaining `read` | every retained DEK version is unwrapped with the operational key and re-wrapped to the grantee, in the same transaction as the ACL row |
| `Grant` losing `read` | the identity's wraps (all versions) are deleted **and the group DEK is auto-rotated**, in one transaction |
| `RemoveIdentity` | the same delete + auto-rotate, for **every** group the identity could read, all in one transaction — a crash can never leave a revocation half-applied |
| `RotateDek` | a new version wrapped to `operational`, `backup`, and every current reader; nobody loses access to what they were granted |
| `recover` | the `operational` row of each DEK version is replaced in place; reader and backup wraps are untouched |
| `serve` startup | idempotent backfill: any missing `(group, version, read-granted identity)` wrap is minted before the sync ALPN starts accepting sessions |

Rotation needs **no private key**: a fresh DEK is generated and wrapped
outward to public recipients only. Handing a *new* reader the retained
versions does need the operational key, because those DEKs must be
unwrapped first — which is why the offline `db grant` command resolves the
operational key for read grants and for nothing else.

The startup backfill exists so that a database predating per-reader
wrapping becomes fully wrapped on the first boot of the new binary, and it
runs *before* replication is served so a replica can never receive a
manifest with its own wraps still missing.

### Storage layout

```
meta             schema version, role, operational/backup pubkeys, replica stamps
identity         registered EndpointId + name + service-admin flag
secret_group     group metadata
group_acl        which identities have which permissions on a group
group_dek        (group_id, version, created_at) — the DEK version registry
dek_wrap         (group_id, dek_version, recipient, wrapped, created_at)
secret           (group_id, name) — metadata only
secret_version   (secret_id, version, dek_version, nonce, ciphertext, ...)
audit_log        append-only request log with hash chain
```

`group_dek` carried the two wrapped blobs as columns in schema v1; v2 moved
them into `dek_wrap` rows (`'operational'`, `'backup'`) and made
`group_dek` a bare version registry. The migration is pure SQL and applies
on open; reader wraps cannot be minted by SQL alone (they need the
operational key to unwrap what they re-wrap) and are backfilled at `serve`
startup instead.

The SQLite file contains EndpointIds (public material only), ACLs,
ciphertext, and wrapped DEKs. It contains no plaintext secrets and no
private keys. A leaked SQLite file is opaque to anyone holding none of the
private keys its wraps are addressed to — which since schema v2 includes
every read-granted identity's endpoint key, not just the operational and
backup keys (section 2).

## 5. Request Authentication

There is no application-layer signature scheme. Authentication is a
transport property:

- The server binds an iroh endpoint with the ALPN `secret-bunker/1` and
  accepts connections from any peer. An authoritative node additionally
  serves `secret-bunker-sync/1` on the same endpoint for replication,
  authenticated identically and authorized by explicit `read` grants alone
  (see [`../docs/sync-protocol.md`](../docs/sync-protocol.md)).
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

A replica runs the identical path with two substitutions: it opens the wrap
addressed to its own EndpointId, using the age identity derived from its
endpoint key (section 3). It has no operational key and no other wrap to
try.

Replication itself carries no plaintext: a sync stream ships ciphertext,
the caller's own wraps, and metadata, never an unwrapped DEK and never a
wrap addressed to anyone else (see
[`../docs/sync-protocol.md`](../docs/sync-protocol.md) section 4).

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
target group.

### Revocation

Since group DEKs are wrapped to readers (section 4), revoking access is two
things at once, and the implementation does both in a single transaction:
it deletes the ACL row (or clears the `read` bit) **and** deletes that
identity's wraps and auto-rotates the group DEK. `RemoveIdentity` does it
for every group the identity could read at once. What that buys, precisely:

- **At the authoritative node the denial is instant.** Identity and ACL are
  re-checked on every request, so the very next stream on an already-open
  connection is refused — connections carry no session token to outlive
  the change.
- **Future writes are protected.** Every secret written after the rotation
  is encrypted under a DEK version the revoked identity has no wrap for,
  so a stashed copy of the old DEK decrypts nothing new.
- **Already-synced copies cannot be clawed back.** Ciphertext and wraps a
  reader mirrored before the revocation stay readable by it. Rotation does
  not re-encrypt existing secret versions — old versions stay under old
  DEKs by design — so revocation is forward protection, never retroactive
  erasure. Treat a secret a revoked reader could read as compromised and
  rewrite it; that write lands under the new DEK.
- **A replica enforces a revocation only when it syncs it.** The ACL
  travels with the mirror, so until the replica applies the sync carrying
  the change, a revoked third party can still read its formerly-granted
  groups *through that replica*. While the authoritative node is down or
  the replica is partitioned, that window is unbounded — see section 12.

### Replicas

A replica authorizes strictly by the explicit ACL rows it mirrored. The
permission check is the same shared code as the authoritative node's, with
the service-admin bypass switched off: `service_admin` is pinned to 0 on
every mirrored identity row *and* the replica passes "no implicit admin"
on every call, so neither a synced flag nor a locally tampered one buys
anything. `ListIdentities` — service-admin gated upstream — is therefore
uniformly denied on a replica, `ListGroups` reports explicit grants with
`service_admin: false`, and mutations get `ReadOnlyReplica` (registered
callers) or the uniform `Denied` (everyone else, so a stranger cannot even
learn the node's role). See [`../docs/protocol.md`](../docs/protocol.md)
section 7.

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
against a populated database. It also stamps the database's **role** as
authoritative; the v1→v2 migration stamps existing databases the same way,
so the authoritative/replica distinction is well defined for pre-existing
files.

### Replica initialization

A replica has no `init` and no key ceremony. Its only key material is its
own iroh endpoint secret key (auto-generated on first use like any other);
the age identity that opens its DEK wraps is derived from it (section 3),
and it holds neither the operational nor the backup key. The first
`serve --replica-of <id>` stamps the mirror database with its role, the
authoritative EndpointId, and its own EndpointId, and every later start is
refused unless all three match — a mirror whose wraps are addressed to a
different key is useless, and syncing over an authoritative database would
destroy it.

Onboarding a replica is therefore an ordinary identity registration: read
its EndpointId on the replica host, register it and grant `read` on the
authoritative node, start it. One key per replica instance — sharing a key
across replicas confuses audit attribution and is unsupported.

### Rotation

**Group DEK.** An admin issues a `rotate-dek` request for a group. The
server generates a new DEK, wraps it to the operational and backup pubkeys
*and to every current reader*, and writes it as a new version. New writes
use the new DEK; old secret versions remain decryptable via the retained
old DEKs. Revoking a reader's `read` performs the same rotation implicitly
(section 7).

**Operational age keypair.** Generate a new keypair offline. Use the
existing operational private key (or, if unavailable, the backup private
key) to decrypt every wrapped DEK, then re-wrap to the new operational
pubkey. Replace the k8s Secret. The bunker's EndpointId is unaffected, and
so are the backup and reader wraps: only the `operational` rows change, so
replicas notice nothing.

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
swap for the same reason. Key material follows the ACL automatically:
removing the old identity rotates every group it could read, and each new
grant of `read` wraps the group's retained DEK versions to the new
EndpointId's derived recipient. Existing secret versions are never
re-encrypted.

### Revocation

Deleting an identity row (or its ACL rows) takes effect on the next
request. iroh connections are authenticated per-connection, not
per-session-token, so a revoked peer's existing connection can no longer
pass the ACL check on any subsequent stream. Since DEKs are wrapped to
readers, revocation also deletes the identity's wraps and rotates the
group DEK in the same transaction; what that does and does not guarantee
is spelled out in section 7.

## 9. Disaster Recovery

If the operational private key is suspected compromised:

1. Spin down the running service.
2. Generate a new operational age keypair offline.
3. On a clean machine, with the SQLite file copied offline and the backup
   private key available, run the recovery tool:
   - For every `dek_wrap` row whose recipient is `backup`, age-decrypt the
     wrap with the backup identity.
   - Re-wrap the recovered DEK to the new operational pubkey.
   - Update that DEK version's `operational` row in place, and record the
     new operational pubkey — all in one transaction, so a failure part-way
     cannot leave a half-rewrapped database.
4. Replace the k8s Secret with the new operational private key.
5. Bring the service back up.

Reader wraps are **not** touched: they are addressed to endpoint keys the
operational key has nothing to do with, so replicas keep working across a
recovery without re-syncing anything. Backup wraps are likewise untouched —
recovery re-keys the online half only.

Compromise of the *endpoint* secret key does not expose stored secrets (it
grants the ability to impersonate the bunker to clients); respond by
rotating the endpoint key as in section 8. The derivation of section 3
does not change this: the bunker's own endpoint key is not a registered
identity, so no DEK is ever wrapped to it.

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

A **replica** — including an operator pod embedding the `Replica` library
component — needs exactly **one** mounted Secret: its own endpoint secret
key. No operational key, no backup key, no age key of any kind; the age
identity is derived from the endpoint key in process. What such a pod can
mirror is decided cryptographically by the authoritative node's ACL and
its DEK wraps, not by anything configurable in the cluster: granting the
pod's EndpointId `read` on a group is the whole mechanism, and revoking it
(plus the automatic rotation) is the whole undo — subject to the sync lag
of section 7.

## 11. Cryptographic Primitives Summary

| Purpose | Primitive | Library |
|---|---|---|
| Transport auth + encryption | QUIC / TLS 1.3 RPK, ed25519 EndpointIds | `iroh` |
| Symmetric secret encryption (DEK) | ChaCha20-Poly1305 | `chacha20poly1305` |
| Wrapping DEKs to public keys | X25519 + ChaCha20-Poly1305 via age | `age` |
| Deriving an age recipient/identity from an iroh key | ed25519 → X25519 (Edwards→Montgomery; SHA-512 scalar half), Bech32-encoded | `ed25519-dalek`, `bech32` |
| Audit-log hash chain | SHA-256 | `sha2` |

## 12. Non-Goals

The following are explicitly not provided:

- **Defense against a hostile operator.** The server decrypts secrets in
  memory to serve reads, so the operator can read all plaintexts in
  principle.
- **Forward secrecy for stored secrets.** A future leak of the backup
  private key allows decryption of past database snapshots. The same holds
  for a read-granted identity's endpoint key, for the groups it could read.
- **Retroactive revocation.** Revoking `read` rotates the group DEK, so
  nothing written afterwards is readable by the revoked key — but
  ciphertext and wraps it already fetched or mirrored cannot be recalled,
  and existing secret versions are not re-encrypted. Revocation is forward
  protection; rewrite the secrets you must actually consider burned.
- **A staleness bound on replicas.** A replica serves its last mirror for
  as long as it cannot reach the authoritative node — that is the feature —
  so an ACL revocation reaches a replica's clients only when the replica
  syncs it, with no upper bound during a partition or an outage. Nothing
  in the protocol expires a mirror, and clients cannot tell how stale one
  is.
- **Replica chaining.** A replica does not serve the sync ALPN, and a v1
  mirror could not anyway: it holds only the wraps addressed to its own
  key. Every replica syncs from the authoritative node directly.
- **Write proxying and multi-master.** Replicas redirect mutations to the
  authoritative node rather than forwarding them; there is exactly one
  writable copy.
- **Metadata confinement of a read grant.** A read grant used for
  replication discloses the group's full ACL roster (names, endpoint ids,
  permission bits) to the grantee, wider than what the client protocol
  would give the same identity (section 2). There is no "sync without the
  roster" mode: a replica needs the roster to authorize its own clients.
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
