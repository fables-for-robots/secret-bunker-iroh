# secret-bunker-iroh

A small secrets service ("bunker") that stores secrets encrypted at rest and
serves them over [iroh](https://www.iroh.computer) — peer-to-peer QUIC
connections dialed by public key. There is no TLS certificate, hostname, or
CA to configure: the bunker's identity *is* its ed25519 EndpointId, and so is
every client's.

The security model of the network surface:

> **Anyone may connect to the bunker over iroh. A connected peer can do
> nothing — not read, not write, not enumerate, not distinguish "denied"
> from "does not exist" — unless its iroh key has been granted access to
> some secrets.**

See [`design/crypto-design.md`](design/crypto-design.md) for the full
cryptographic design, threat model, and non-goals. The short version:

- **Transport**: iroh QUIC (TLS 1.3 with raw public keys). Both sides are
  mutually authenticated by their EndpointIds; relays only ever forward
  ciphertext. There is no application-layer signing — the handshake is the
  authentication.
- **Authorization**: per-group ACLs (`read`/`write`/`admin` bits) keyed by
  EndpointId, plus a service-admin flag for creating groups and registering
  identities. Unknown identity, missing permission, and nonexistent target
  all produce the same uniform denial.
- **At rest**: secrets are encrypted with per-group data-encryption keys
  (ChaCha20-Poly1305); each DEK is wrapped to an *operational* age key
  (online, serves reads) and an offline *backup* age key (disaster
  recovery). A stolen database file is opaque.

## Building

With [nix](https://nixos.org) + [direnv](https://direnv.net): `direnv allow`,
then `cargo build`. Without nix: any Rust toolchain ≥ 1.91.

```
cargo test          # unit + end-to-end tests (in-process iroh endpoints)
```

## Quick start

Private keys live under `$XDG_DATA_HOME/secret-bunker-iroh` (falling back
to `~/.local/share/secret-bunker-iroh`) and are auto-generated on first
use, so most commands need no key flags at all.

On the admin's machine, create a client identity and note its EndpointId:

```sh
secret-bunker-iroh key generate client
```

On the server, generate an offline backup key, initialize the database
(one-shot), and serve — the endpoint and operational keys auto-generate:

```sh
secret-bunker-iroh keygen-age --out backup.age   # move this OFFLINE; note the age1... pubkey
secret-bunker-iroh init \
  --db bunker.sqlite \
  --backup-pubkey age1... \
  --admin-id <admin EndpointId>

secret-bunker-iroh serve --db bunker.sqlite      # prints the bunker's EndpointId
```

Use it. With the default n0 relays and discovery, the bunker's EndpointId
is all a client needs; add `--server-addr ip:port` to dial directly. Save
the id under the `default` alias once and `--server` becomes optional
everywhere:

```sh
secret-bunker-iroh server add default <bunker EndpointId>
alias bunker='secret-bunker-iroh client'

bunker create-group prod
echo -n "hunter2" | bunker put --group prod --name db-password
bunker get --group prod --name db-password

# register a read-only client
bunker add-identity --name ci --id <ci EndpointId>
bunker grant --group prod --identity ci --perms r

# maintenance
bunker rotate-dek --group prod
bunker list-identities
```

`server add <name> <id>` also stores named aliases (`server ls`, `server
rm`), and every `--server` flag accepts an alias or a raw EndpointId.

Writes are compare-and-set: `put` takes `--expected-version` (0 = create;
otherwise the current version), and a mismatch fails with the current
version instead of clobbering a concurrent write.

## Terminal UI

`tui` opens an interactive, role-aware view of the bunker:

```sh
secret-bunker-iroh tui   # uses the "default" alias; --server <id-or-alias> to override
```

Everyone gets the two-pane browser — groups on the left (with your
permission flags), secrets on the right — with popups to view (`enter`),
create (`n`), edit (`e`), and delete (`d`) secrets. Group admins manage a
group's ACL from `a` (toggle `r`/`w`/`a` bits per identity, `x` revokes,
`n` grants to a new identity) and rotate its DEK with `R`. Service admins
additionally create groups and manage registered identities (`I`). Press
`?` for the full key reference.

The TUI is only a lens on the protocol: every action is a normal request,
authorized server-side, and a "denied" status means the bunker refused —
the UI holds no privileged state.

## Key management

Three keys are managed in the XDG data directory: `client.key` (the
`client` subcommand's identity), `server.key` (the bunker's identity), and
`operational.age` (wraps the group DEKs). All are created mode 0600 in a
0700 directory.

```sh
secret-bunker-iroh key show                        # paths + public identifiers
secret-bunker-iroh key generate client             # ensure a key exists, print its id
secret-bunker-iroh key export client --out c.key   # or to stdout (it is SECRET material)
secret-bunker-iroh key import client --in c.key    # onto another machine; --force to overwrite
```

Export/import moves an identity between machines without changing its
EndpointId, so existing ACL grants keep working. Auto-generation only ever
happens at the default XDG paths — an explicitly passed `--key`,
`--endpoint-key`, or `--operational-key` path that does not exist is an
error, so a typo cannot silently mint a fresh identity. `keygen-endpoint`
and `keygen-age` remain for creating keys at arbitrary paths (e.g. the
offline backup key).

## Connectivity: NATs and local networks

A client needs only the bunker's EndpointId; how the connection happens
depends on where the two ends are:

- **Across the internet / behind NATs** (default): the bunker registers
  with n0 relays and publishes its relay URL to n0 discovery; `serve`
  prints `online: reachable via relay` once that's confirmed. Clients
  resolve the EndpointId, connect via the relay, and QUIC hole punching
  upgrades to a direct path when the NATs allow it. Neither side needs a
  public IP or port forwarding.
- **Same local network, no internet**: both sides speak mDNS
  (advertised by `serve`, resolved by `client`), so a bare EndpointId works
  offline too — combine with `--no-relay` for fully air-gapped LANs.
  Disable the announcement with `--no-mdns` if you don't want the bunker
  visible to the local segment.
- **Static addressing**: pass `--server-addr ip:port` to the client to skip
  discovery entirely.

Every path ends in the same mutually authenticated handshake against the
EndpointId being dialed, so discovery can only affect reachability, never
identity.

## Disaster recovery

If the operational key is compromised or lost, take the service down and
re-wrap every group DEK from the offline backup key to a fresh operational
key — the bunker's EndpointId and the database contents are unaffected:

```sh
secret-bunker-iroh keygen-age --out operational-new.age
secret-bunker-iroh recover \
  --db bunker.sqlite \
  --backup-key backup.age \
  --new-operational-pubkey age1...   # pubkey printed by keygen-age
```

Restart `serve` with the new operational key; the old one is rejected.

## Embedding

The crate is also a library: `secret_bunker_iroh::client::Client` speaks the
protocol from Rust (`connect`, `request`, `close`), and
`secret_bunker_iroh::server::Bunker` is an iroh `ProtocolHandler` you can
mount on your own `Router` under the `secret-bunker/1` ALPN.

## License

[AGPL-3.0-or-later](LICENSE).
