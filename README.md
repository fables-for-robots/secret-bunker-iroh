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

Generate keys — the server's endpoint key, the operational age key, an
offline backup age key, and an admin client key:

```sh
secret-bunker-iroh keygen-endpoint --out server.key     # prints the bunker's EndpointId
secret-bunker-iroh keygen-endpoint --out admin.key      # prints the admin's EndpointId
secret-bunker-iroh keygen-age --out operational.age     # prints age1... pubkey
secret-bunker-iroh keygen-age --out backup.age          # keep this file OFFLINE
```

Initialize the database (one-shot) and start the bunker:

```sh
secret-bunker-iroh init \
  --db bunker.sqlite \
  --operational-key operational.age \
  --backup-pubkey age1... \
  --admin-id <admin EndpointId>

secret-bunker-iroh serve \
  --db bunker.sqlite \
  --endpoint-key server.key \
  --operational-key operational.age
```

Use it. With the default n0 relays and discovery, the bunker's EndpointId is
all a client needs; add `--server-addr ip:port` to dial directly:

```sh
alias bunker='secret-bunker-iroh client --key admin.key --server <bunker EndpointId>'

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

Writes are compare-and-set: `put` takes `--expected-version` (0 = create;
otherwise the current version), and a mismatch fails with the current
version instead of clobbering a concurrent write.

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
