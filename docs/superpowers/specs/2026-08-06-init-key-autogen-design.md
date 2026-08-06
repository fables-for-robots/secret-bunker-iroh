# `init` key auto-generation

Date: 2026-08-06. Status: approved.

## Problem

`init` requires `--backup-pubkey` and `--admin-id`, so a bare
`secret-bunker-iroh init --db bunker.sqlite` fails. Every other command
auto-generates its keys in the XDG data dir; `init` should too.

## Design

Both flags become optional; explicit values keep exact current behavior.

- **`--admin-id` omitted:** default to the XDG `client.key`'s EndpointId
  via the existing `resolve_endpoint_key(None, KeyRole::Client)` path
  (auto-generates when missing). Print a notice naming the id and its
  source, so the same machine's `client`/`tui` works as service admin
  immediately — the single-machine bootstrap.

- **`--backup-pubkey` omitted:** add `KeyRole::Backup` (`backup.age`) and
  load-or-generate it in the XDG data dir like the operational key. Print
  the `age1...` recipient and a loud warning that the secret half lives at
  that path and should be moved offline (`key export backup --out ...`).
  Because `KeyRole` is a clap `ValueEnum`, `key show/generate/export/import`
  pick up the backup role automatically; `key show`'s role list gains
  `Backup`.

No store/schema changes; `store.init()` is untouched.

## Testing

New CLI integration test in `tests/cli.rs`: bare `init --db` succeeds,
prints recipient + admin id, and the generated `client.key` really is the
admin (a client request requiring admin works).

## Docs

README quickstart: bare `init` becomes the happy path; the explicit-flag
form stays documented for production (backup key generated elsewhere,
admin on another machine).
