# Kubernetes Operator for secret-bunker-iroh — Design

Date: 2026-08-11
Status: approved design, pre-implementation

## Overview

A Kubernetes operator, `secret-bunker-operator`, that syncs secrets from a
secret-bunker-iroh bunker into native Kubernetes `Secret` objects. It embeds
the crate's `Replica` engine (read replication), so it holds a live local
mirror of every group its identity has been granted `read` on, receives
push change events, and re-renders k8s Secrets sub-second after a bunker
write. A namespaced `BunkerSecret` custom resource declares the mapping —
per-key references, whole-group fan-out, JSON explode, and key renames —
in the style of external-secrets' `ExternalSecret`.

### Goals

- Declarative sync: one `BunkerSecret` CR renders exactly one k8s `Secret`.
- Push-driven updates: bunker write → k8s Secret update without polling.
- JSON mapping: extract a JSON property into a key, or explode a
  JSON-object-valued bunker secret into many keys.
- Key remapping: bunker secret names → arbitrary k8s Secret keys.
- Safe failure modes: access revocation or replica staleness must never
  destroy workload secrets.
- Prometheus metrics for replica health and reconcile behavior.

### Non-goals (v1)

- Write-back / push-secrets into the bunker.
- Templating engine for rendered Secrets.
- Multi-bunker support (no `SecretStore`-style indirection; one bunker per
  operator installation, static config).
- Helm chart (plain manifests only).
- A "refresh now" annotation — the `Replica` engine has no force-resync
  API (`src/replica.rs:147-258`); file upstream instead of working around.
- Replica chaining, serving the mirror to other clients
  (`protocol_handler()` stays unused).

## Context: upstream facts this design relies on

All references are to the secret-bunker-iroh source at the time of writing
(branch `sops-replication`).

- The crate is a usable library; `src/lib.rs` exports all modules, no
  feature flags. AGPL-3.0-or-later (`Cargo.toml`), so the operator —
  linking it — is AGPL too. It lives in this repo, so lockstep versioning
  is structural (no in-band sync protocol version negotiation; breaking
  changes bump the ALPN, `docs/sync-protocol.md`).
- `Replica::builder()` (`src/replica.rs:457`) takes `store_path`
  (SQLite mirror), `secret_key` (iroh ed25519 identity),
  `authoritative` (EndpointId), optional `authoritative_addrs`
  (direct dial, no relays/discovery). `spawn()` starts a background tokio
  task; `shutdown().await` is bounded (<5 s even against a stalled peer).
- Reads are local and synchronous: `get(group, name) →
  Zeroizing<Vec<u8>>` returns plaintext (DEK unwrap uses an age identity
  derived in-process from the same ed25519 key); `list(group)` returns
  `(name, version)` pairs; `status()` returns
  `{connected, last_synced, groups, authoritative}`.
- `subscribe()` returns a `tokio::sync::broadcast::Receiver<ReplicaEvent>`
  (capacity 1024, hard-coded). Events: `SecretChanged{group,name,version}`,
  `SecretDeleted`, `GroupAdded`, `GroupRemoved`, `Connected`,
  `Disconnected`. Data events fire post-commit: after an event, `get()`
  is guaranteed to see the new state. Subscribing immediately after
  `spawn()` is race-free; there is no replay. On `RecvError::Lagged`,
  level reconciliation is mandatory.
- `Connected` fires *before* the first manifest applies; the only
  initial-sync-complete signal is `status().last_synced` turning `Some`.
- Sync scope is explicit `read` grants only; `service_admin` grants no
  sync access and must not be given to the operator.
- Two access-loss modes (`docs/sync-protocol.md`): identity removed
  upstream → every reconnect is denied, the mirror silently freezes;
  last read grant revoked → empty manifest, the mirror empties itself and
  emits `GroupRemoved` per group. These need different operator responses.
- Version ABA: delete+recreate restarts versions at 1; only the nonce
  reliably differs. Never key change detection on bunker versions.
- Key handling (`src/keys.rs`): explicitly supplied key paths must
  pre-exist (never auto-generated); *default* XDG paths auto-generate — a
  container footgun this design avoids by always passing an explicit path.
- The mirror DB is role-stamped to (role, authoritative id, replica id);
  a key rotation requires a fresh mirror. Warm start over an existing
  mirror is untested upstream. The mirror leaks metadata (group/secret
  names, versions, ACL rosters) in plaintext; `Store::open` forces 0600.
- Transient decrypt race: during grant/DEK-rotation races `get()` can fail
  with "no DEK wrap … not yet synced"; the engine re-fetches — retryable.

## Architecture

### Crate layout

`secret-bunker-iroh` becomes a cargo workspace. The existing crate stays
the root package; a new member crate `operator/` (package
`secret-bunker-operator`, binary, AGPL-3.0-or-later) depends on it by
path. The flake builds the operator binary and a container image
(nix dockerTools). CI runs the workspace.

Key operator dependencies: `kube` (derive + runtime), `k8s-openapi`,
`secret-bunker-iroh` (path), `tokio`, `serde`/`serde_json`, `prometheus`,
`axum` (or `hyper`) for the health/metrics endpoint, `tracing`, `clap`.

### Process shape

One binary, one pod. Four cooperating pieces on one tokio runtime:

1. **Replica manager.** Spawns the embedded `Replica` at startup:
   - `store_path` on an `emptyDir` volume — full resync each start; warm
     start is untested upstream, and emptyDir sidesteps key↔mirror
     pairing issues entirely.
   - `secret_key` loaded from an explicit file path mounted from a k8s
     Secret (pre-provisioned identity; explicit paths never
     auto-generate).
   - `authoritative` EndpointId; `authoritative_addrs` when direct
     addresses are configured, otherwise default n0 relay/discovery for a
     remote bunker.
   - `shutdown().await` wired into SIGTERM handling.
2. **Controller.** A kube-rs `Controller` on `BunkerSecret`, additionally
   watching Secrets it owns (via ownerReference back-mapping), so manual
   edits to a rendered Secret trigger reconciliation and get reverted.
3. **Event bridge.** Subscribes to `ReplicaEvent`s immediately after
   `spawn()` (race-free). Maps events to reconcile triggers through the
   controller's reflector store:
   - `SecretChanged`/`SecretDeleted`/`GroupAdded`/`GroupRemoved{group}` →
     requeue every `BunkerSecret` whose spec references that group.
   - `Connected`/`Disconnected` → update staleness state + metrics.
   - `RecvError::Lagged` → requeue **all** `BunkerSecret`s.
   Events are wake-ups only; reconciliation always reads full state from
   the replica. A missed event costs latency, never correctness.
4. **Health/metrics server.** One HTTP listener (default `:8080`):
   `/healthz` (liveness: process up), `/readyz` (readiness:
   `status().last_synced.is_some()`), `/metrics` (Prometheus).

### Operator configuration (flags/env on the Deployment)

| Flag | Required | Default | Meaning |
|---|---|---|---|
| `--bunker-id` | yes | — | Authoritative bunker EndpointId (64-hex) |
| `--bunker-addr` | no | (n0 discovery) | Direct `host:port`, repeatable; disables relays/discovery |
| `--key-file` | yes | — | Path to the operator's iroh ed25519 key (mounted Secret) |
| `--mirror-path` | yes | — | Replica SQLite path (emptyDir volume) |
| `--resync-interval` | no | `1h` | Level-reconcile backstop for every CR |
| `--staleness-threshold` | no | `10m` | Disconnected-longer-than-this degrades CR readiness |
| `--listen` | no | `:8080` | Health + metrics listener |

There is deliberately **no per-CR refresh interval**: updates are
push-driven; the global `--resync-interval` is a defense-in-depth backstop
(level-triggered doctrine), not a sync mechanism.

### High availability

Single-replica Deployment, `strategy: Recreate`, no leader election.
Upstream forbids sharing one identity key across replica instances, and
the read path needs no HA. Brief unavailability during rescheduling is
acceptable: consuming workloads keep their Secrets; only propagation of
new bunker writes pauses. Documented limitation.

### Identity provisioning (runbook, documented with the manifests)

1. Generate an iroh key for the operator (`secret-bunker-iroh key
   generate client` on an admin machine, or any tool producing the
   lowercase-hex format).
2. `client add-identity --name k8s-operator --id <EndpointId>` and
   `client grant --group <g> --identity k8s-operator --perms r` for each
   group to sync. No `service_admin`.
3. Store the key in a k8s Secret in the operator's namespace; mount at
   `--key-file` path with mode 0400.
4. Rotation: create + register + grant a new identity, update the key
   Secret, restart the operator (emptyDir gives a fresh mirror
   automatically), then revoke the old identity. Document that revoking
   the old identity's grants auto-rotates group DEKs.

The key Secret is as sensitive as every secret it can decrypt; RBAC on
that namespace should reflect that.

## CRD: `BunkerSecret`

Group `bunker.fables-for-robots.ch`, version `v1alpha1`, namespaced,
short name `bs`. Rust types with `kube::CustomResource` derive; generated
CRD YAML checked into `operator/deploy/`.

```yaml
apiVersion: bunker.fables-for-robots.ch/v1alpha1
kind: BunkerSecret
metadata:
  name: app-secrets
  namespace: prod
spec:
  deletionPolicy: Retain     # Retain (default) | Delete — Secret fate when the CR is deleted
  target:
    name: app-secrets        # optional, defaults to CR name
    type: Opaque             # optional, defaults to Opaque
  data:                      # explicit per-key mappings — highest precedence
    - secretKey: DB_PASSWORD
      remoteRef:
        group: prod
        name: db-password
    - secretKey: SMTP_PASS
      remoteRef:
        group: prod
        name: mailer-config
        property: /smtp/password   # JSON Pointer (RFC 6901)
  dataFrom:                  # bulk mappings, applied in list order, before data
    - group:
        name: prod           # whole-group fan-out: each secret name → one key
        rewrite:             # optional exact-name renames
          - source: db-password
            target: DB_PASSWORD
    - extract:
        group: prod
        name: config-json    # JSON-object value → one key per top-level property
status:
  conditions:                # single condition type "Ready" with reasons
    - type: Ready
      status: "True"
      reason: Synced
      message: ""
  lastSyncTime: "2026-08-11T12:00:00Z"
  observedGeneration: 3
  syncedSecretKeys: [DB_PASSWORD, SMTP_PASS, ...]
```

### Value semantics

- Bunker values are opaque bytes; JSON is a convention, not a wire type.
- No `property`: bytes copied verbatim (binary-safe).
- `property`: value must parse as JSON; the JSON Pointer is resolved. A
  JSON string result becomes its raw UTF-8 bytes; any other JSON type is
  re-serialized as compact JSON.
- `dataFrom.extract`: value must parse as a JSON object; each top-level
  property becomes a key, same string-vs-other rule per value.
- `dataFrom.group`: each bunker secret in the group becomes a key,
  bytes verbatim, name mapped through `rewrite` (exact match) if present.

### Precedence

`dataFrom` entries apply in list order (later entries win on key
collision), then `data` entries apply on top (always win). Identical to
external-secrets, stated in the CRD documentation.

### Name hygiene — no silent sanitization

k8s Secret keys must match `[A-Za-z0-9._-]+`. Bunker names are
unconstrained strings. If a fan-out/extract produces an invalid key, the
reconcile fails **atomically** — nothing partial is written, the existing
Secret is untouched — with `Ready=False/InvalidKey` naming the offenders.
The fix is a `rewrite` rule or an explicit `data` entry. The same
atomic-fail rule covers JSON parse errors, unresolvable pointers,
non-object `extract` targets, and missing referenced groups/secrets.

### Deletion and access-loss semantics

| Situation | Behavior |
|---|---|
| CR deleted, `deletionPolicy: Delete` | Owned Secret garbage-collected via ownerReference |
| CR deleted, `deletionPolicy: Retain` | Finalizer strips the ownerReference first; Secret orphaned intact |
| `spec.target.name` changed | New Secret rendered under the new name; the old Secret follows `deletionPolicy` (Delete → operator deletes it, Retain → ownerReference stripped, orphaned) |
| Bunker secret deleted, referenced by `data` | Hard reference: render fails, Secret frozen, `Ready=False/MissingSecret` |
| Bunker secret deleted, was part of `dataFrom.group` fan-out | Normal update: Secret re-rendered without that key |
| Group vanishes after having synced (`GroupRemoved` — revocation) | **Never** re-render from the emptied mirror: Secret frozen, `Ready=False/AccessRevoked`, warning Event |
| Group absent and never synced | `Ready=False/MissingGroup` (initial state, nothing rendered yet) |
| Identity removed upstream (silent mirror freeze) | Surfaces via staleness: `Ready=False/StaleReplica` after `--staleness-threshold` |
| Target Secret exists but is not owned by the CR | Never adopt or overwrite: `Ready=False/Conflict` |

The revocation-safety rule exists because a revoked grant is
indistinguishable from an ACL mistake; cascading would wipe workload
secrets cluster-wide. Cleanup after intentional revocation is a human
action (delete the CRs).

Finalizer lifecycle: the operator adds its finalizer to every
`BunkerSecret` on first reconcile. On CR deletion it strips the
ownerReference when `deletionPolicy: Retain`, does nothing extra for
`Delete` (GC cascades), then removes the finalizer.

### Change detection

The rendered Secret carries an annotation
`bunker.fables-for-robots.ch/content-hash: sha256:<hex>` over the rendered
data map. Apply is skipped when the hash matches. Comparing content —
never bunker version numbers — makes the delete+recreate version-ABA
hazard irrelevant.

## Reconcile flow

Triggers: CR add/update, owned-Secret change, replica event via the
bridge, global `--resync-interval` backstop, staleness flips.

1. **Gate.** If `status().last_synced` is `None` (initial sync not
   complete), set `Ready=False/AwaitingSync` and requeue — never render
   from an unsynced mirror (a boot-time empty mirror must not look like
   mass deletion).
2. **Read.** Resolve every reference with local `replica.get()` /
   `list()` / `groups()` calls (synchronous, no network).
3. **Render.** Build the full desired data map (fan-out → extract →
   rewrites → `data` overrides), validate key names. Any error → atomic
   fail per the table above: specific condition, warning Event, existing
   Secret untouched, backoff requeue.
4. **Apply.** Server-side apply (field manager
   `secret-bunker-operator`), ownerReference to the CR, content-hash
   annotation; skip when hash unchanged.
5. **Status.** `Ready=True/Synced`, `lastSyncTime`, `observedGeneration`,
   `syncedSecretKeys`.

### Error taxonomy

- **Config errors** (invalid key names, bad pointers, missing hard refs,
  conflicts): no hot retry — wait for CR edits, relevant replica events,
  or the backstop. Condition + Event carry the details.
- **Transient errors** (kube API failures, "no DEK wrap yet" decrypt
  races): exponential backoff retry; the next sync push usually heals the
  decrypt case.
- **Access loss / staleness**: terminal-until-events; conditions as per
  the table. Secrets always frozen, never destroyed.

## Observability

### Conditions & Events

Single `Ready` condition per CR with reasons `Synced`, `AwaitingSync`,
`InvalidKey`, `JsonError`, `MissingSecret`, `MissingGroup`,
`AccessRevoked`, `StaleReplica`, `Conflict`. Warning Events on every
transition to a failure reason.

### Prometheus metrics (`/metrics`)

Replica health:
- `bunker_replica_connected` (gauge, 0/1)
- `bunker_replica_last_sync_timestamp_seconds` (gauge)
- `bunker_replica_groups` (gauge)

Event flow:
- `bunker_replica_events_total{type=secret_changed|secret_deleted|group_added|group_removed|connected|disconnected|lagged}` (counter)

Reconcile behavior:
- `bunker_secret_reconciles_total{result=success|error}` (counter)
- `bunker_secret_reconcile_duration_seconds` (histogram)
- `bunker_secret_applies_total{outcome=applied|skipped}` (counter)
- `bunker_secret_ready{namespace,name}` (gauge, 0/1; cardinality = CR count)

No ServiceMonitor in the manifests; a commented example in the docs.

## Security considerations

- The operator's key decrypts every granted group; the key Secret and the
  operator namespace deserve tight RBAC. No `service_admin`.
- The emptyDir mirror holds plaintext *metadata* (group/secret names,
  ACL rosters) and ciphertext data; upstream forces 0600 on the DB files.
  Pod runs as non-root with a dedicated fsGroup; no other container
  mounts the volume.
- Rendered k8s Secrets are only as protected as cluster RBAC on Secrets —
  unchanged from any external-secrets-style deployment.
- Revocation is forward-only upstream: values already synced into k8s are
  not clawed back by a bunker-side revoke. Documented; cleanup is
  deleting the CRs/Secrets.
- RBAC (operator ServiceAccount): `bunkersecrets` get/list/watch +
  status patch + finalizer update; `secrets` get/list/watch/create/patch
  + delete (needed for `spec.target.name` renames under
  `deletionPolicy: Delete`); `events` create.

## Testing

- **Unit** (operator crate): the render pipeline is pure
  (`BTreeMap<(group, name), bytes>` in → Secret data map or typed error
  out). Table tests: JSON pointer extraction, explode, precedence,
  rewrites, invalid keys, collisions, binary passthrough.
- **Integration**: real in-process bunker + embedded Replica (reusing the
  `tests/e2e.rs` harness pattern — in-process iroh endpoints, no relays),
  operator sync engine on top, kube API mocked with kube-rs tower mock
  services. Scenarios: initial sync gate, push-driven update, fan-out
  shrink, hard-ref delete freeze, revocation freeze (`GroupRemoved`),
  Lagged → reconcile-all, deletion policies (finalizer/ownerRef),
  conflict on unowned Secret, staleness flip.
- **Smoke e2e** (optional CI job, not in the default `cargo test`):
  `kind` cluster, operator image, real bunker; one happy-path
  create→update→observe flow.

Convergence in tests is always awaited with bounded deadlines (matching
the upstream test style), never assumed.

## Packaging

`operator/deploy/`: generated CRD YAML, RBAC, Deployment (key Secret
mount at `--key-file`, emptyDir at `--mirror-path`, liveness `/healthz`,
readiness `/readyz`), Namespace. Container image via nix dockerTools in
the existing flake. No Helm in v1.

## Upstream asks (file as issues, not workarounds)

- Force-resync / "reconcile now" API on `Replica`.
- An explicit initial-sync-complete / `ManifestApplied` event.
- Builder knobs for reconnect backoff, event-channel capacity, server
  debounce (all hard-coded today).
- Public accessors for secret metadata (`created_at`, `dek_version`) if
  ever needed for richer status.
- A forward `schema_version` guard in `Store::open`.

## Resolved design decisions (for the record)

1. Integration: embed the Rust `Replica` engine (vs sidecar CLI, vs Go
   client polling). Operator is Rust + kube-rs, AGPL.
2. Mapping model: one CR → one Secret with `data` + `dataFrom`
   (external-secrets style).
3. Topology: single bunker per installation, static config; no store CRD.
4. Deletion: per-CR `deletionPolicy` (default Retain) + revocation
   safety (access loss never cascades).
5. Repo: workspace member in the bunker repo (lockstep versioning).
6. Backstop: global `--resync-interval`, no per-CR refresh field.
7. Prometheus metrics are in scope for v1.
