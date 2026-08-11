# secret-bunker-operator

A Kubernetes operator that syncs secrets from a
[secret-bunker-iroh](../README.md) bunker into native Kubernetes `Secret`
objects. It embeds the crate's [`Replica`](../README.md#embedding-a-replica)
engine directly (no sidecar, no polling loop of its own): it holds a live
local mirror of every group its identity has been granted `read` on,
receives push change events over the same iroh connection, and re-renders
the Kubernetes Secrets it owns sub-second after a bunker write. A
namespaced `BunkerSecret` custom resource declares the mapping from bunker
groups/secrets to Secret keys, in the style of
[external-secrets](https://external-secrets.io)' `ExternalSecret`. The
full design — including the reasoning behind every safety rule below — is
in [`docs/superpowers/specs/2026-08-11-k8s-operator-design.md`](../docs/superpowers/specs/2026-08-11-k8s-operator-design.md).

Scope for v1: one bunker per operator installation (no multi-bunker
`SecretStore`-style indirection), read-only (no write-back into the
bunker), no templating, installable via the Helm chart in
[`../charts/secret-bunker-operator`](../charts/secret-bunker-operator)
(published to `oci://ghcr.io/fables-for-robots/charts`) or the plain
manifests in [`deploy/`](deploy/).

## The `BunkerSecret` CRD

Group `bunker.fables-for-robots.ch`, version `v1alpha1`, namespaced, short
name `bs`. The generated CRD schema is [`deploy/crd.yaml`](deploy/crd.yaml)
(regenerate with `cargo run -p secret-bunker-operator --bin crdgen`).

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

One `BunkerSecret` renders exactly one Kubernetes `Secret`. There is no
per-CR refresh interval field: sync is push-driven off the replica's event
stream, and the operator-wide `--resync-interval` flag (see
[Configuration](#configuration)) is a defense-in-depth backstop, not the
sync mechanism.

### Value semantics

- Bunker values are opaque bytes; JSON is a convention, not a wire type.
- No `property`: bytes copied verbatim (binary-safe).
- `property`: the value must parse as JSON; the JSON Pointer is resolved
  against it. A JSON string result becomes its raw UTF-8 bytes; any other
  JSON type is re-serialized as compact JSON.
- `dataFrom.extract`: the value must parse as a JSON object; each
  top-level property becomes a key, same string-vs-other rule per value.
- `dataFrom.group`: each bunker secret in the group becomes a key, bytes
  verbatim, with the name mapped through `rewrite` (exact match) when
  present.

### Precedence

`dataFrom` entries apply in list order (a later entry wins on key
collision), then `data` entries apply on top and always win. This mirrors
external-secrets' precedence rules.

### Name hygiene — no silent sanitization

Kubernetes Secret keys must match `[A-Za-z0-9._-]+`. Bunker names are
unconstrained strings. If a fan-out or `extract` produces an invalid key,
the reconcile fails atomically — nothing partial is written, the existing
Secret is left exactly as it was — with `Ready=False/InvalidKey` naming the
offending keys. Fix it with a `rewrite` rule or an explicit `data` entry.
The same atomic-fail rule covers JSON parse errors, unresolvable JSON
Pointers, non-object `extract` targets, and missing referenced
groups/secrets.

### Deletion and access-loss semantics

| Situation | Behavior |
|---|---|
| CR deleted, `deletionPolicy: Delete` | Owned Secret garbage-collected via ownerReference |
| CR deleted, `deletionPolicy: Retain` | Finalizer strips the ownerReference first; Secret orphaned intact |
| `spec.target.name` changed | New Secret rendered under the new name; the old Secret follows `deletionPolicy` (Delete → operator deletes it, Retain → ownerReference stripped, orphaned) |
| Bunker secret deleted, referenced by `data` | Hard reference: render fails, Secret frozen, `Ready=False/MissingSecret` |
| Bunker secret deleted, was part of `dataFrom.group` fan-out | Normal update: Secret re-rendered without that key |
| Group vanishes after having synced (revocation) | **Never** re-render from the emptied mirror: Secret frozen, `Ready=False/AccessRevoked`, Warning Event |
| Group absent and never synced | `Ready=False/MissingGroup` (initial state, nothing rendered yet) |
| Identity removed upstream (silent mirror freeze) | Surfaces via staleness: `Ready=False/StaleReplica` once disconnected longer than `--staleness-threshold` |
| Target Secret exists but is not owned by the CR | Never adopt or overwrite: `Ready=False/Conflict` |

The revocation rule exists because a revoked grant is indistinguishable
from an ACL mistake from the operator's point of view; cascading the
deletion would wipe workload secrets cluster-wide the moment someone
fat-fingers an ACL change. **Access loss never deletes a rendered
Secret** — it freezes it, with the last successfully synced content
still in place, and reports the failure through the `Ready` condition and
a Warning Event. Cleaning up after an *intentional* revocation is a
deliberate human action: delete the `BunkerSecret` (and, per its
`deletionPolicy`, its Secret).

The same freeze rule applies to staleness: if the sync session to the
bunker drops and stays down past `--staleness-threshold`, the CR's
readiness degrades to `StaleReplica`, but the Secret keeps serving
whatever it last successfully rendered. Nothing is ever torn down because
the operator can no longer confirm it's still correct — only because a CR
or its target Secret is explicitly deleted.

### Security notes

The `bunker.fables-for-robots.ch/content-hash` annotation is an unsalted
SHA-256 over the rendered Secret data; low-entropy values (short passwords,
PINs, etc.) are offline-guessable by anyone who can read the Secret's
metadata, without needing `get` on its data.

## Installing with Helm

```sh
helm install bunker oci://ghcr.io/fables-for-robots/charts/secret-bunker-operator \
  --namespace secret-bunker-system --create-namespace \
  --set bunker.id=<the bunker's 64-char hex EndpointId>
```

By default the operator manages its own identity: on first boot it generates
an iroh key and stores it in the `secret-bunker-operator-identity` Secret in
the release namespace — restarts and redeployments reuse it, never mint a new
one (deleting that Secret is the explicit "start over with a fresh identity"
action). Grant the new identity read access on the bunker:

```sh
kubectl -n secret-bunker-system get secret secret-bunker-operator-identity \
  -o jsonpath='{.metadata.annotations.bunker\.fables-for-robots\.ch/endpoint-id}'
bunker add-identity --name k8s-operator --id <EndpointId printed above>
bunker grant --group prod --identity k8s-operator --perms r
```

Until granted, the pod runs but `/readyz` stays 503 and `BunkerSecret`s
report `AwaitingSync`. To bring your own key instead (the runbook below),
set `identity.existingSecret` — the chart then mounts that Secret and passes
`--key-file`; nothing is ever generated.

Helm never touches `crds/` after install: on chart upgrades apply the CRD
manually first (`kubectl apply -f operator/deploy/crd.yaml`).

Container images are published to
`ghcr.io/fables-for-robots/secret-bunker-operator` (linux/amd64 + arm64):
`vX.Y.Z` releases as `X.Y.Z` + `latest`, every main push as `edge` +
`sha-<commit>`.

## Bring-your-own-key provisioning (runbook)

Only needed with `identity.existingSecret` (or the plain manifests); the
Helm default is managed identity, above.

The operator needs its own iroh identity, registered with the bunker and
granted `read` on every group it should sync — never `service_admin`.

1. Generate a key for the operator at an arbitrary path (never at the XDG
   default — `--key-file`/`BUNKER_KEY_FILE` always takes an explicit path,
   which never auto-generates, so a typo can't silently mint a throwaway
   identity):

   ```sh
   secret-bunker-iroh keygen-endpoint --out operator.key
   # prints the operator's EndpointId, e.g. 1a984b...27b6
   ```

2. On an admin machine with access to the bunker, register that id and
   grant it `read` on each group the operator should sync:

   ```sh
   bunker add-identity --name k8s-operator --id <operator EndpointId>
   bunker grant --group prod --identity k8s-operator --perms r
   # repeat --group/grant for every group this operator installation syncs
   ```

   (`bunker` here is the `secret-bunker-iroh client` alias set up in the
   [root README's quick start](../README.md#quick-start).)

3. Store `operator.key` in a Kubernetes Secret in the operator's namespace
   and mount it at the deployment's `--key-file` path, mode 0400:

   ```sh
   kubectl create namespace secret-bunker-system
   kubectl -n secret-bunker-system create secret generic \
     secret-bunker-operator-identity --from-file=identity.key=operator.key
   ```

   Treat this Secret as being as sensitive as every value it can decrypt —
   RBAC on `secret-bunker-system` should reflect that. Delete the local
   `operator.key` file once it's in the cluster.

4. Set `BUNKER_ID` on the Deployment to the bunker's EndpointId (and
   `BUNKER_ADDR` if it needs a direct address — see
   [Configuration](#configuration)), then apply the manifests, namespace
   first (see [Deploying](#deploying) for why):

   ```sh
   kubectl apply -f operator/deploy/namespace.yaml
   kubectl apply -f operator/deploy/
   ```

## Rotation runbook

Identities aren't updated in place; rotation means provisioning a new one
and retiring the old one.

1. Generate a new key, register it, and grant it the same groups as the
   identity being retired (steps 1–2 above, with a new `--name`).
2. Update the `secret-bunker-operator-identity` Secret with the new key
   file's contents (`kubectl -n secret-bunker-system create secret generic
   secret-bunker-operator-identity --from-file=identity.key=new-operator.key
   --dry-run=client -o yaml | kubectl apply -f -`).
3. Restart the operator (`kubectl -n secret-bunker-system rollout restart
   deployment/secret-bunker-operator`). The mirror lives on an `emptyDir`,
   so the restart gets a fresh mirror automatically under the new
   identity — no key/mirror pairing to worry about.
4. Once the new pod reports `Ready` (check `/readyz`, or `kubectl get
   bunkersecrets -A` for `Ready=True/Synced` conditions across the
   cluster), revoke the old identity:

   ```sh
   bunker remove-identity <old identity name>
   ```

   Removing an identity rotates the DEK of every group it could read, in
   the same transaction — so this step doesn't just stop the old key from
   working, it makes the plaintext it once held cryptographically
   unrecoverable from a stolen database snapshot going forward. (It does
   *not* claw back copies already synced into Kubernetes Secrets before
   rotation; that's the same forward-only guarantee every bunker consumer
   gets.)

## Configuration

Flags (all settable as environment variables too — the env var name is
the flag name upper-cased with `-` → `_`, with `--key-file`,
`--identity-secret` and `--mirror-path` additionally prefixed `BUNKER_`):

| Flag | Env var | Required | Default | Meaning |
|---|---|---|---|---|
| `--bunker-id` | `BUNKER_ID` | yes | — | EndpointId (64-char hex) of the authoritative bunker |
| `--bunker-addr` | `BUNKER_ADDR` | no | (n0 relay/discovery) | Direct `host:port` of the bunker; disables relays/discovery. Repeatable on the CLI for more than one address — the env var only carries a single value, so use repeated `--bunker-addr` flags (e.g. in `args:`) if you need more than one |
| `--key-file` | `BUNKER_KEY_FILE` | one of the two | — | Path to the operator's iroh ed25519 key (mounted from the identity Secret; must already exist, never auto-generated) |
| `--identity-secret` | `BUNKER_IDENTITY_SECRET` | one of the two | — | Name of a Secret in the operator's own namespace holding its identity key; generated and stored there on first boot when missing. Mutually exclusive with `--key-file` |
| `--mirror-path` | `BUNKER_MIRROR_PATH` | yes | — | Replica SQLite mirror path (on the `emptyDir` volume) |
| `--resync-interval` | `RESYNC_INTERVAL` | no | `1h` | Level-reconcile backstop applied to every `BunkerSecret`; sync itself is push-driven, this only guards against a missed event |
| `--staleness-threshold` | `STALENESS_THRESHOLD` | no | `10m` | Once the sync session has been down this long, CRs degrade to `Ready=False/StaleReplica` |
| `--listen` | `LISTEN` | no | `0.0.0.0:8080` | Health + metrics HTTP listener address |

The bundled [`deploy/deployment.yaml`](deploy/deployment.yaml) sets
`BUNKER_ID`/`BUNKER_KEY_FILE`/`BUNKER_MIRROR_PATH` via env and leaves
`BUNKER_ADDR` commented out (uncomment for a direct-dial, in-cluster, or
fixed-address bunker; otherwise the operator uses ordinary n0
relay/discovery to reach it).

## Metrics

Exposed on `/metrics` in Prometheus text format.

Replica health:

| Metric | Type | Meaning |
|---|---|---|
| `bunker_replica_connected` | gauge (0/1) | 1 when the sync session to the authoritative bunker is up |
| `bunker_replica_last_sync_timestamp_seconds` | gauge | Unix time of the last completed sync; 0 before the first |
| `bunker_replica_groups` | gauge | Groups currently present in the local mirror |

Event flow:

| Metric | Type | Meaning |
|---|---|---|
| `bunker_replica_events_total{type}` | counter | Replica events seen, by `type` — one of `secret_changed`, `secret_deleted`, `group_added`, `group_removed`, `connected`, `disconnected`, `lagged` |

Reconcile behavior:

| Metric | Type | Meaning |
|---|---|---|
| `bunker_secret_reconciles_total{result}` | counter | Reconcile outcomes, `result` is `success` or `error` |
| `bunker_secret_reconcile_duration_seconds` | histogram | Reconcile duration |
| `bunker_secret_applies_total{outcome}` | counter | Secret writes vs. hash-skips, `outcome` is `applied` or `skipped` |
| `bunker_secret_ready{namespace,name}` | gauge (0/1) | 1 when that `BunkerSecret`'s `Ready` condition is `True`; cardinality equals the number of CRs in the cluster |

### Health endpoints

- `/healthz` — liveness: the process is up (unconditional 200).
- `/readyz` — readiness: 200 once the replica's initial sync has
  completed (`status().last_synced.is_some()`), 503 otherwise. The
  operator deliberately never renders a `BunkerSecret` before this point —
  a boot-time empty mirror must not be mistaken for mass deletion — so
  `/readyz` doubles as "the operator is safe to start reconciling
  against."

## Conditions

Every `BunkerSecret` carries a single condition of `type: Ready`. The
`reason` field is one of:

| Reason | Meaning |
|---|---|
| `Synced` | Rendered and applied successfully; `status` is current |
| `AwaitingSync` | The embedded replica hasn't completed its initial sync yet; nothing has been rendered |
| `InvalidKey` | A rendered key isn't a valid k8s Secret key name; fix with `rewrite` or an explicit `data` entry |
| `JsonError` | A `property`/`extract` reference failed to parse as JSON, a JSON Pointer didn't resolve, or an `extract` target wasn't a JSON object |
| `MissingSecret` | A `data` hard reference points at a bunker secret that doesn't exist |
| `MissingGroup` | A referenced group has never appeared in the mirror (no read grant, or the group doesn't exist yet) |
| `AccessRevoked` | A group that had synced successfully disappeared from the mirror (revocation); the Secret is frozen at its last good content |
| `StaleReplica` | The sync session has been down longer than `--staleness-threshold`; the Secret is still serving its last synced content |
| `Conflict` | The target Secret exists and isn't owned by this CR; the operator refuses to adopt or overwrite it |

The operator emits a Warning Kubernetes Event on every **transition** into
a failure reason (repeated reconciles that land on the same reason again
stay quiet — check `kubectl describe bunkersecret <name>` or `kubectl get
events` for the history, not a flood on every resync).

## Monitoring with Prometheus Operator

No `ServiceMonitor` ships in `deploy/` (it would require a `Service` and a
hard dependency on the Prometheus Operator CRDs neither of which v1
assumes). The Helm chart renders both when `metrics.service.enabled` /
`metrics.serviceMonitor.enabled` are set. With plain manifests, create the
equivalent Service + ServiceMonitor by hand.

## High availability

Single-replica Deployment, `strategy: Recreate`, no leader election —
sharing one iroh identity key across replica instances isn't supported
upstream, and the read path needs no HA. During a reschedule, consuming
workloads keep whatever Secrets are already applied; only propagation of
new bunker writes pauses until the new pod's replica finishes its initial
sync. This is a documented limitation, not a bug.

## Deploying

`kubectl apply -f <dir>` applies every file in the directory in
alphabetical order, **not** dependency order — `crd.yaml`,
`deployment.yaml`, `namespace.yaml`, `rbac.yaml`. Applying the whole
directory in one shot therefore tries the Deployment (namespace
`secret-bunker-system`) before the Namespace itself exists, and fails on
a fresh cluster (`namespaces "secret-bunker-system" not found`). Apply
the namespace first, then the rest:

```sh
kubectl apply -f operator/deploy/namespace.yaml
kubectl apply -f operator/deploy/
```

The second command applies the `BunkerSecret` CRD, the
ServiceAccount/ClusterRole/ClusterRoleBinding, and the Deployment
(`operator/deploy/crd.yaml`, `rbac.yaml`, `deployment.yaml` — order among
these three doesn't matter). It assumes the
`secret-bunker-operator-identity` Secret already exists (step 3 of
[Bring-your-own-key provisioning](#bring-your-own-key-provisioning-runbook))
and that
`deployment.yaml`'s `BUNKER_ID` and container `image` have been edited for
your bunker and registry.

Or skip all of this with the Helm chart (see
[Installing with Helm](#installing-with-helm)).

## License

secret-bunker-operator links `secret-bunker-iroh`, which is
[AGPL-3.0-or-later](../LICENSE); this crate is licensed the same way.
