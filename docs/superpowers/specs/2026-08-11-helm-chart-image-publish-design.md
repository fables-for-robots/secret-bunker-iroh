# Helm Chart + Image Publishing for secret-bunker-operator — Design

Date: 2026-08-11
Status: approved design, pre-implementation

## Overview

Two deliverables, one release story:

1. A Helm chart for `secret-bunker-operator`, published as an OCI package
   to GHCR, replacing "clone the repo and edit `deploy/deployment.yaml`"
   as the primary install path (the plain manifests stay for kubectl
   users).
2. A GitHub Actions release pipeline that builds the operator container
   image from a new repo-root `Dockerfile` for `linux/amd64` +
   `linux/arm64` and publishes it to
   `ghcr.io/fables-for-robots/secret-bunker-operator`.

One operator behavior change rides along, requested during design: a
**managed identity mode**. Instead of requiring a pre-provisioned key
file, the operator can generate its iroh identity on first boot and
persist it in a Kubernetes Secret — restarts and redeployments reuse the
same identity, never mint a new one. The chart defaults to this mode.

### Goals

- `helm install oci://ghcr.io/fables-for-robots/charts/secret-bunker-operator`
  works on a fresh cluster with only `bunker.id` set.
- First-boot identity bootstrap: install → read the operator's EndpointId
  off the identity Secret → grant it on the bunker → operator goes Ready.
  The private key never leaves the cluster.
- Restarts/redeployments/upgrades/uninstalls never change the operator's
  identity (the identity Secret is the persistence; no PVC).
- Multi-arch images (amd64 + arm64) built on native runners, no QEMU.
- Tag `vX.Y.Z` → image `X.Y.Z` + `latest`, chart `X.Y.Z` (appVersion
  `X.Y.Z`). Every push to `main` → image `edge` + `sha-<short>`.
- The chart is exercised in CI (lint + render always; kind install in the
  manual e2e job).

### Non-goals

- Chart-managed key material: the chart never templates or receives a
  private key through values.
- Multi-replica / leader election, multi-bunker — unchanged v1 scope.
- Publishing the chart to a GitHub Pages `index.yaml` repo (OCI only).
- Automated GHCR package visibility (one-time manual step, see
  [Rollout](#rollout)).
- cargo-chef / build caching sophistication in the Dockerfile — plain
  multi-stage first; optimize if release build times hurt.

## User decisions (do not relitigate)

- Chart published as **OCI to GHCR** (`oci://ghcr.io/fables-for-robots/charts/…`).
- Image is **amd64 + arm64**, native runners stitched into one manifest.
- Image built from a **Dockerfile with buildx** — explicitly chosen over
  reusing the nix `operator-image`. Consequence: the Dockerfile is the
  single image definition; the redundant `operator-image` flake output is
  removed (`packages.operator` binary stays).
- **Tags release, main = edge** trigger/tag scheme (see Goals).
- Identity: **generate if missing, persistent thereafter** — approach A,
  a k8s Secret managed by the operator through the API (not a PVC: RWO
  binding would pin the pod to a node; the SQLite mirror stays
  `emptyDir` by design). `--key-file` remains for bring-your-own-key.

## Operator: managed identity mode

### CLI surface

New flag `--identity-secret <name>` (env `BUNKER_IDENTITY_SECRET`),
mutually exclusive with `--key-file` / `BUNKER_KEY_FILE`; exactly one of
the two is required (clap arg group). `--key-file` behavior is unchanged:
load only, never generate (`keys::load_endpoint_key`).

### Boot flow (managed mode)

In the operator's own namespace (the kube client's default namespace,
from the mounted service-account):

1. GET the named Secret.
2. **Present** → parse `data["identity.key"]` (hex, same encoding as key
   files — `keys::encode_endpoint_key`). Unparsable or missing key ⇒
   **hard error and exit**. Never overwrite existing key material.
3. **Absent (404)** → generate a fresh iroh ed25519 key, `create` (POST,
   not apply) the Secret:
   - `data["identity.key"]`: hex-encoded secret key
   - annotation `bunker.fables-for-robots.ch/endpoint-id`: the public
     EndpointId, so `kubectl describe secret` shows what to grant —
     no log spelunking
   - label `app.kubernetes.io/managed-by: secret-bunker-operator`
   - **not** `immutable: true` — the rotation runbook (replace key
     material in place + rollout restart) must keep working
4. On a 409 create race → re-GET and load (idempotent; single-replica
   Deployment makes this a corner case, not a code path we rely on).

The resolved key then feeds `spawn_replica` exactly as the file path
does today; everything downstream (replica, reconciler, metrics) is
untouched. Key bytes are handled zeroized in memory as elsewhere in the
crate.

### Safety argument

The original "never auto-generate" rule existed so a typo'd `--key-file`
path couldn't silently mint a throwaway identity. Managed mode keys
generation to the *absence of one well-known Secret*, not a path typo,
and a mistakenly fresh identity has no grants: the replica can't sync,
`/readyz` stays 503, `BunkerSecret`s report `AwaitingSync` — loud, and
nothing rendered or lost. Deleting the identity Secret is an explicit
admin action (that *is* the reset/rotate-by-regeneration flow).

### RBAC

The existing ClusterRole already grants `get/list/watch/create/patch` on
`secrets` cluster-wide (the operator writes rendered Secrets); no new
rules needed for managed identity.

## Helm chart

Location `charts/secret-bunker-operator/`, chart name
`secret-bunker-operator`. In-repo `Chart.yaml` carries placeholder
`version: 0.0.0-dev` / `appVersion: 0.0.0-dev`; real values are stamped
at publish time from the git tag.

### CRD handling

`crds/bunkersecrets.yaml` is a **byte-identical copy** of
`operator/deploy/crd.yaml`; CI enforces it (see [CI changes](#ci-changes)).
Helm `crds/` semantics are exactly the safety profile we want: installed
on first install, untouched on upgrade, never deleted on uninstall (so
`helm uninstall` can't cascade-delete every `BunkerSecret` and its
Secrets). Cost, documented in the chart README: CRD **upgrades** are a
manual `kubectl apply -f operator/deploy/crd.yaml` (or `--server-side`)
before `helm upgrade`.

### Templates

Deployment, ServiceAccount, ClusterRole, ClusterRoleBinding (RBAC
mirrors `operator/deploy/rbac.yaml`), optional metrics Service, optional
ServiceMonitor, `_helpers.tpl`, `NOTES.txt`. No Namespace object —
`helm install -n secret-bunker-system --create-namespace`.

`NOTES.txt` prints the post-install step: how to read the EndpointId
annotation and the `bunker add-identity` / `bunker grant` commands
(managed mode), or a reminder that the referenced Secret must exist
(BYO-key mode).

Deployment specifics carried over from `deploy/deployment.yaml`: 1
replica hard-wired with `strategy: Recreate` and a comment explaining the
single-identity constraint (`replicas` deliberately **not** a value);
same securityContexts (runAsNonRoot 65532, readOnlyRootFilesystem, drop
ALL); `emptyDir` mirror volume; liveness `/healthz`, readiness `/readyz`.
In managed mode there is **no identity volume at all**; in BYO-key mode
the named Secret is mounted read-only at `/etc/secret-bunker` with
`defaultMode: 0400` and `--key-file` is passed instead of
`--identity-secret`.

### Values

```yaml
image:
  repository: ghcr.io/fables-for-robots/secret-bunker-operator
  tag: ""              # "" → .Chart.AppVersion
  pullPolicy: IfNotPresent
imagePullSecrets: []

bunker:
  id: ""               # REQUIRED (64-char hex EndpointId); `required` fails install if empty
  addrs: []            # each entry → a repeated --bunker-addr arg

identity:
  secretName: secret-bunker-operator-identity  # managed mode (default)
  existingSecret: ""   # set → BYO-key mode: mount this Secret, use --key-file
  secretKey: identity.key  # BYO-key mode only: item inside existingSecret to
                           # use as the key file. Managed mode always uses
                           # data["identity.key"] (hardcoded operator-side).

resyncInterval: ""     # "" → binary default (1h); flag rendered only when set
stalenessThreshold: "" # "" → binary default (10m)

metrics:
  port: 8080
  service:
    enabled: false
  serviceMonitor:
    enabled: false     # requires metrics.service.enabled

serviceAccount:
  create: true
  name: ""
  annotations: {}
rbac:
  create: true

resources: {}
nodeSelector: {}
tolerations: []
affinity: {}
podAnnotations: {}
podLabels: {}
priorityClassName: ""
```

`helm lint` clean; `helm template` with only `bunker.id` set renders a
valid manifest set matching what `deploy/` produces today (modulo
namespace and managed identity).

## Dockerfile

Repo root (build context = workspace root), plus `.dockerignore`
(`target/`, `.git/`, `.direnv/`, `result`, `docs/`).

- Stage 1 `rust:1.91-bookworm`: copy workspace, `cargo build --release
  --locked -p secret-bunker-operator`. (Verify the exact rust image tag
  at implementation time; must satisfy `rust-version = "1.91"`.)
- Stage 2 `gcr.io/distroless/cc-debian12:nonroot`: glibc + CA certs,
  runs as uid 65532 — matching the chart's securityContext. Copy the
  `operator` binary; `ENTRYPOINT ["/operator"]`.
- OCI labels: `org.opencontainers.image.source=https://github.com/fables-for-robots/secret-bunker-iroh`
  (links the GHCR package to the repo), `…description`,
  `…licenses=AGPL-3.0-or-later`.

`rusqlite` is `bundled` (compiles SQLite in the builder), so the runtime
image needs no sqlite package.

## Release workflow

New `.github/workflows/release.yml`:

- `on: push: branches: [main], tags: ['v*']`
- `permissions: contents: read, packages: write`
- Job **build** — matrix `{ubuntu-latest → linux/amd64, ubuntu-24.04-arm
  → linux/arm64}`: `docker/login-action` (GHCR, `GITHUB_TOKEN`),
  `docker/setup-buildx-action`, `docker/build-push-action` pushing **by
  digest only** (`push-by-digest=true`, no tags); each digest uploaded as
  a workflow artifact for the merge job.
- Job **merge** — needs build: `docker/metadata-action` computes tags —
  on `main`: `edge` + `sha-<short>`; on `v*`: `X.Y.Z` (version without
  the `v`) + `latest` — then one `docker buildx imagetools create`
  stitches both digests into each tag.
- Job **chart** — needs merge, `if: startsWith(github.ref,
  'refs/tags/v')`: `helm registry login ghcr.io` with `GITHUB_TOKEN`,
  `helm package charts/secret-bunker-operator --version X.Y.Z
  --app-version X.Y.Z`, `helm push … oci://ghcr.io/fables-for-robots/charts`.
  Ordering guarantees the image a chart's appVersion points at exists
  before the chart is pullable.

## CI changes

In `.github/workflows/ci.yml`:

- **CRD drift check** (existing `test` job step) additionally asserts
  `diff operator/deploy/crd.yaml charts/secret-bunker-operator/crds/bunkersecrets.yaml`.
- New lightweight **helm job**: `helm lint` +
  `helm template --set bunker.id=<64-hex dummy>` render smoke (runner's
  preinstalled helm; no cluster).
- **e2e-kind** (manual job) reworked: `docker build` the Dockerfile,
  `kind load` it, `helm install` the chart with the local image and a
  dummy 64-hex `bunker.id`, then assert: CRD registered, pod Running
  (liveness green), and — the managed-mode smoke — the operator
  **auto-created the identity Secret** with the `endpoint-id`
  annotation. `/readyz` 503 is expected (no reachable bunker) and not
  asserted. The old placeholder-Secret + `nix build .#operator-image`
  steps go away.

`flake.nix`: drop the `operator-image` output (superseded by the
Dockerfile); keep `packages.operator` and the dev shell (add `helm` to
the dev shell packages).

## Documentation changes

- `operator/README.md`: remove "no Helm chart" from the scope line; add
  a Helm install quickstart as the primary path (managed identity flow:
  install → read annotation → grant → Ready); recast the provisioning
  runbook — managed mode first, BYO-key (`identity.existingSecret`,
  existing keygen runbook) second; note the CRD-upgrade-is-manual rule;
  keep the plain-manifest instructions.
- `charts/secret-bunker-operator/README.md`: values table, install
  one-liner, CRD upgrade note, GHCR locations of chart + image.
- Root `README.md`: one-line pointer to the chart install.

## Testing

- Rust: unit/integration tests for managed-identity resolution against
  the existing kubemock harness (`operator/tests/kubemock/`): absent →
  created with annotation + parseable key; present → loaded, no write;
  present-but-garbage → hard error, no write; 409 on create → re-GET
  path. `--key-file` path untouched by construction (arg group keeps
  modes exclusive).
- Chart: CI `helm lint` + render smoke; byte-diff CRD check; kind e2e as
  above.
- Pipeline: release.yml triggers only on main/tags, so it cannot run on
  the PR itself; first validation is the first main push after merge,
  then a `v0.1.0` tag. The Dockerfile itself *is* PR-validated via the
  reworked e2e-kind job (manual dispatch on the branch).

## Rollout

1. Merge → `main` push publishes `edge` + `sha-…` images (first real run
   of release.yml).
2. Tag `v0.1.0` → image `0.1.0` + `latest`, chart `0.1.0`.
3. Manual, once: set both GHCR packages
   (`secret-bunker-operator`, `charts/secret-bunker-operator`) public in
   the org package settings (GHCR defaults to private).
