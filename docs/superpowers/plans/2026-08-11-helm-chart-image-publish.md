# Helm Chart + Image Publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Helm chart (OCI on GHCR) + multi-arch GHCR image publishing for secret-bunker-operator, plus a managed-identity mode where the operator generates its iroh key on first boot and persists it in a Kubernetes Secret.

**Architecture:** A new `identity` module resolves the operator key from either a file (existing `--key-file`) or a managed k8s Secret (new `--identity-secret`, generate-if-absent, never overwrite). The chart at `charts/secret-bunker-operator/` defaults to managed mode; CRD ships in the chart's `crds/` dir as a byte-copy of `operator/deploy/crd.yaml`. A repo-root Dockerfile is the single image definition; `release.yml` builds amd64+arm64 on native runners, pushes by digest, stitches one manifest, and pushes the chart on `v*` tags.

**Tech Stack:** Rust (kube 4.2, k8s-openapi 0.28, clap 4, iroh 1), Helm 3, Docker buildx, GitHub Actions, GHCR.

**Spec:** `docs/superpowers/specs/2026-08-11-helm-chart-image-publish-design.md` — read it first.

## Global Constraints

- Rust edition 2024, `rust-version = "1.91"`; CI runs `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` — code must pass both.
- Image name: `ghcr.io/fables-for-robots/secret-bunker-operator`. Chart OCI repo: `oci://ghcr.io/fables-for-robots/charts`.
- Identity Secret data key: `identity.key` (hardcoded operator-side in managed mode). Annotation: `bunker.fables-for-robots.ch/endpoint-id`. Label: `app.kubernetes.io/managed-by: secret-bunker-operator`.
- Never overwrite existing key material: present-but-unparsable identity Secret ⇒ hard error and exit.
- Managed-mode Secret is **not** `immutable: true` (rotation runbook replaces key material in place).
- Chart.yaml in-repo carries `version: 0.0.0-dev` / `appVersion: 0.0.0-dev`; real versions stamped only at publish time.
- `charts/secret-bunker-operator/crds/bunkersecrets.yaml` must stay byte-identical to `operator/deploy/crd.yaml` (CI-enforced).
- Tag scheme: main push → `edge` + `sha-<short>`; tag `vX.Y.Z` → `X.Y.Z` + `latest` + chart `X.Y.Z`.
- Replicas hard-wired to 1 with `strategy: Recreate` — not a chart value.
- All work on the existing `helm-chart` branch; commit after every task.

---

### Task 1: Managed identity module (`identity.rs`)

**Files:**
- Create: `operator/src/identity.rs`
- Modify: `operator/src/lib.rs` (add `pub mod identity;`)
- Test: `operator/tests/identity.rs`

**Interfaces:**
- Consumes: `operator/tests/kubemock/mod.rs` — `scripted(Vec<Expectation>) -> (kube::Client, JoinHandle<()>)`, `expect(method, path_contains, status, respond_json)`, `expect_checked(…, check)`. The mock client's default namespace is `"default"`. `secret_bunker_iroh::keys::encode_endpoint_key(&SecretKey) -> String` (lowercase hex).
- Produces: `secret_bunker_operator::identity::resolve_managed_identity(client: &kube::Client, name: &str) -> anyhow::Result<iroh::SecretKey>`; consts `identity::IDENTITY_SECRET_KEY = "identity.key"`, `identity::ENDPOINT_ID_ANNOTATION = "bunker.fables-for-robots.ch/endpoint-id"`. Task 2 calls `resolve_managed_identity`; the chart (Task 3) and e2e job (Task 7) rely on the Secret shape produced here.

- [ ] **Step 1: Write the failing tests**

Create `operator/tests/identity.rs`:

```rust
//! Managed-identity resolution against the scripted kube mock.

mod kubemock;

use std::str::FromStr as _;

use iroh::SecretKey;
use kubemock::{expect, expect_checked, scripted};
use secret_bunker_iroh::keys::encode_endpoint_key;
use secret_bunker_operator::identity::{
    ENDPOINT_ID_ANNOTATION, IDENTITY_SECRET_KEY, resolve_managed_identity,
};

const NAME: &str = "secret-bunker-operator-identity";
const SECRETS_PATH: &str = "/api/v1/namespaces/default/secrets";

fn secret_json(key: &SecretKey) -> serde_json::Value {
    let b64 = data_encoding::BASE64.encode(encode_endpoint_key(key).as_bytes());
    serde_json::json!({
        "apiVersion": "v1", "kind": "Secret",
        "metadata": { "name": NAME, "namespace": "default" },
        "data": { IDENTITY_SECRET_KEY: b64 },
    })
}

fn not_found() -> serde_json::Value {
    serde_json::json!({
        "kind": "Status", "apiVersion": "v1", "metadata": {},
        "status": "Failure", "reason": "NotFound", "code": 404,
        "message": "secrets \"secret-bunker-operator-identity\" not found",
    })
}

#[tokio::test]
async fn present_secret_is_loaded_not_written() {
    let existing = SecretKey::generate();
    let (client, join) = scripted(vec![expect(
        "GET",
        &format!("{SECRETS_PATH}/{NAME}"),
        200,
        secret_json(&existing),
    )]);
    let got = resolve_managed_identity(&client, NAME).await.unwrap();
    assert_eq!(got.public(), existing.public());
    join.await.unwrap(); // script exhausted: exactly one GET, no writes
}

#[tokio::test]
async fn absent_secret_is_generated_and_created() {
    let (client, join) = scripted(vec![
        expect("GET", &format!("{SECRETS_PATH}/{NAME}"), 404, not_found()),
        expect_checked(
            "POST",
            SECRETS_PATH,
            201,
            serde_json::json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": { "name": NAME, "namespace": "default" },
            }),
            |body| {
                let key_text = body["stringData"][IDENTITY_SECRET_KEY]
                    .as_str()
                    .expect("stringData carries the key");
                let key = SecretKey::from_str(key_text.trim()).expect("created key parses");
                let annotated = body["metadata"]["annotations"][ENDPOINT_ID_ANNOTATION]
                    .as_str()
                    .expect("endpoint-id annotation present");
                assert_eq!(annotated, key.public().to_string());
                assert_eq!(
                    body["metadata"]["labels"]["app.kubernetes.io/managed-by"],
                    "secret-bunker-operator"
                );
            },
        ),
    ]);
    let got = resolve_managed_identity(&client, NAME).await.unwrap();
    // A freshly generated key: 64-hex public id.
    assert_eq!(got.public().to_string().len(), 64);
    join.await.unwrap();
}

#[tokio::test]
async fn garbage_key_material_is_a_hard_error() {
    let bad = serde_json::json!({
        "apiVersion": "v1", "kind": "Secret",
        "metadata": { "name": NAME, "namespace": "default" },
        "data": { IDENTITY_SECRET_KEY: data_encoding::BASE64.encode(b"not-a-key") },
    });
    let (client, join) = scripted(vec![expect(
        "GET",
        &format!("{SECRETS_PATH}/{NAME}"),
        200,
        bad,
    )]);
    let err = resolve_managed_identity(&client, NAME).await.unwrap_err();
    assert!(err.to_string().contains("refusing to overwrite"), "{err}");
    join.await.unwrap(); // no POST followed the failed parse
}

#[tokio::test]
async fn create_race_falls_back_to_winner() {
    let winner = SecretKey::generate();
    let conflict = serde_json::json!({
        "kind": "Status", "apiVersion": "v1", "metadata": {},
        "status": "Failure", "reason": "AlreadyExists", "code": 409,
        "message": "secrets \"secret-bunker-operator-identity\" already exists",
    });
    let (client, join) = scripted(vec![
        expect("GET", &format!("{SECRETS_PATH}/{NAME}"), 404, not_found()),
        expect("POST", SECRETS_PATH, 409, conflict),
        expect(
            "GET",
            &format!("{SECRETS_PATH}/{NAME}"),
            200,
            secret_json(&winner),
        ),
    ]);
    let got = resolve_managed_identity(&client, NAME).await.unwrap();
    assert_eq!(got.public(), winner.public());
    join.await.unwrap();
}
```

Note: `data-encoding` is already a dependency of the operator crate (`operator/Cargo.toml:21`), but only for the binary — if `cargo test` complains it is not visible to tests, it is already in `[dependencies]` so it will be.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-bunker-operator --test identity`
Expected: COMPILE FAILURE — `secret_bunker_operator::identity` does not exist.

- [ ] **Step 3: Implement the module**

Create `operator/src/identity.rs`:

```rust
//! Managed identity: the operator's iroh key, stored in a Kubernetes Secret.
//!
//! First boot generates a key and creates the Secret; every later boot loads
//! the same key. Present-but-unparsable key material is a hard error — this
//! module never overwrites an existing key. The public EndpointId is recorded
//! in an annotation so `kubectl describe secret` shows what to grant on the
//! bunker side without log spelunking.

use std::collections::BTreeMap;

use anyhow::Context as _;
use iroh::SecretKey;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::Client;
use secret_bunker_iroh::keys;

/// Data key inside the identity Secret. Same hex encoding as key files.
pub const IDENTITY_SECRET_KEY: &str = "identity.key";
/// Annotation carrying the public EndpointId of the stored key.
pub const ENDPOINT_ID_ANNOTATION: &str = "bunker.fables-for-robots.ch/endpoint-id";

/// Resolve the operator identity from the named Secret in the client's
/// default namespace (in-cluster: the pod's own namespace), generating and
/// storing a fresh key when the Secret does not exist.
pub async fn resolve_managed_identity(client: &Client, name: &str) -> anyhow::Result<SecretKey> {
    let api: Api<Secret> = Api::default_namespaced(client.clone());
    if let Some(existing) = api
        .get_opt(name)
        .await
        .with_context(|| format!("getting identity Secret {name}"))?
    {
        let key = parse_identity_secret(&existing, name)?;
        tracing::info!(secret = name, operator_id = %key.public(), "loaded operator identity");
        return Ok(key);
    }
    let key = SecretKey::generate();
    match api.create(&PostParams::default(), &identity_secret(name, &key)).await {
        Ok(_) => {
            tracing::info!(
                secret = name,
                operator_id = %key.public(),
                "generated new operator identity; grant it read access on the bunker"
            );
            Ok(key)
        }
        // Lost a create race (or the Secret appeared since the GET): the
        // stored key wins — ours is discarded, never the other way around.
        Err(kube::Error::Api(ae)) if ae.code == 409 => {
            let existing = api
                .get(name)
                .await
                .with_context(|| format!("re-getting identity Secret {name} after create conflict"))?;
            let key = parse_identity_secret(&existing, name)?;
            tracing::info!(secret = name, operator_id = %key.public(), "loaded operator identity (lost create race)");
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("creating identity Secret {name}")),
    }
}

fn parse_identity_secret(secret: &Secret, name: &str) -> anyhow::Result<SecretKey> {
    let data = secret
        .data
        .as_ref()
        .and_then(|d| d.get(IDENTITY_SECRET_KEY))
        .with_context(|| format!("identity Secret {name} has no {IDENTITY_SECRET_KEY:?} entry"))?;
    let text = std::str::from_utf8(&data.0)
        .with_context(|| format!("identity Secret {name}: {IDENTITY_SECRET_KEY:?} is not UTF-8"))?;
    text.trim().parse::<SecretKey>().map_err(|e| {
        anyhow::anyhow!(
            "parsing key from identity Secret {name}: {e} — refusing to overwrite existing key material; \
             delete the Secret to let the operator generate a fresh identity"
        )
    })
}

fn identity_secret(name: &str, key: &SecretKey) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            annotations: Some(BTreeMap::from([(
                ENDPOINT_ID_ANNOTATION.to_string(),
                key.public().to_string(),
            )])),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/managed-by".to_string(),
                "secret-bunker-operator".to_string(),
            )])),
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([(
            IDENTITY_SECRET_KEY.to_string(),
            keys::encode_endpoint_key(key),
        )])),
        type_: Some("Opaque".to_string()),
        ..Default::default()
    }
}
```

Add to `operator/src/lib.rs` (alphabetical, after `pub mod http;` — the list is `bunker, crd, events, http, metrics, reconcile, render, secretbuild`):

```rust
pub mod identity;
```

(placed between `http` and `metrics`)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p secret-bunker-operator --test identity`
Expected: 4 tests PASS.

- [ ] **Step 5: fmt + clippy + commit**

```bash
cargo fmt --all
cargo clippy -p secret-bunker-operator --all-targets -- -D warnings
git add operator/src/identity.rs operator/src/lib.rs operator/tests/identity.rs
git commit -m "feat(operator): managed identity — generate-on-first-boot key in a k8s Secret"
```

---

### Task 2: Wire managed identity into the binary

**Files:**
- Modify: `operator/src/main.rs` (Args struct lines 28-51, boot sequence lines 61-82)
- Modify: `operator/src/bunker.rs:93-118` (`spawn_replica` takes a resolved key)
- Test: `operator/tests/replica_source.rs:40-92` (adjust to the new signature)

**Interfaces:**
- Consumes: `identity::resolve_managed_identity(&Client, &str)` from Task 1; `secret_bunker_iroh::keys::load_endpoint_key(&Path) -> anyhow::Result<SecretKey>`.
- Produces: `spawn_replica(id: &str, addrs: &[SocketAddr], secret: iroh::SecretKey, mirror_path: &Path) -> anyhow::Result<Replica>`; CLI contract used by the chart (Task 3): `--key-file` and `--identity-secret` (env `BUNKER_IDENTITY_SECRET`) are mutually exclusive, exactly one required.

- [ ] **Step 1: Update the existing test to the new signature (failing first)**

In `operator/tests/replica_source.rs`, replace the body of `spawn_replica_loads_key_from_explicit_path` (lines 41-92) — the file-load now happens before spawn, and the missing-file hard error is asserted at load time:

```rust
#[tokio::test]
async fn spawn_replica_loads_key_from_explicit_path() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("g").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("g", "op").await;
    bunker.put("g", "s", b"v", 0).await;

    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("identity.key");
    std::fs::write(
        &key_file,
        secret_bunker_iroh::keys::encode_endpoint_key(&reader),
    )
    .unwrap();

    // Direct socket addrs from the in-process bunker's EndpointAddr.
    let addrs: Vec<std::net::SocketAddr> = bunker
        .addr
        .addrs
        .iter()
        .filter_map(|a| match a {
            iroh::TransportAddr::Ip(s) => Some(*s),
            _ => None,
        })
        .collect();
    assert!(
        !addrs.is_empty(),
        "in-process bunker must expose an IP transport addr"
    );

    let key = secret_bunker_iroh::keys::load_endpoint_key(&key_file).unwrap();
    let replica = spawn_replica(
        &bunker.addr.id.to_string(),
        &addrs,
        key,
        &dir.path().join("mirror.sqlite"),
    )
    .await
    .unwrap();
    let got = common::await_mirrored(&replica, "g", "s").await;
    assert_eq!(got, b"v".to_vec());
    // A missing key file is still a hard error at load time — file mode
    // never auto-generates an identity.
    let err =
        secret_bunker_iroh::keys::load_endpoint_key(&dir.path().join("missing.key")).unwrap_err();
    assert!(err.to_string().contains("reading endpoint key"), "{err}");
}
```

- [ ] **Step 2: Run to verify the test fails to compile**

Run: `cargo test -p secret-bunker-operator --test replica_source`
Expected: COMPILE FAILURE — `spawn_replica` still takes `&Path` where a `SecretKey` is passed.

- [ ] **Step 3: Change `spawn_replica` to take the resolved key**

In `operator/src/bunker.rs`, replace lines 93-118 with:

```rust
/// Spawn the embedded replica from operator config. Key resolution (file or
/// managed Secret) happens in `main`/`identity` before this — by the time we
/// are here an identity exists; nothing is ever auto-generated past this
/// point.
pub async fn spawn_replica(
    id: &str,
    addrs: &[SocketAddr],
    secret: iroh::SecretKey,
    mirror_path: &Path,
) -> anyhow::Result<Replica> {
    let authoritative: iroh::EndpointId =
        id.parse().context("parsing --bunker-id as an EndpointId")?;
    tracing::info!(
        operator_id = %secret.public(),
        %authoritative,
        "spawning embedded replica"
    );
    let mut builder = Replica::builder()
        .store_path(mirror_path)
        .secret_key(secret)
        .authoritative(authoritative);
    if !addrs.is_empty() {
        builder = builder.authoritative_addrs(addrs.iter().copied());
    }
    builder.spawn().await
}
```

and drop the now-unused `use secret_bunker_iroh::keys;` import (line 10).

- [ ] **Step 4: Rework `main.rs` args and boot order**

In `operator/src/main.rs`, replace the `key_file` field (lines 36-38) with:

```rust
    /// Path to the operator's iroh ed25519 key (pre-provisioned; never
    /// generated). Exactly one of --key-file / --identity-secret.
    #[arg(
        long,
        env = "BUNKER_KEY_FILE",
        conflicts_with = "identity_secret",
        required_unless_present = "identity_secret"
    )]
    key_file: Option<PathBuf>,
    /// Name of a Secret in the operator's own namespace holding its identity
    /// key; generated and stored there on first boot when missing.
    #[arg(long, env = "BUNKER_IDENTITY_SECRET")]
    identity_secret: Option<String>,
```

Then reorder boot: the kube client must exist before key resolution. Replace lines 63-82 (`let metrics…` through `let secrets…`) with:

```rust
    let metrics = Metrics::new()?;
    let client = Client::try_default()
        .await
        .context("building kube client")?;
    let secret_key = match (&args.key_file, &args.identity_secret) {
        (Some(path), None) => secret_bunker_iroh::keys::load_endpoint_key(path)?,
        (None, Some(name)) => identity::resolve_managed_identity(&client, name).await?,
        // clap: conflicts_with + required_unless_present enforce exactly one.
        _ => unreachable!("clap enforces exactly one of --key-file/--identity-secret"),
    };
    let replica = Arc::new(
        spawn_replica(
            &args.bunker_id,
            &args.bunker_addr,
            secret_key,
            &args.mirror_path,
        )
        .await
        .context("spawning embedded replica")?,
    );
    // Subscribe immediately after spawn — race-free window for the first events.
    let events_rx = replica.subscribe();
    let staleness = Arc::new(Staleness::new());

    let crs: Api<BunkerSecret> = Api::all(client.clone());
    let secrets: Api<Secret> = Api::all(client.clone());
```

Add the import (with the other `secret_bunker_operator` imports):

```rust
use secret_bunker_operator::identity;
```

- [ ] **Step 5: Run the full operator test suite**

Run: `cargo test -p secret-bunker-operator`
Expected: ALL PASS (identity, replica_source, reconcile_apply, reconcile_cleanup and unit tests).

- [ ] **Step 6: Sanity-check the CLI contract**

```bash
cargo run -p secret-bunker-operator --bin operator -- --bunker-id=x --mirror-path=/tmp/m.sqlite 2>&1 | head -5
```
Expected: clap usage error mentioning that `--key-file` (or `--identity-secret`) is required — NOT a panic, NOT a successful start.

```bash
cargo run -p secret-bunker-operator --bin operator -- --bunker-id=x --mirror-path=/tmp/m.sqlite --key-file=/a --identity-secret=b 2>&1 | head -5
```
Expected: clap conflict error (`--key-file` cannot be used with `--identity-secret`).

- [ ] **Step 7: fmt + clippy + commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add operator/src/main.rs operator/src/bunker.rs operator/tests/replica_source.rs
git commit -m "feat(operator): --identity-secret flag; spawn_replica takes a resolved key"
```

---

### Task 3: Helm chart core

**Files:**
- Create: `charts/secret-bunker-operator/Chart.yaml`
- Create: `charts/secret-bunker-operator/values.yaml`
- Create: `charts/secret-bunker-operator/.helmignore`
- Create: `charts/secret-bunker-operator/templates/_helpers.tpl`
- Create: `charts/secret-bunker-operator/templates/deployment.yaml`
- Create: `charts/secret-bunker-operator/templates/serviceaccount.yaml`
- Create: `charts/secret-bunker-operator/templates/rbac.yaml`
- Create: `charts/secret-bunker-operator/crds/bunkersecrets.yaml` (byte-copy)

**Interfaces:**
- Consumes: CLI contract from Task 2 (`--identity-secret` / `--key-file`, `--bunker-id`, `--bunker-addr` repeatable, `--mirror-path`, `--resync-interval`, `--staleness-threshold`, `--listen`); RBAC rules verbatim from `operator/deploy/rbac.yaml`; securityContext/probes from `operator/deploy/deployment.yaml`.
- Produces: chart rendered by Tasks 4/6/7; values schema documented in Task 8. Helper names: `secret-bunker-operator.fullname`, `.labels`, `.selectorLabels`, `.serviceAccountName`.

- [ ] **Step 1: Copy the CRD (the "test" for this file is the byte-diff)**

```bash
mkdir -p charts/secret-bunker-operator/crds charts/secret-bunker-operator/templates
cp operator/deploy/crd.yaml charts/secret-bunker-operator/crds/bunkersecrets.yaml
diff operator/deploy/crd.yaml charts/secret-bunker-operator/crds/bunkersecrets.yaml
```
Expected: `diff` exits 0, no output.

- [ ] **Step 2: Write Chart.yaml, values.yaml, .helmignore**

`charts/secret-bunker-operator/Chart.yaml`:

```yaml
apiVersion: v2
name: secret-bunker-operator
description: Syncs secrets from a secret-bunker-iroh bunker into native Kubernetes Secrets
type: application
# Placeholders: the release workflow stamps the real chart/app version from
# the git tag (helm package --version X.Y.Z --app-version X.Y.Z).
version: 0.0.0-dev
appVersion: 0.0.0-dev
home: https://github.com/fables-for-robots/secret-bunker-iroh
sources:
  - https://github.com/fables-for-robots/secret-bunker-iroh
```

`charts/secret-bunker-operator/values.yaml`:

```yaml
image:
  repository: ghcr.io/fables-for-robots/secret-bunker-operator
  # "" → the chart's appVersion (the image released with this chart).
  tag: ""
  pullPolicy: IfNotPresent
imagePullSecrets: []

bunker:
  # REQUIRED: EndpointId (64-char hex) of the authoritative bunker.
  id: ""
  # Direct host:port addresses of the bunker; each entry becomes a repeated
  # --bunker-addr flag. Empty → iroh n0 relay/discovery.
  addrs: []

identity:
  # Managed mode (default): the operator generates its iroh key on first
  # boot and stores it in this Secret in the release namespace; restarts
  # reuse it. The public EndpointId to grant is recorded in the Secret's
  # "bunker.fables-for-robots.ch/endpoint-id" annotation.
  secretName: secret-bunker-operator-identity
  # Bring-your-own-key mode: set to the name of an existing Secret to mount
  # it read-only and pass --key-file instead. Nothing is ever generated.
  existingSecret: ""
  # BYO-key mode only: the item inside existingSecret holding the key file.
  # Managed mode always uses "identity.key" (hardcoded operator-side).
  secretKey: identity.key

# "" → binary defaults (1h / 10m); flags are only rendered when set.
resyncInterval: ""
stalenessThreshold: ""

metrics:
  port: 8080
  service:
    enabled: false
  serviceMonitor:
    # Requires metrics.service.enabled and the Prometheus Operator CRDs.
    enabled: false

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

`charts/secret-bunker-operator/.helmignore`:

```
.DS_Store
*.swp
*.bak
*.tmp
*.orig
.git/
.gitignore
```

- [ ] **Step 3: Write _helpers.tpl**

`charts/secret-bunker-operator/templates/_helpers.tpl`:

```
{{- define "secret-bunker-operator.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else -}}
{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end -}}
{{- end }}

{{- define "secret-bunker-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "secret-bunker-operator.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "secret-bunker-operator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "secret-bunker-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ default (include "secret-bunker-operator.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end }}
```

- [ ] **Step 4: Write the Deployment template**

`charts/secret-bunker-operator/templates/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "secret-bunker-operator.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "secret-bunker-operator.labels" . | nindent 4 }}
spec:
  # One iroh identity, one replica: never two pods at once — sharing one
  # identity key across concurrent endpoints is unsupported upstream.
  # Deliberately not a value.
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      {{- include "secret-bunker-operator.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "secret-bunker-operator.selectorLabels" . | nindent 8 }}
        {{- with .Values.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      {{- with .Values.podAnnotations }}
      annotations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
    spec:
      serviceAccountName: {{ include "secret-bunker-operator.serviceAccountName" . }}
      {{- with .Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.priorityClassName }}
      priorityClassName: {{ . }}
      {{- end }}
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        fsGroup: 65532
      containers:
        - name: operator
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          args:
            - --bunker-id={{ required "bunker.id is required: the authoritative bunker's EndpointId (64-char hex)" .Values.bunker.id }}
            {{- range .Values.bunker.addrs }}
            - --bunker-addr={{ . }}
            {{- end }}
            {{- if .Values.identity.existingSecret }}
            - --key-file=/etc/secret-bunker/{{ .Values.identity.secretKey }}
            {{- else }}
            - --identity-secret={{ .Values.identity.secretName }}
            {{- end }}
            - --mirror-path=/var/lib/secret-bunker/replica.sqlite
            {{- with .Values.resyncInterval }}
            - --resync-interval={{ . }}
            {{- end }}
            {{- with .Values.stalenessThreshold }}
            - --staleness-threshold={{ . }}
            {{- end }}
            - --listen=0.0.0.0:{{ .Values.metrics.port }}
          ports:
            - containerPort: {{ .Values.metrics.port }}
              name: http
          livenessProbe:
            httpGet: { path: /healthz, port: http }
          readinessProbe:
            httpGet: { path: /readyz, port: http }
            periodSeconds: 5
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          {{- with .Values.resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          volumeMounts:
            - name: mirror
              mountPath: /var/lib/secret-bunker
            {{- if .Values.identity.existingSecret }}
            - name: identity
              mountPath: /etc/secret-bunker
              readOnly: true
            {{- end }}
      {{- with .Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      volumes:
        - name: mirror
          emptyDir: {}      # full resync each start, by design
        {{- if .Values.identity.existingSecret }}
        - name: identity
          secret:
            secretName: {{ .Values.identity.existingSecret }}
            defaultMode: 0400
        {{- end }}
```

- [ ] **Step 5: Write ServiceAccount and RBAC templates**

`charts/secret-bunker-operator/templates/serviceaccount.yaml`:

```yaml
{{- if .Values.serviceAccount.create }}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "secret-bunker-operator.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "secret-bunker-operator.labels" . | nindent 4 }}
  {{- with .Values.serviceAccount.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
```

`charts/secret-bunker-operator/templates/rbac.yaml` (rules verbatim from `operator/deploy/rbac.yaml`):

```yaml
{{- if .Values.rbac.create }}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "secret-bunker-operator.fullname" . }}
  labels:
    {{- include "secret-bunker-operator.labels" . | nindent 4 }}
rules:
  - apiGroups: ["bunker.fables-for-robots.ch"]
    resources: ["bunkersecrets"]
    verbs: ["get", "list", "watch", "patch"]
  - apiGroups: ["bunker.fables-for-robots.ch"]
    resources: ["bunkersecrets/status"]
    verbs: ["get", "patch"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
  - apiGroups: ["events.k8s.io"]
    resources: ["events"]
    verbs: ["create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "secret-bunker-operator.fullname" . }}
  labels:
    {{- include "secret-bunker-operator.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "secret-bunker-operator.fullname" . }}
subjects:
  - kind: ServiceAccount
    name: {{ include "secret-bunker-operator.serviceAccountName" . }}
    namespace: {{ .Release.Namespace }}
{{- end }}
```

- [ ] **Step 6: Lint and render both modes**

```bash
helm lint charts/secret-bunker-operator
helm template test charts/secret-bunker-operator \
  --namespace secret-bunker-system \
  --set bunker.id=5866666666666666666666666666666666666666666666666666666666666666
helm template test charts/secret-bunker-operator \
  --namespace secret-bunker-system \
  --set bunker.id=5866666666666666666666666666666666666666666666666666666666666666 \
  --set identity.existingSecret=my-identity \
  --set identity.secretKey=op.key \
  --set bunker.addrs='{10.0.0.5:4433,10.0.0.6:4433}'
helm template test charts/secret-bunker-operator 2>&1 | grep 'bunker.id is required'
```
Expected: lint passes (0 failures); first render shows `--identity-secret=secret-bunker-operator-identity` and NO identity volume; second shows `--key-file=/etc/secret-bunker/op.key`, the identity volume/mount, and two `--bunker-addr` args; third fails with the `required` message. If `helm` is missing locally: `nix shell nixpkgs#kubernetes-helm -c helm …`.

- [ ] **Step 7: Commit**

```bash
git add charts/
git commit -m "feat(chart): secret-bunker-operator Helm chart — core templates + CRD"
```

---

### Task 4: Chart extras — metrics Service, ServiceMonitor, NOTES.txt

**Files:**
- Create: `charts/secret-bunker-operator/templates/service.yaml`
- Create: `charts/secret-bunker-operator/templates/servicemonitor.yaml`
- Create: `charts/secret-bunker-operator/templates/NOTES.txt`

**Interfaces:**
- Consumes: helpers and values from Task 3; annotation name `bunker.fables-for-robots.ch/endpoint-id` from Task 1.
- Produces: nothing consumed by later tasks (leaf templates).

- [ ] **Step 1: Write service.yaml**

```yaml
{{- if .Values.metrics.service.enabled }}
apiVersion: v1
kind: Service
metadata:
  name: {{ include "secret-bunker-operator.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "secret-bunker-operator.labels" . | nindent 4 }}
spec:
  selector:
    {{- include "secret-bunker-operator.selectorLabels" . | nindent 4 }}
  ports:
    - name: http
      port: {{ .Values.metrics.port }}
      targetPort: http
{{- end }}
```

- [ ] **Step 2: Write servicemonitor.yaml**

```yaml
{{- if .Values.metrics.serviceMonitor.enabled }}
{{- if not .Values.metrics.service.enabled }}
{{- fail "metrics.serviceMonitor.enabled requires metrics.service.enabled" }}
{{- end }}
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {{ include "secret-bunker-operator.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "secret-bunker-operator.labels" . | nindent 4 }}
spec:
  selector:
    matchLabels:
      {{- include "secret-bunker-operator.selectorLabels" . | nindent 6 }}
  endpoints:
    - port: http
      path: /metrics
{{- end }}
```

- [ ] **Step 3: Write NOTES.txt**

```
secret-bunker-operator installed as release {{ .Release.Name }} in namespace {{ .Release.Namespace }}.

{{- if .Values.identity.existingSecret }}

Identity: bring-your-own-key mode, using Secret "{{ .Values.identity.existingSecret }}"
(item "{{ .Values.identity.secretKey }}"). The Secret must already exist in
{{ .Release.Namespace }} — the pod will not start until it does.
{{- else }}

Identity: managed mode. On first boot the operator generates its iroh key and
stores it in Secret "{{ .Values.identity.secretName }}"; restarts reuse it.
Grant the operator read access on your bunker:

  kubectl -n {{ .Release.Namespace }} get secret {{ .Values.identity.secretName }} \
    -o jsonpath='{.metadata.annotations.bunker\.fables-for-robots\.ch/endpoint-id}'
  bunker add-identity --name k8s-operator --id <EndpointId printed above>
  bunker grant --group <group> --identity k8s-operator --perms r

Until granted, /readyz stays 503 and BunkerSecrets report AwaitingSync — loud,
nothing rendered.
{{- end }}

CRD upgrades are manual (Helm never touches crds/ after install):
  kubectl apply -f https://raw.githubusercontent.com/fables-for-robots/secret-bunker-iroh/main/operator/deploy/crd.yaml
```

- [ ] **Step 4: Render with metrics enabled + failure guard**

```bash
helm template test charts/secret-bunker-operator \
  --namespace secret-bunker-system \
  --set bunker.id=5866666666666666666666666666666666666666666666666666666666666666 \
  --set metrics.service.enabled=true \
  --set metrics.serviceMonitor.enabled=true \
  | grep -E 'kind: (Service|ServiceMonitor)'
helm template test charts/secret-bunker-operator \
  --set bunker.id=5866666666666666666666666666666666666666666666666666666666666666 \
  --set metrics.serviceMonitor.enabled=true 2>&1 \
  | grep 'requires metrics.service.enabled'
helm lint charts/secret-bunker-operator
```
Expected: first shows both kinds; second fails with the guard message; lint clean.

- [ ] **Step 5: Commit**

```bash
git add charts/secret-bunker-operator/templates/
git commit -m "feat(chart): optional metrics Service/ServiceMonitor, NOTES"
```

---

### Task 5: Dockerfile + .dockerignore

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

**Interfaces:**
- Consumes: workspace layout (operator binary is `-p secret-bunker-operator --bin operator`); `rust-version = "1.91"` from both Cargo.tomls.
- Produces: the image contract used by release.yml (Task 6) and e2e-kind (Task 7): repo-root build context, final binary at `/operator`, uid 65532.

- [ ] **Step 1: Write .dockerignore**

```
.git/
.direnv/
.superpowers/
target/
result
docs/
design/
*.gif
*.png
```

- [ ] **Step 2: Write Dockerfile**

```dockerfile
FROM rust:1.91-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked -p secret-bunker-operator --bin operator

# distroless/cc: glibc + CA certs, nothing else; :nonroot runs as uid 65532,
# matching the chart's runAsUser/fsGroup.
FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/fables-for-robots/secret-bunker-iroh" \
      org.opencontainers.image.description="secret-bunker → Kubernetes Secret sync operator" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
COPY --from=builder /build/target/release/operator /operator
USER 65532:65532
ENTRYPOINT ["/operator"]
```

If `docker pull rust:1.91-bookworm` reports no such tag, use the most specific existing tag satisfying rust-version 1.91 (e.g. `rust:1.91`); do not fall back to `rust:latest`.

- [ ] **Step 3: Build the image (the test)**

Run: `docker build -t secret-bunker-operator:dev .`
Expected: builds to completion; a Rust release build takes minutes — be patient.
If no docker daemon is available locally, this is verified by the e2e-kind workflow dispatch after the PR is pushed (Task 7 / Task 9) — note it in the commit message and move on.

- [ ] **Step 4: Smoke the entrypoint (only if the build ran)**

```bash
docker run --rm secret-bunker-operator:dev --help
docker rmi secret-bunker-operator:dev
```
Expected: clap help listing `--bunker-id`, `--key-file`, `--identity-secret`. Remove the local image afterwards (keep the machine clean).

- [ ] **Step 5: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "build: repo-root Dockerfile (rust builder → distroless/cc, uid 65532)"
```

---

### Task 6: Release workflow (`release.yml`)

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: Dockerfile contract from Task 5; chart from Tasks 3-4 (placeholder versions stamped here).
- Produces: images at `ghcr.io/fables-for-robots/secret-bunker-operator`, chart at `oci://ghcr.io/fables-for-robots/charts/secret-bunker-operator`.

- [ ] **Step 1: Write the workflow**

```yaml
name: Release

on:
  push:
    branches: [main]
    tags: ['v*']

env:
  IMAGE: ghcr.io/fables-for-robots/secret-bunker-operator

jobs:
  build:
    strategy:
      matrix:
        include:
          - runner: ubuntu-latest
            platform: linux/amd64
          - runner: ubuntu-24.04-arm
            platform: linux/arm64
    runs-on: ${{ matrix.runner }}
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v5

      - name: Sanitize platform for artifact name
        id: platform
        env:
          PLATFORM: ${{ matrix.platform }}
        run: echo "pair=${PLATFORM//\//-}" >> "$GITHUB_OUTPUT"

      - uses: docker/setup-buildx-action@v3

      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push by digest
        id: build
        uses: docker/build-push-action@v6
        with:
          context: .
          platforms: ${{ matrix.platform }}
          outputs: type=image,name=${{ env.IMAGE }},push-by-digest=true,name-canonical=true,push=true

      - name: Export digest
        env:
          DIGEST: ${{ steps.build.outputs.digest }}
        run: |
          mkdir -p /tmp/digests
          touch "/tmp/digests/${DIGEST#sha256:}"

      - uses: actions/upload-artifact@v4
        with:
          name: digests-${{ steps.platform.outputs.pair }}
          path: /tmp/digests/*
          if-no-files-found: error
          retention-days: 1

  merge:
    runs-on: ubuntu-latest
    needs: build
    permissions:
      packages: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: /tmp/digests
          pattern: digests-*
          merge-multiple: true

      - uses: docker/setup-buildx-action@v3

      # main → edge + sha-<short>; tag vX.Y.Z → X.Y.Z (+ latest via
      # flavor's default latest=auto on semver).
      - uses: docker/metadata-action@v5
        id: meta
        with:
          images: ${{ env.IMAGE }}
          tags: |
            type=edge,branch=main
            type=sha
            type=semver,pattern={{version}}

      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Create multi-arch manifest
        working-directory: /tmp/digests
        run: |
          docker buildx imagetools create \
            $(jq -cr '.tags | map("-t " + .) | join(" ")' <<< "$DOCKER_METADATA_OUTPUT_JSON") \
            $(printf "$IMAGE@sha256:%s " *)

      - name: Inspect manifest
        run: docker buildx imagetools inspect "$(jq -r '.tags[0]' <<< "$DOCKER_METADATA_OUTPUT_JSON")"

  chart:
    runs-on: ubuntu-latest
    needs: merge
    if: startsWith(github.ref, 'refs/tags/v')
    permissions:
      packages: write
    steps:
      - uses: actions/checkout@v5

      - name: Package and push chart
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          ver="${GITHUB_REF_NAME#v}"
          echo "$GH_TOKEN" | helm registry login ghcr.io -u "${{ github.actor }}" --password-stdin
          helm package charts/secret-bunker-operator --version "$ver" --app-version "$ver"
          helm push "secret-bunker-operator-${ver}.tgz" oci://ghcr.io/fables-for-robots/charts
```

- [ ] **Step 2: Validate the YAML parses**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/release.yml'))" && echo OK`
(or `nix shell nixpkgs#actionlint -c actionlint .github/workflows/release.yml` if available — actionlint also catches expression typos)
Expected: OK / no findings. Real end-to-end validation only happens on the first main push after merge (documented in the spec's Testing section).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: release workflow — multi-arch GHCR image + OCI chart publish"
```

---

### Task 7: CI updates — helm job, drift check, e2e-kind rework

**Files:**
- Modify: `.github/workflows/ci.yml` (add `helm` job; rework `e2e-kind` job lines 51-75)

**Interfaces:**
- Consumes: chart from Tasks 3-4; Dockerfile from Task 5; identity Secret shape (name + annotation) from Task 1.
- Produces: nothing downstream; this is the verification harness.

- [ ] **Step 1: Add the helm job**

Insert after the `audit` job in `.github/workflows/ci.yml`:

```yaml
  helm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - name: Lint chart
        run: helm lint charts/secret-bunker-operator

      - name: Render smoke (managed identity, defaults)
        run: |
          helm template test charts/secret-bunker-operator \
            --namespace secret-bunker-system \
            --set bunker.id=5866666666666666666666666666666666666666666666666666666666666666 \
            > /dev/null

      - name: Render smoke (BYO key + metrics + ServiceMonitor)
        run: |
          helm template test charts/secret-bunker-operator \
            --namespace secret-bunker-system \
            --set bunker.id=5866666666666666666666666666666666666666666666666666666666666666 \
            --set identity.existingSecret=my-identity \
            --set metrics.service.enabled=true \
            --set metrics.serviceMonitor.enabled=true \
            > /dev/null

      - name: Chart CRD copy matches operator/deploy/crd.yaml
        run: diff operator/deploy/crd.yaml charts/secret-bunker-operator/crds/bunkersecrets.yaml
```

(The `test` job's existing crdgen drift step keeps checking `operator/deploy/crd.yaml`; this byte-diff transitively covers the chart copy.)

- [ ] **Step 2: Rework the e2e-kind job**

Replace the whole `e2e-kind` job (lines 51-75) with:

```yaml
  e2e-kind:
    # Manual-only heavyweight smoke test: run from the Actions tab.
    if: github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - name: Build operator image
        run: docker build -t secret-bunker-operator:e2e .

      - uses: helm/kind-action@v1

      - name: Load operator image into kind
        run: kind load docker-image secret-bunker-operator:e2e --name chart-testing

      - name: Install chart (managed identity mode)
        run: |
          # No bunker is reachable in this smoke test; any parseable
          # EndpointId works. 0x58 + 31×0x66 is the ed25519 basepoint —
          # a guaranteed-valid public key encoding.
          helm install bunker charts/secret-bunker-operator \
            --namespace secret-bunker-system --create-namespace \
            --set image.repository=secret-bunker-operator \
            --set image.tag=e2e \
            --set image.pullPolicy=Never \
            --set bunker.id=5866666666666666666666666666666666666666666666666666666666666666

      - name: CRD registered
        run: kubectl get crd bunkersecrets.bunker.fables-for-robots.ch

      - name: Operator bootstraps its identity Secret
        run: |
          for i in $(seq 1 60); do
            id=$(kubectl -n secret-bunker-system get secret secret-bunker-operator-identity \
              -o jsonpath='{.metadata.annotations.bunker\.fables-for-robots\.ch/endpoint-id}' \
              2>/dev/null) && [ -n "$id" ] && break
            sleep 2
          done
          echo "operator EndpointId: ${id:-<never appeared>}"
          [[ "$id" =~ ^[0-9a-f]{64}$ ]]

      - name: Pod is running, not crash-looping
        run: |
          kubectl -n secret-bunker-system get pods
          sel='-l app.kubernetes.io/name=secret-bunker-operator'
          phase=$(kubectl -n secret-bunker-system get pods $sel -o jsonpath='{.items[0].status.phase}')
          restarts=$(kubectl -n secret-bunker-system get pods $sel -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')
          [ "$phase" = Running ] && [ "$restarts" = "0" ]
```

- [ ] **Step 3: Validate the YAML parses**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo OK`
Expected: OK.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: helm lint/render job, chart CRD drift check, e2e-kind via docker build + helm install"
```

---

### Task 8: flake.nix cleanup

**Files:**
- Modify: `flake.nix:27-51` (drop `operator-image`; add helm to the dev shell)

**Interfaces:**
- Consumes: nothing. Produces: nothing downstream — the Dockerfile (Task 5) is now the single image definition; nothing in CI references `.#operator-image` after Task 7.

- [ ] **Step 1: Edit flake.nix**

In the devShell packages list (line 23), add `kubernetes-helm`:

```nix
          packages = with pkgs; [ rustc cargo rustfmt clippy rust-analyzer kind kubectl kubernetes-helm ];
```

Replace the packages output (lines 27-51) so only the binary remains:

```nix
      packages = eachSystem (system: pkgs:
        let
          operator = pkgs.rustPlatform.buildRustPackage {
            pname = "secret-bunker-operator";
            version = "0.1.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            buildAndTestSubdir = "operator";
            # Tests run in CI via the cargo-native `test` job; skip them in the
            # nix sandbox, which blocks the real UDP/QUIC socket binds the
            # iroh integration tests need (EPERM under sandbox-exec on Darwin).
            doCheck = false;
          };
        in
        {
          inherit operator;
        });
```

(The container image now comes from the repo-root Dockerfile; the
`operator-image` output and its `isLinux` guard go away.)

- [ ] **Step 2: Verify the flake still evaluates and nothing references the removed output**

```bash
nix flake show 2>&1 | head -20
grep -rn 'operator-image' . --include='*.yml' --include='*.nix' --include='*.md' --exclude-dir=target --exclude-dir=.git
```
Expected: flake shows `packages.<system>.operator` and no `operator-image`; grep hits only historical docs (spec/plan files are fine — they describe the change) — no hits in `.github/` or `flake.nix`.

- [ ] **Step 3: Commit**

```bash
git add flake.nix
git commit -m "nix: drop operator-image (Dockerfile is the single image definition), add helm to dev shell"
```

---

### Task 9: Documentation

**Files:**
- Modify: `operator/README.md` (scope para lines 16-19, identity runbook lines 142-190, configuration table lines 229-238, monitoring lines 304-338, deploying lines 349-371)
- Create: `charts/secret-bunker-operator/README.md`
- Modify: `README.md` (root — add a one-line chart pointer in the operator section)

**Interfaces:**
- Consumes: everything above. Produces: user-facing docs; no code.

- [ ] **Step 1: Update operator/README.md**

1. Scope paragraph (lines 16-19): replace "no Helm chart — plain manifests in `deploy/`" with "installable via the Helm chart in [`../charts/secret-bunker-operator`](../charts/secret-bunker-operator) (published to `oci://ghcr.io/fables-for-robots/charts`) or the plain manifests in [`deploy/`](deploy/)".
2. Insert a new section `## Installing with Helm` immediately before `## Identity provisioning (runbook)`:

```markdown
## Installing with Helm

​```sh
helm install bunker oci://ghcr.io/fables-for-robots/charts/secret-bunker-operator \
  --namespace secret-bunker-system --create-namespace \
  --set bunker.id=<the bunker's 64-char hex EndpointId>
​```

By default the operator manages its own identity: on first boot it generates
an iroh key and stores it in the `secret-bunker-operator-identity` Secret in
the release namespace — restarts and redeployments reuse it, never mint a new
one (deleting that Secret is the explicit "start over with a fresh identity"
action). Grant the new identity read access on the bunker:

​```sh
kubectl -n secret-bunker-system get secret secret-bunker-operator-identity \
  -o jsonpath='{.metadata.annotations.bunker\.fables-for-robots\.ch/endpoint-id}'
bunker add-identity --name k8s-operator --id <EndpointId printed above>
bunker grant --group prod --identity k8s-operator --perms r
​```

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
​```
```

(strip the zero-width markers `​` when writing — they only keep this plan's fences balanced)

3. Retitle `## Identity provisioning (runbook)` to `## Bring-your-own-key provisioning (runbook)` and add one intro sentence: "Only needed with `identity.existingSecret` (or the plain manifests); the Helm default is managed identity, above." Keep steps 1-4 as they are.
4. Configuration table (line 229): change the `--key-file` row's Required column to "one of the two" and add below it:

```markdown
| `--identity-secret` | `BUNKER_IDENTITY_SECRET` | one of the two | — | Name of a Secret in the operator's own namespace holding its identity key; generated and stored there on first boot when missing. Mutually exclusive with `--key-file` |
```

5. Monitoring section (lines 304-338): replace the commented Service+ServiceMonitor YAML block with: "The Helm chart renders both when `metrics.service.enabled` / `metrics.serviceMonitor.enabled` are set. With plain manifests, create the equivalent Service + ServiceMonitor by hand." (keep the section header).
6. Deploying section: unchanged apart from adding at the end: "Or skip all of this with the Helm chart (see [Installing with Helm](#installing-with-helm))."

- [ ] **Step 2: Write the chart README**

`charts/secret-bunker-operator/README.md`:

```markdown
# secret-bunker-operator Helm chart

Installs the [secret-bunker-iroh Kubernetes operator](../../operator/README.md):
syncs bunker secrets into native Kubernetes `Secret`s, push-driven.

​```sh
helm install bunker oci://ghcr.io/fables-for-robots/charts/secret-bunker-operator \
  --namespace secret-bunker-system --create-namespace \
  --set bunker.id=<64-char hex EndpointId>
​```

Images: `ghcr.io/fables-for-robots/secret-bunker-operator` (amd64+arm64).
The chart's `appVersion` pins the image built from the same tag; `image.tag`
overrides.

## Identity

Managed by default: first boot generates an iroh key into
`identity.secretName` (annotation `bunker.fables-for-robots.ch/endpoint-id`
carries the id to grant); restarts reuse it. Set `identity.existingSecret`
for bring-your-own-key (mounted read-only, `--key-file`; nothing generated).
The private key never passes through Helm values in either mode.

## CRD lifecycle

`crds/` installs the `BunkerSecret` CRD on first install. Helm never
upgrades or deletes it (deliberate: uninstall must not cascade-delete your
synced Secrets). Before `helm upgrade`, apply CRD changes manually:

​```sh
kubectl apply -f https://raw.githubusercontent.com/fables-for-robots/secret-bunker-iroh/main/operator/deploy/crd.yaml
​```

## Values

| Key | Default | Meaning |
|---|---|---|
| `bunker.id` | — (required) | EndpointId (64-char hex) of the authoritative bunker |
| `bunker.addrs` | `[]` | Direct `host:port` addrs (repeated `--bunker-addr`); empty → n0 relay/discovery |
| `identity.secretName` | `secret-bunker-operator-identity` | Managed-mode Secret (generated on first boot) |
| `identity.existingSecret` | `""` | Set → BYO-key mode: mount this Secret, pass `--key-file` |
| `identity.secretKey` | `identity.key` | BYO-key mode: item inside `existingSecret` |
| `image.repository` | `ghcr.io/fables-for-robots/secret-bunker-operator` | |
| `image.tag` | `""` (appVersion) | |
| `image.pullPolicy` | `IfNotPresent` | |
| `resyncInterval` | `""` (binary: `1h`) | Level-reconcile backstop |
| `stalenessThreshold` | `""` (binary: `10m`) | Degrade to `StaleReplica` after this |
| `metrics.port` | `8080` | Health + metrics listener port |
| `metrics.service.enabled` | `false` | Render a Service for `/metrics` |
| `metrics.serviceMonitor.enabled` | `false` | Render a ServiceMonitor (needs the Service + Prometheus Operator) |
| `serviceAccount.create` / `rbac.create` | `true` | |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations`, `podLabels`, `priorityClassName`, `imagePullSecrets` | `{}`/`[]`/`""` | Standard pod knobs |

`replicas` is deliberately not a value: one iroh identity, one pod
(`strategy: Recreate`).
​```
```

(again: the `​` markers exist only to nest fences in this plan — write plain ``` in the real file)

- [ ] **Step 3: Root README pointer**

In the root `README.md`, find the section that introduces the operator (search for "operator") and add one sentence: "Install it with Helm: `helm install bunker oci://ghcr.io/fables-for-robots/charts/secret-bunker-operator --set bunker.id=…` — see [`operator/README.md`](operator/README.md)." If no operator section exists, add the sentence to the feature list near the top.

- [ ] **Step 4: Verify docs render + no stale claims**

```bash
grep -n 'no Helm chart' operator/README.md README.md || echo "stale claim gone"
grep -rn 'operator-image' README.md operator/README.md || echo "no stale nix image refs"
```
Expected: both echo lines print.

- [ ] **Step 5: Commit**

```bash
git add operator/README.md charts/secret-bunker-operator/README.md README.md
git commit -m "docs: Helm install path, managed identity flow, chart README"
```

---

### Task 10: Full verification + PR

**Files:** none new.

- [ ] **Step 1: Full local gate (mirror CI exactly)**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p secret-bunker-operator --bin crdgen | diff - operator/deploy/crd.yaml
diff operator/deploy/crd.yaml charts/secret-bunker-operator/crds/bunkersecrets.yaml
helm lint charts/secret-bunker-operator
```
Expected: every command exits 0.

- [ ] **Step 2: Push and open the PR**

```bash
git push -u origin helm-chart
gh pr create --title "Helm chart, GHCR image publishing, managed identity mode" --body "$(cat <<'EOF'
Implements docs/superpowers/specs/2026-08-11-helm-chart-image-publish-design.md.

## What
- **Managed identity mode**: new `--identity-secret` flag — the operator generates its iroh key on first boot and stores it in a k8s Secret (EndpointId in the `bunker.fables-for-robots.ch/endpoint-id` annotation); every later boot reuses it. Present-but-unparsable key material is a hard error, never overwritten. `--key-file` unchanged (mutually exclusive, exactly one required).
- **Helm chart** at `charts/secret-bunker-operator` (managed identity by default, `identity.existingSecret` for BYO-key; CRD via `crds/` so uninstall never cascade-deletes; optional metrics Service/ServiceMonitor; replicas hard-wired to 1).
- **Publishing**: repo-root Dockerfile (rust → distroless/cc, uid 65532); `release.yml` builds linux/amd64+arm64 on native runners, pushes by digest, stitches one manifest — main → `edge`+`sha-…`, tag `vX.Y.Z` → `X.Y.Z`+`latest` + OCI chart push to `oci://ghcr.io/fables-for-robots/charts`.
- CI: helm lint/render job, chart-CRD byte-drift check, e2e-kind now installs the chart from the Dockerfile image and asserts the identity bootstrap. flake.nix drops `operator-image` (Dockerfile is the single image definition).

## Test plan
- [ ] CI: fmt, clippy, workspace tests (incl. 4 new managed-identity tests over the kube mock), crdgen drift, helm lint + two render smokes, chart CRD byte-diff
- [ ] Manual `e2e-kind` dispatch on this branch: chart install in kind, identity Secret bootstrap assertion
- [ ] After merge: first `main` push exercises release.yml (edge images); then tag `v0.1.0` and make both GHCR packages public (manual, once)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Watch CI on the PR and fix anything red**

```bash
gh pr checks --watch
```
Expected: test, audit, helm jobs green. If red: fix, commit, push, re-watch.
