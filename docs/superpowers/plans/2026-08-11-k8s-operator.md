# secret-bunker-operator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `secret-bunker-operator`, a workspace-member crate that syncs bunker
secrets into Kubernetes `Secret`s via an embedded `Replica`, driven by a namespaced
`BunkerSecret` CRD, per the approved spec
`docs/superpowers/specs/2026-08-11-k8s-operator-design.md`.

**Architecture:** One binary, one pod. An embedded
`secret_bunker_iroh::replica::Replica` mirrors granted groups locally and emits push
events; a kube-rs `Controller` on `BunkerSecret` (also watching owned Secrets)
renders one k8s Secret per CR via a pure mapping pipeline; an event bridge converts
`ReplicaEvent`s into targeted reconcile triggers; axum serves
`/healthz` `/readyz` `/metrics`.

**Tech Stack:** Rust edition 2024 (toolchain in devShell: cargo 1.95), kube 4.2.0
(features `runtime, client, derive, unstable-runtime`), k8s-openapi 0.28
(`latest`, `schemars`), schemars 1, prometheus 0.14, axum 0.8, clap 4.6
(derive+env) + humantime 2.4, sha2 0.10 + data-encoding 2 (match root crate),
thiserror 2, futures 0.3, iroh 1, path-dep `secret-bunker-iroh`.

## Global Constraints

- Workspace: root package `secret-bunker-iroh` stays at repo root; new member at `operator/`, package name `secret-bunker-operator`, binary name `operator`, `license = "AGPL-3.0-or-later"`, `edition = "2024"`, `rust-version = "1.91"`.
- All cargo commands run inside the devShell (direnv loads it; plain `cargo` in the repo works). Use `--workspace` for clippy/test.
- CRD identity: group `bunker.fables-for-robots.ch`, version `v1alpha1`, kind `BunkerSecret`, plural default, shortname `bs`, namespaced.
- Constants (defined once in `operator/src/crd.rs`, used everywhere): `FINALIZER = "bunker.fables-for-robots.ch/finalizer"`, `HASH_ANNOTATION = "bunker.fables-for-robots.ch/content-hash"`, `FIELD_MANAGER = "secret-bunker-operator"`.
- Condition reasons (exact strings): `Synced`, `AwaitingSync`, `InvalidKey`, `JsonError`, `MissingSecret`, `MissingGroup`, `AccessRevoked`, `StaleReplica`, `Conflict`.
- Freeze rule: a failed render NEVER touches the existing Secret. Access loss never cascades.
- Change detection: sha256 content hash annotation; never bunker versions.
- k8s Secret keys must match `^[A-Za-z0-9._-]+$`; no silent sanitization — fail the whole render.
- Upstream API facts (verified): `Replica` is NOT `Clone` — share as `Arc<Replica>`; `subscribe()` before first await after `spawn()`; broadcast capacity 1024 → handle `RecvError::Lagged` by reconciling all; `status().last_synced: Option<SystemTime>` is the only initial-sync signal; `get()` returns `anyhow::Result<Zeroizing<Vec<u8>>>`.
- Tests must await convergence with bounded deadlines (30 s style of `tests/e2e.rs`), never sleep-and-hope.
- Commit after every task (conventional style used by this repo: `feat:`, `test:`, `docs:`, `ci:`).
- Per user global instruction: remove any binaries you generate outside `target/` (e.g. ad-hoc scratch builds).

## Interfaces defined by this plan (single source of truth)

```rust
// operator/src/crd.rs
pub const FINALIZER: &str;
pub const HASH_ANNOTATION: &str;
pub const FIELD_MANAGER: &str;
pub struct BunkerSecretSpec { pub target: Option<TargetSpec>, pub deletion_policy: DeletionPolicy, pub data: Vec<DataEntry>, pub data_from: Vec<DataFromEntry> }
pub struct TargetSpec { pub name: Option<String>, pub r#type: Option<String> }
pub enum DeletionPolicy { Retain (default), Delete }
pub struct DataEntry { pub secret_key: String, pub remote_ref: RemoteRef }
pub struct RemoteRef { pub group: String, pub name: String, pub property: Option<String> }
pub enum DataFromEntry { Group(GroupFrom), Extract(ExtractFrom) }   // externally tagged
pub struct GroupFrom { pub name: String, pub rewrite: Vec<Rewrite> }
pub struct Rewrite { pub source: String, pub target: String }
pub struct ExtractFrom { pub group: String, pub name: String }
pub struct BunkerSecretStatus { pub conditions: Vec<Condition>, pub last_sync_time: Option<Time>, pub observed_generation: Option<i64>, pub synced_secret_keys: Vec<String>, pub target_secret_name: Option<String> }
impl BunkerSecret { pub fn target_name(&self) -> String; pub fn referenced_groups(&self) -> BTreeSet<String>; }

// operator/src/render.rs
pub enum SourceError { MissingGroup, MissingSecret, NotYetSynced(String), Other(String) }
pub trait SecretSource { fn list(&self, group: &str) -> Result<Vec<String>, SourceError>; fn get(&self, group: &str, name: &str) -> Result<Vec<u8>, SourceError>; }
pub enum RenderError { MissingGroup { group }, MissingSecret { group, name }, NotYetSynced { group, name, msg }, InvalidKey { keys: Vec<String> }, Json { group, name, msg }, Pointer { group, name, pointer }, NotObject { group, name } }
pub fn render(spec: &BunkerSecretSpec, source: &dyn SecretSource) -> Result<BTreeMap<String, Vec<u8>>, RenderError>;
pub fn valid_key(k: &str) -> bool;
pub fn content_hash(data: &BTreeMap<String, Vec<u8>>) -> String;   // "sha256:<hex>"

// operator/src/secretbuild.rs
pub fn build_secret(cr: &BunkerSecret, data: &BTreeMap<String, Vec<u8>>) -> Secret;

// operator/src/metrics.rs
#[derive(Clone)] pub struct Metrics { pub registry: Registry, pub connected: IntGauge, pub last_sync_ts: IntGauge, pub groups: IntGauge, pub events_total: IntCounterVec, pub reconciles_total: IntCounterVec, pub reconcile_duration: Histogram, pub applies_total: IntCounterVec, pub ready: IntGaugeVec }
impl Metrics { pub fn new() -> anyhow::Result<Metrics>; }

// operator/src/bunker.rs
pub struct ReplicaSource(pub Arc<Replica>);          // impls SecretSource
pub struct Staleness { .. }                          // set_connected(bool), disconnected_for() -> Option<Duration>
pub async fn spawn_replica(id: &str, addrs: &[SocketAddr], key_file: &Path, mirror_path: &Path) -> anyhow::Result<Replica>;

// operator/src/events.rs
pub fn spawn_event_bridge(rx: broadcast::Receiver<ReplicaEvent>, crs: Box<dyn Fn() -> Vec<Arc<BunkerSecret>> + Send>, staleness: Arc<Staleness>, threshold: Duration, metrics: Metrics) -> impl futures::Stream<Item = ObjectRef<BunkerSecret>>;

// operator/src/reconcile.rs
pub struct Context { pub client: Client, pub source: ReplicaSource, pub replica: Arc<Replica>, pub metrics: Metrics, pub staleness: Arc<Staleness>, pub recorder: kube::runtime::events::Recorder, pub resync: Duration, pub staleness_threshold: Duration }
pub enum Error { Kube(kube::Error), Finalizer(Box<finalizer::Error<Error>>), Transient(String) }   // thiserror
pub async fn reconcile(cr: Arc<BunkerSecret>, ctx: Arc<Context>) -> Result<Action, Error>;
pub fn error_policy(cr: Arc<BunkerSecret>, err: &Error, ctx: Arc<Context>) -> Action;
pub async fn apply_bunker_secret(cr: &BunkerSecret, ctx: &Context) -> Result<Action, Error>;   // tested directly
pub async fn cleanup_bunker_secret(cr: &BunkerSecret, ctx: &Context) -> Result<Action, Error>; // tested directly

// operator/src/http.rs
pub struct AppState { pub metrics: Metrics, pub replica: Arc<Replica> }
pub fn router(state: Arc<AppState>) -> axum::Router;
```

---

### Task 1: Workspace conversion + operator crate skeleton + CI

**Files:**
- Modify: `Cargo.toml` (repo root — add `[workspace]`)
- Create: `operator/Cargo.toml`, `operator/src/main.rs`
- Modify: `.github/workflows/ci.yml` (add `--workspace` to clippy and test)

**Interfaces:**
- Consumes: nothing.
- Produces: a compiling workspace where `cargo test --workspace` runs root + operator crates.

- [ ] **Step 1: Add the workspace section to the root Cargo.toml**

Insert after the `[package]` block (root package is an implicit member — do NOT list `"."`):

```toml
[workspace]
members = ["operator"]
resolver = "3"
```

- [ ] **Step 2: Create operator/Cargo.toml with the full dependency set**

```toml
[package]
name = "secret-bunker-operator"
version = "0.1.0"
edition = "2024"
rust-version = "1.91"
license = "AGPL-3.0-or-later"

[[bin]]
name = "operator"
path = "src/main.rs"

[[bin]]
name = "crdgen"
path = "src/bin/crdgen.rs"

[dependencies]
secret-bunker-iroh = { path = ".." }
anyhow = "1"
axum = "0.8"
clap = { version = "4", features = ["derive", "env"] }
data-encoding = "2"
futures = "0.3"
humantime = "2.4"
iroh = "1"
k8s-openapi = { version = "0.28", features = ["latest", "schemars"] }
kube = { version = "4.2", features = ["runtime", "client", "derive", "unstable-runtime"] }
prometheus = "0.14"
schemars = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
sha2 = "0.10"
thiserror = "2"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal", "sync", "time"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
zeroize = "1"

[dev-dependencies]
age = "0.11"
http = "1"
tempfile = "3"
tower-test = "0.4"
```

- [ ] **Step 3: Create operator/src/main.rs stub**

```rust
fn main() {
    println!("secret-bunker-operator");
}
```

Also create `operator/src/bin/crdgen.rs` stub (filled in Task 2):

```rust
fn main() {}
```

- [ ] **Step 4: Verify the workspace builds and both crates test**

Run: `cargo test --workspace`
Expected: root crate's full suite passes; operator crate compiles with 0 tests. First build is slow (kube dep tree).

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 5: Update CI for the workspace**

In `.github/workflows/ci.yml` change the two lines:

```yaml
      - name: Clippy
        run: cargo clippy --workspace --all-targets -- -D warnings
```

```yaml
      - name: Tests (unit + end-to-end over in-process iroh endpoints)
        run: cargo test --workspace
```

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock operator .github/workflows/ci.yml
git commit -m "feat: workspace + secret-bunker-operator crate skeleton"
```

---

### Task 2: CRD types + crdgen

**Files:**
- Create: `operator/src/crd.rs`, `operator/src/lib.rs`
- Modify: `operator/src/bin/crdgen.rs`
- Test: unit tests in `operator/src/crd.rs`

**Interfaces:**
- Consumes: kube derive, k8s-openapi `Condition`/`Time` (JsonSchema via the `schemars` feature).
- Produces: `BunkerSecret`, `BunkerSecretSpec`, `BunkerSecretStatus`, `DeletionPolicy`, `DataEntry`, `RemoteRef`, `DataFromEntry`, `GroupFrom`, `ExtractFrom`, `Rewrite`, `TargetSpec`, constants `FINALIZER`/`HASH_ANNOTATION`/`FIELD_MANAGER`, helpers `target_name()`, `referenced_groups()`.

- [ ] **Step 1: Create operator/src/lib.rs**

```rust
pub mod crd;
```

(Modules are added here as later tasks create them: `render`, `secretbuild`, `metrics`, `bunker`, `events`, `reconcile`, `http`. `main.rs` will use the lib crate: `use secret_bunker_operator::...`.)

- [ ] **Step 2: Write failing unit tests in crd.rs (bottom of file)**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The spec's example YAML must deserialize exactly.
    #[test]
    fn spec_yaml_round_trip() {
        let yaml = r#"
target:
  name: app-secrets
  type: Opaque
deletionPolicy: Delete
data:
  - secretKey: DB_PASSWORD
    remoteRef:
      group: prod
      name: db-password
  - secretKey: SMTP_PASS
    remoteRef:
      group: prod
      name: mailer-config
      property: /smtp/password
dataFrom:
  - group:
      name: prod
      rewrite:
        - source: db-password
          target: DB_PASSWORD
  - extract:
      group: prod
      name: config-json
"#;
        let spec: BunkerSecretSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.deletion_policy, DeletionPolicy::Delete);
        assert_eq!(spec.data[1].remote_ref.property.as_deref(), Some("/smtp/password"));
        match &spec.data_from[0] {
            DataFromEntry::Group(g) => {
                assert_eq!(g.name, "prod");
                assert_eq!(g.rewrite[0].target, "DB_PASSWORD");
            }
            other => panic!("expected group entry, got {other:?}"),
        }
        match &spec.data_from[1] {
            DataFromEntry::Extract(e) => assert_eq!(e.name, "config-json"),
            other => panic!("expected extract entry, got {other:?}"),
        }
    }

    #[test]
    fn defaults_are_retain_and_empty() {
        let spec: BunkerSecretSpec = serde_yaml::from_str("{}").unwrap();
        assert_eq!(spec.deletion_policy, DeletionPolicy::Retain);
        assert!(spec.data.is_empty() && spec.data_from.is_empty() && spec.target.is_none());
    }

    #[test]
    fn target_name_defaults_to_cr_name() {
        let mut cr = BunkerSecret::new("my-cr", BunkerSecretSpec::default());
        assert_eq!(cr.target_name(), "my-cr");
        cr.spec.target = Some(TargetSpec { name: Some("other".into()), r#type: None });
        assert_eq!(cr.target_name(), "other");
    }

    #[test]
    fn referenced_groups_covers_data_and_data_from() {
        let yaml = r#"
data:
  - secretKey: A
    remoteRef: { group: g1, name: a }
dataFrom:
  - group: { name: g2 }
  - extract: { group: g3, name: j }
"#;
        let spec: BunkerSecretSpec = serde_yaml::from_str(yaml).unwrap();
        let cr = BunkerSecret::new("x", spec);
        let groups: Vec<_> = cr.referenced_groups().into_iter().collect();
        assert_eq!(groups, vec!["g1".to_string(), "g2".into(), "g3".into()]);
    }

    #[test]
    fn crd_yaml_has_expected_identity() {
        use kube::CustomResourceExt;
        let crd = BunkerSecret::crd();
        let yaml = serde_yaml::to_string(&crd).unwrap();
        assert!(yaml.contains("group: bunker.fables-for-robots.ch"));
        assert!(yaml.contains("kind: BunkerSecret"));
        assert!(yaml.contains("bs"));
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p secret-bunker-operator`
Expected: compile error — types not defined.

- [ ] **Step 4: Implement crd.rs**

```rust
//! The BunkerSecret CRD: one CR renders exactly one Kubernetes Secret from
//! bunker groups the operator's identity can read.

use std::collections::BTreeSet;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const FINALIZER: &str = "bunker.fables-for-robots.ch/finalizer";
pub const HASH_ANNOTATION: &str = "bunker.fables-for-robots.ch/content-hash";
pub const FIELD_MANAGER: &str = "secret-bunker-operator";

#[derive(CustomResource, Serialize, Deserialize, Debug, Default, Clone, PartialEq, JsonSchema)]
#[kube(
    group = "bunker.fables-for-robots.ch",
    version = "v1alpha1",
    kind = "BunkerSecret",
    namespaced,
    status = "BunkerSecretStatus",
    shortname = "bs",
    doc = "Syncs secrets from a secret-bunker into one Kubernetes Secret",
    printcolumn(name = "Target", type_ = "string", json_path = ".spec.target.name"),
    printcolumn(name = "LastSync", type_ = "date", json_path = ".status.lastSyncTime")
)]
#[serde(rename_all = "camelCase")]
pub struct BunkerSecretSpec {
    /// Target Secret; name defaults to the CR name, type to Opaque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSpec>,
    /// What happens to the Secret when this CR is deleted.
    #[serde(default)]
    pub deletion_policy: DeletionPolicy,
    /// Explicit per-key mappings; highest precedence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data: Vec<DataEntry>,
    /// Bulk mappings, applied in list order before `data`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_from: Vec<DataFromEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TargetSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy, PartialEq, Eq, JsonSchema)]
pub enum DeletionPolicy {
    #[default]
    Retain,
    Delete,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DataEntry {
    pub secret_key: String,
    pub remote_ref: RemoteRef,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RemoteRef {
    pub group: String,
    pub name: String,
    /// RFC 6901 JSON Pointer into a JSON-valued secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DataFromEntry {
    /// Whole-group fan-out: each bunker secret name becomes a key.
    Group(GroupFrom),
    /// Explode one JSON-object-valued bunker secret into keys.
    Extract(ExtractFrom),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupFrom {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewrite: Vec<Rewrite>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Rewrite {
    pub source: String,
    pub target: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExtractFrom {
    pub group: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BunkerSecretStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_time: Option<Time>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub synced_secret_keys: Vec<String>,
    /// Name of the Secret last applied — used to clean up on target rename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_secret_name: Option<String>,
}

impl BunkerSecret {
    /// The k8s Secret name this CR renders to.
    pub fn target_name(&self) -> String {
        self.spec
            .target
            .as_ref()
            .and_then(|t| t.name.clone())
            .unwrap_or_else(|| self.metadata.name.clone().unwrap_or_default())
    }

    /// Every bunker group this CR reads from.
    pub fn referenced_groups(&self) -> BTreeSet<String> {
        let mut groups = BTreeSet::new();
        for d in &self.spec.data {
            groups.insert(d.remote_ref.group.clone());
        }
        for df in &self.spec.data_from {
            match df {
                DataFromEntry::Group(g) => groups.insert(g.name.clone()),
                DataFromEntry::Extract(e) => groups.insert(e.group.clone()),
            };
        }
        groups
    }
}
```

If `Condition`/`Time` fail to satisfy `JsonSchema` despite the k8s-openapi
`schemars` feature (compile error in the derive), fall back to defining a local
`Condition` struct with fields `type_ (rename "type"), status, reason, message,
last_transition_time: Option<Time>, observed_generation: Option<i64>` and a local
`Time` newtype over String — keep field names identical so later tasks compile
unchanged. Do NOT silently drop status fields.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p secret-bunker-operator`
Expected: 5 tests pass.

- [ ] **Step 6: Implement crdgen and generate the CRD manifest**

`operator/src/bin/crdgen.rs`:

```rust
use kube::CustomResourceExt;

fn main() {
    print!(
        "{}",
        serde_yaml::to_string(&secret_bunker_operator::crd::BunkerSecret::crd()).unwrap()
    );
}
```

Run: `mkdir -p operator/deploy && cargo run -p secret-bunker-operator --bin crdgen > operator/deploy/crd.yaml`
Expected: `operator/deploy/crd.yaml` contains `kind: CustomResourceDefinition`, `name: bunkersecrets.bunker.fables-for-robots.ch`.

- [ ] **Step 7: Commit**

```bash
git add operator/src operator/deploy/crd.yaml
git commit -m "feat: BunkerSecret CRD types + crdgen"
```

---

### Task 3: Render pipeline

**Files:**
- Create: `operator/src/render.rs`; add `pub mod render;` to `operator/src/lib.rs`
- Test: unit tests in `operator/src/render.rs`

**Interfaces:**
- Consumes: `crd::{BunkerSecretSpec, DataFromEntry}`.
- Produces: `SecretSource` trait, `SourceError`, `RenderError`, `render()`, `valid_key()`, `content_hash()` — exact signatures from the interfaces block at the top of this plan.

- [ ] **Step 1: Write the failing tests (bottom of render.rs)**

The fixture source is a `BTreeMap<(String, String), Vec<u8>>`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Fixture(BTreeMap<(String, String), Vec<u8>>);

    impl Fixture {
        fn new(entries: &[(&str, &str, &[u8])]) -> Self {
            Fixture(
                entries
                    .iter()
                    .map(|(g, n, v)| ((g.to_string(), n.to_string()), v.to_vec()))
                    .collect(),
            )
        }
    }

    impl SecretSource for Fixture {
        fn list(&self, group: &str) -> Result<Vec<String>, SourceError> {
            let names: Vec<String> = self
                .0
                .keys()
                .filter(|(g, _)| g == group)
                .map(|(_, n)| n.clone())
                .collect();
            if names.is_empty() {
                return Err(SourceError::MissingGroup);
            }
            Ok(names)
        }
        fn get(&self, group: &str, name: &str) -> Result<Vec<u8>, SourceError> {
            if !self.0.keys().any(|(g, _)| g == group) {
                return Err(SourceError::MissingGroup);
            }
            self.0
                .get(&(group.to_string(), name.to_string()))
                .cloned()
                .ok_or(SourceError::MissingSecret)
        }
    }

    fn spec(yaml: &str) -> crate::crd::BunkerSecretSpec {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn data_verbatim_bytes() {
        let src = Fixture::new(&[("g", "pw", b"hunter2\xff")]); // binary-safe
        let out = render(
            &spec("data: [{secretKey: PW, remoteRef: {group: g, name: pw}}]"),
            &src,
        )
        .unwrap();
        assert_eq!(out["PW"], b"hunter2\xff".to_vec());
    }

    #[test]
    fn property_extracts_json_string_as_raw_bytes() {
        let src = Fixture::new(&[("g", "cfg", br#"{"smtp":{"password":"s3cr3t"}}"#)]);
        let out = render(
            &spec("data: [{secretKey: P, remoteRef: {group: g, name: cfg, property: /smtp/password}}]"),
            &src,
        )
        .unwrap();
        assert_eq!(out["P"], b"s3cr3t".to_vec());
    }

    #[test]
    fn property_reserializes_non_string_compactly() {
        let src = Fixture::new(&[("g", "cfg", br#"{"port": 25, "hosts": ["a","b"]}"#)]);
        let out = render(
            &spec("data: [{secretKey: H, remoteRef: {group: g, name: cfg, property: /hosts}}]"),
            &src,
        )
        .unwrap();
        assert_eq!(out["H"], br#"["a","b"]"#.to_vec());
    }

    #[test]
    fn property_miss_is_pointer_error() {
        let src = Fixture::new(&[("g", "cfg", br#"{"a":1}"#)]);
        let err = render(
            &spec("data: [{secretKey: X, remoteRef: {group: g, name: cfg, property: /nope}}]"),
            &src,
        )
        .unwrap_err();
        assert!(matches!(err, RenderError::Pointer { .. }));
    }

    #[test]
    fn property_on_non_json_is_json_error() {
        let src = Fixture::new(&[("g", "blob", b"\xff\xfe not json")]);
        let err = render(
            &spec("data: [{secretKey: X, remoteRef: {group: g, name: blob, property: /a}}]"),
            &src,
        )
        .unwrap_err();
        assert!(matches!(err, RenderError::Json { .. }));
    }

    #[test]
    fn extract_fans_out_object_keys() {
        let src = Fixture::new(&[("g", "cfg", br#"{"user":"u","port":25}"#)]);
        let out = render(&spec("dataFrom: [{extract: {group: g, name: cfg}}]"), &src).unwrap();
        assert_eq!(out["user"], b"u".to_vec());
        assert_eq!(out["port"], b"25".to_vec());
    }

    #[test]
    fn extract_non_object_is_not_object_error() {
        let src = Fixture::new(&[("g", "cfg", br#"[1,2]"#)]);
        let err = render(&spec("dataFrom: [{extract: {group: g, name: cfg}}]"), &src).unwrap_err();
        assert!(matches!(err, RenderError::NotObject { .. }));
    }

    #[test]
    fn group_fan_out_with_rewrite() {
        let src = Fixture::new(&[("g", "db-password", b"pw"), ("g", "api_key", b"k")]);
        let out = render(
            &spec("dataFrom: [{group: {name: g, rewrite: [{source: db-password, target: DB_PASSWORD}]}}]"),
            &src,
        )
        .unwrap();
        assert_eq!(out["DB_PASSWORD"], b"pw".to_vec());
        assert_eq!(out["api_key"], b"k".to_vec());
        assert!(!out.contains_key("db-password"));
    }

    #[test]
    fn precedence_later_data_from_wins_then_data_overrides() {
        let src = Fixture::new(&[
            ("g1", "k", b"from-g1"),
            ("g2", "k", b"from-g2"),
            ("g3", "explicit", b"from-data"),
        ]);
        let out = render(
            &spec(
                "dataFrom: [{group: {name: g1}}, {group: {name: g2}}]\n\
                 data: [{secretKey: k, remoteRef: {group: g3, name: explicit}}]",
            ),
            &src,
        )
        .unwrap();
        // g2 overwrote g1; data overrode both.
        assert_eq!(out["k"], b"from-data".to_vec());
    }

    #[test]
    fn invalid_keys_fail_whole_render_listing_offenders() {
        let src = Fixture::new(&[("g", "bad/name", b"v"), ("g", "ok", b"v")]);
        let err = render(&spec("dataFrom: [{group: {name: g}}]"), &src).unwrap_err();
        match err {
            RenderError::InvalidKey { keys } => assert_eq!(keys, vec!["bad/name".to_string()]),
            other => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[test]
    fn missing_group_and_secret_errors() {
        let src = Fixture::new(&[("g", "a", b"v")]);
        assert!(matches!(
            render(&spec("dataFrom: [{group: {name: nope}}]"), &src).unwrap_err(),
            RenderError::MissingGroup { .. }
        ));
        assert!(matches!(
            render(&spec("data: [{secretKey: X, remoteRef: {group: g, name: nope}}]"), &src).unwrap_err(),
            RenderError::MissingSecret { .. }
        ));
    }

    #[test]
    fn content_hash_is_stable_and_order_independent() {
        let mut a = BTreeMap::new();
        a.insert("x".to_string(), b"1".to_vec());
        a.insert("y".to_string(), b"2".to_vec());
        let h1 = content_hash(&a);
        assert!(h1.starts_with("sha256:"));
        // Same logical content, different insertion order → same hash (BTreeMap sorts).
        let mut b = BTreeMap::new();
        b.insert("y".to_string(), b"2".to_vec());
        b.insert("x".to_string(), b"1".to_vec());
        assert_eq!(h1, content_hash(&b));
        // Key/value boundary ambiguity must matter: ("ab","c") != ("a","bc").
        let mut c = BTreeMap::new();
        c.insert("ab".to_string(), b"c".to_vec());
        let mut d = BTreeMap::new();
        d.insert("a".to_string(), b"bc".to_vec());
        assert_ne!(content_hash(&c), content_hash(&d));
    }

    #[test]
    fn valid_key_charset() {
        assert!(valid_key("a-b_c.D9"));
        assert!(!valid_key("a/b"));
        assert!(!valid_key(""));
        assert!(!valid_key("a b"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-bunker-operator render`
Expected: compile error — module not implemented.

- [ ] **Step 3: Implement render.rs**

```rust
//! Pure mapping pipeline: bunker bytes in, k8s Secret data map out.
//! No kube types, no replica handle — everything here is unit-testable.

use std::collections::BTreeMap;

use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

use crate::crd::{BunkerSecretSpec, DataFromEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    MissingGroup,
    MissingSecret,
    /// Mirror has the entry but cannot serve it yet (DEK wrap race) — retryable.
    NotYetSynced(String),
    Other(String),
}

pub trait SecretSource {
    fn list(&self, group: &str) -> Result<Vec<String>, SourceError>;
    fn get(&self, group: &str, name: &str) -> Result<Vec<u8>, SourceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    MissingGroup { group: String },
    MissingSecret { group: String, name: String },
    NotYetSynced { group: String, name: String, msg: String },
    InvalidKey { keys: Vec<String> },
    Json { group: String, name: String, msg: String },
    Pointer { group: String, name: String, pointer: String },
    NotObject { group: String, name: String },
}

pub fn valid_key(k: &str) -> bool {
    !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// "sha256:<hex>" over length-prefixed sorted (key, value) pairs.
pub fn content_hash(data: &BTreeMap<String, Vec<u8>>) -> String {
    let mut h = Sha256::new();
    for (k, v) in data {
        h.update((k.len() as u64).to_le_bytes());
        h.update(k.as_bytes());
        h.update((v.len() as u64).to_le_bytes());
        h.update(v);
    }
    format!("sha256:{}", HEXLOWER.encode(&h.finalize()))
}

fn source_err(e: SourceError, group: &str, name: &str) -> RenderError {
    match e {
        SourceError::MissingGroup => RenderError::MissingGroup { group: group.into() },
        SourceError::MissingSecret => RenderError::MissingSecret { group: group.into(), name: name.into() },
        SourceError::NotYetSynced(msg) => RenderError::NotYetSynced { group: group.into(), name: name.into(), msg },
        SourceError::Other(msg) => RenderError::NotYetSynced { group: group.into(), name: name.into(), msg },
    }
}

fn parse_json(group: &str, name: &str, bytes: &[u8]) -> Result<serde_json::Value, RenderError> {
    serde_json::from_slice(bytes).map_err(|e| RenderError::Json {
        group: group.into(),
        name: name.into(),
        msg: e.to_string(),
    })
}

/// A resolved JSON string becomes raw UTF-8 bytes; any other value is compact JSON.
fn json_value_bytes(v: &serde_json::Value) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.clone().into_bytes(),
        other => other.to_string().into_bytes(),
    }
}

pub fn render(
    spec: &BunkerSecretSpec,
    source: &dyn SecretSource,
) -> Result<BTreeMap<String, Vec<u8>>, RenderError> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut invalid: Vec<String> = Vec::new();

    // 1. dataFrom, in list order; later entries overwrite earlier on collision.
    for entry in &spec.data_from {
        match entry {
            DataFromEntry::Group(g) => {
                let names = source.list(&g.name).map_err(|e| source_err(e, &g.name, ""))?;
                for name in names {
                    let value = source.get(&g.name, &name).map_err(|e| source_err(e, &g.name, &name))?;
                    let key = g
                        .rewrite
                        .iter()
                        .find(|r| r.source == name)
                        .map(|r| r.target.clone())
                        .unwrap_or_else(|| name.clone());
                    if !valid_key(&key) {
                        invalid.push(key);
                        continue;
                    }
                    out.insert(key, value);
                }
            }
            DataFromEntry::Extract(e) => {
                let value = source.get(&e.group, &e.name).map_err(|err| source_err(err, &e.group, &e.name))?;
                let json = parse_json(&e.group, &e.name, &value)?;
                let obj = json.as_object().ok_or_else(|| RenderError::NotObject {
                    group: e.group.clone(),
                    name: e.name.clone(),
                })?;
                for (k, v) in obj {
                    if !valid_key(k) {
                        invalid.push(k.clone());
                        continue;
                    }
                    out.insert(k.clone(), json_value_bytes(v));
                }
            }
        }
    }

    // 2. data, always wins.
    for d in &spec.data {
        let r = &d.remote_ref;
        let value = source.get(&r.group, &r.name).map_err(|e| source_err(e, &r.group, &r.name))?;
        let bytes = match &r.property {
            None => value,
            Some(pointer) => {
                let json = parse_json(&r.group, &r.name, &value)?;
                let v = json.pointer(pointer).ok_or_else(|| RenderError::Pointer {
                    group: r.group.clone(),
                    name: r.name.clone(),
                    pointer: pointer.clone(),
                })?;
                json_value_bytes(v)
            }
        };
        if !valid_key(&d.secret_key) {
            invalid.push(d.secret_key.clone());
            continue;
        }
        out.insert(d.secret_key.clone(), bytes);
    }

    if !invalid.is_empty() {
        invalid.sort();
        invalid.dedup();
        return Err(RenderError::InvalidKey { keys: invalid });
    }
    Ok(out)
}
```

Add `pub mod render;` to `operator/src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p secret-bunker-operator render`
Expected: all 13 tests pass.

- [ ] **Step 5: Commit**

```bash
git add operator/src
git commit -m "feat: pure render pipeline (data/dataFrom, JSON pointer, fan-out, hash)"
```

---

### Task 4: Secret construction

**Files:**
- Create: `operator/src/secretbuild.rs`; add `pub mod secretbuild;` to lib.rs
- Test: unit tests in `operator/src/secretbuild.rs`

**Interfaces:**
- Consumes: `crd::{BunkerSecret, HASH_ANNOTATION}`, `render::content_hash`.
- Produces: `pub fn build_secret(cr: &BunkerSecret, data: &BTreeMap<String, Vec<u8>>) -> Secret` (k8s_openapi Secret with name/namespace/labels/hash annotation/ownerReference/type/data).

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{BunkerSecret, BunkerSecretSpec, HASH_ANNOTATION, TargetSpec};
    use std::collections::BTreeMap;

    fn cr() -> BunkerSecret {
        let mut cr = BunkerSecret::new("app", BunkerSecretSpec::default());
        cr.metadata.namespace = Some("prod".into());
        cr.metadata.uid = Some("uid-123".into());
        cr
    }

    #[test]
    fn secret_has_identity_owner_and_hash() {
        let mut data = BTreeMap::new();
        data.insert("K".to_string(), b"v".to_vec());
        let s = build_secret(&cr(), &data);
        assert_eq!(s.metadata.name.as_deref(), Some("app"));
        assert_eq!(s.metadata.namespace.as_deref(), Some("prod"));
        let owner = &s.metadata.owner_references.as_ref().unwrap()[0];
        assert_eq!(owner.kind, "BunkerSecret");
        assert_eq!(owner.uid, "uid-123");
        assert_eq!(owner.controller, Some(true));
        let hash = &s.metadata.annotations.as_ref().unwrap()[HASH_ANNOTATION];
        assert!(hash.starts_with("sha256:"));
        assert_eq!(s.type_.as_deref(), Some("Opaque"));
        assert_eq!(s.data.as_ref().unwrap()["K"].0, b"v".to_vec());
    }

    #[test]
    fn target_overrides_name_and_type() {
        let mut c = cr();
        c.spec.target = Some(TargetSpec {
            name: Some("renamed".into()),
            r#type: Some("kubernetes.io/dockerconfigjson".into()),
        });
        let s = build_secret(&c, &BTreeMap::new());
        assert_eq!(s.metadata.name.as_deref(), Some("renamed"));
        assert_eq!(s.type_.as_deref(), Some("kubernetes.io/dockerconfigjson"));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p secret-bunker-operator secretbuild`
Expected: compile error.

- [ ] **Step 3: Implement**

```rust
//! Builds the desired k8s Secret object for a BunkerSecret CR.

use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Resource;

use crate::crd::{BunkerSecret, HASH_ANNOTATION};
use crate::render::content_hash;

pub fn build_secret(cr: &BunkerSecret, data: &BTreeMap<String, Vec<u8>>) -> Secret {
    let annotations = BTreeMap::from([(HASH_ANNOTATION.to_string(), content_hash(data))]);
    let labels = BTreeMap::from([(
        "app.kubernetes.io/managed-by".to_string(),
        "secret-bunker-operator".to_string(),
    )]);
    Secret {
        metadata: ObjectMeta {
            name: Some(cr.target_name()),
            namespace: cr.metadata.namespace.clone(),
            annotations: Some(annotations),
            labels: Some(labels),
            owner_references: Some(vec![cr.controller_owner_ref(&()).expect("CR has name+uid")]),
            ..Default::default()
        },
        type_: Some(
            cr.spec
                .target
                .as_ref()
                .and_then(|t| t.r#type.clone())
                .unwrap_or_else(|| "Opaque".to_string()),
        ),
        data: Some(data.iter().map(|(k, v)| (k.clone(), ByteString(v.clone()))).collect()),
        ..Default::default()
    }
}
```

- [ ] **Step 4: Run tests, expect pass; clippy clean**

Run: `cargo test -p secret-bunker-operator secretbuild && cargo clippy -p secret-bunker-operator --all-targets -- -D warnings`

- [ ] **Step 5: Commit**

```bash
git add operator/src
git commit -m "feat: desired-Secret builder with owner ref + content hash"
```

---

### Task 5: Metrics + HTTP server

**Files:**
- Create: `operator/src/metrics.rs`, `operator/src/http.rs`; register both in lib.rs
- Test: unit tests in `operator/src/metrics.rs` (registry contents); `operator/src/http.rs` handlers get an integration test later (Task 8 harness has a live replica; `/readyz` logic is a one-liner reading `status()`)

**Interfaces:**
- Consumes: nothing internal.
- Produces: `Metrics` (fields exactly as in the interfaces block; metric names below), `AppState { metrics, replica }`, `router(state)`.

Metric names (spec, verbatim): `bunker_replica_connected`, `bunker_replica_last_sync_timestamp_seconds`, `bunker_replica_groups`, `bunker_replica_events_total{type}`, `bunker_secret_reconciles_total{result}`, `bunker_secret_reconcile_duration_seconds`, `bunker_secret_applies_total{outcome}`, `bunker_secret_ready{namespace,name}`.

- [ ] **Step 1: Write failing test in metrics.rs**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Encoder;

    #[test]
    fn all_metrics_register_and_render() {
        let m = Metrics::new().unwrap();
        m.connected.set(1);
        m.events_total.with_label_values(&["secret_changed"]).inc();
        m.reconciles_total.with_label_values(&["success"]).inc();
        m.reconcile_duration.observe(0.05);
        m.applies_total.with_label_values(&["applied"]).inc();
        m.ready.with_label_values(&["ns", "name"]).set(1);
        let mut buf = Vec::new();
        prometheus::TextEncoder::new().encode(&m.registry.gather(), &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        for name in [
            "bunker_replica_connected",
            "bunker_replica_last_sync_timestamp_seconds",
            "bunker_replica_groups",
            "bunker_replica_events_total",
            "bunker_secret_reconciles_total",
            "bunker_secret_reconcile_duration_seconds",
            "bunker_secret_applies_total",
            "bunker_secret_ready",
        ] {
            assert!(text.contains(name), "missing {name} in:\n{text}");
        }
    }
}
```

- [ ] **Step 2: Run to verify failure, then implement metrics.rs**

```rust
//! Prometheus metrics per the spec's observability section.

use prometheus::{
    Histogram, HistogramOpts, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub connected: IntGauge,
    pub last_sync_ts: IntGauge,
    pub groups: IntGauge,
    pub events_total: IntCounterVec,
    pub reconciles_total: IntCounterVec,
    pub reconcile_duration: Histogram,
    pub applies_total: IntCounterVec,
    pub ready: IntGaugeVec,
}

impl Metrics {
    pub fn new() -> anyhow::Result<Metrics> {
        let registry = Registry::new();
        let connected = IntGauge::new("bunker_replica_connected", "1 when the sync session to the authoritative bunker is up")?;
        let last_sync_ts = IntGauge::new("bunker_replica_last_sync_timestamp_seconds", "Unix time of the last completed sync; 0 before the first")?;
        let groups = IntGauge::new("bunker_replica_groups", "Groups currently in the local mirror")?;
        let events_total = IntCounterVec::new(Opts::new("bunker_replica_events_total", "Replica events seen, by type"), &["type"])?;
        let reconciles_total = IntCounterVec::new(Opts::new("bunker_secret_reconciles_total", "Reconcile outcomes"), &["result"])?;
        let reconcile_duration = Histogram::with_opts(HistogramOpts::new("bunker_secret_reconcile_duration_seconds", "Reconcile duration").buckets(vec![0.001, 0.01, 0.1, 0.5, 2.0, 10.0]))?;
        let applies_total = IntCounterVec::new(Opts::new("bunker_secret_applies_total", "Secret writes vs hash-skips"), &["outcome"])?;
        let ready = IntGaugeVec::new(Opts::new("bunker_secret_ready", "1 when the BunkerSecret's Ready condition is True"), &["namespace", "name"])?;
        for c in [
            Box::new(connected.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(last_sync_ts.clone()),
            Box::new(groups.clone()),
            Box::new(events_total.clone()),
            Box::new(reconciles_total.clone()),
            Box::new(reconcile_duration.clone()),
            Box::new(applies_total.clone()),
            Box::new(ready.clone()),
        ] {
            registry.register(c)?;
        }
        Ok(Metrics { registry, connected, last_sync_ts, groups, events_total, reconciles_total, reconcile_duration, applies_total, ready })
    }
}
```

Run: `cargo test -p secret-bunker-operator metrics` — expect pass.

- [ ] **Step 3: Implement http.rs**

```rust
//! /healthz (liveness), /readyz (initial sync complete), /metrics.

use std::sync::Arc;

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use prometheus::Encoder;
use secret_bunker_iroh::replica::Replica;

use crate::metrics::Metrics;

pub struct AppState {
    pub metrics: Metrics,
    pub replica: Arc<Replica>,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn readyz(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // Connected fires before the manifest applies; last_synced is the only
    // trustworthy initial-sync-complete signal.
    if s.replica.status().last_synced.is_some() {
        (StatusCode::OK, "synced")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "awaiting first sync")
    }
}

async fn metrics(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let mut buf = Vec::new();
    let encoder = prometheus::TextEncoder::new();
    if encoder.encode(&s.metrics.registry.gather(), &mut buf).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, String::new()).into_response();
    }
    ([("content-type", "text/plain; version=0.0.4")], buf).into_response()
}
```

- [ ] **Step 4: Verify build + clippy**

Run: `cargo clippy -p secret-bunker-operator --all-targets -- -D warnings && cargo test -p secret-bunker-operator`
Expected: clean, all previous tests still pass.

- [ ] **Step 5: Commit**

```bash
git add operator/src
git commit -m "feat: prometheus metrics + health/readiness/metrics endpoints"
```

---

### Task 6: Replica integration — spawn, SecretSource, Staleness

**Files:**
- Create: `operator/src/bunker.rs`; add `pub mod bunker;` to lib.rs
- Create: `operator/tests/common/mod.rs` (in-process bunker harness, reused by Task 8)
- Test: `operator/tests/replica_source.rs`

**Interfaces:**
- Consumes: `secret_bunker_iroh::{replica::Replica, keys}`, `render::{SecretSource, SourceError}`.
- Produces: `ReplicaSource(pub Arc<Replica>)` implementing `SecretSource`; `Staleness::new()`, `set_connected(bool)`, `disconnected_for() -> Option<Duration>`; `spawn_replica(id, addrs, key_file, mirror_path)`.
- The test harness `common::TestBunker` with `spawn().await`, `put/grant/create_group/add_identity/delete` helpers and `replica_for(secret) -> (Replica, Receiver<ReplicaEvent>)` — later tasks import it.

- [ ] **Step 1: Write the shared test harness (operator/tests/common/mod.rs)**

Adapted verbatim from the root crate's `tests/e2e.rs` patterns (presets::Minimal, MemoryLookup — hermetic, no relays):

```rust
//! In-process bunker + replica harness for operator integration tests.
#![allow(dead_code)]

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use secret_bunker_iroh::client::Client;
use secret_bunker_iroh::proto::{ALPN, Request, Response};
use secret_bunker_iroh::replica::{Replica, ReplicaEvent};
use secret_bunker_iroh::server::Bunker;
use secret_bunker_iroh::store::Store;
use secret_bunker_iroh::sync::SYNC_ALPN;

pub struct TestBunker {
    pub admin: Client,
    pub addr: EndpointAddr,
    pub router: Router,
    _dir: tempfile::TempDir,
}

impl TestBunker {
    pub async fn spawn() -> TestBunker {
        let dir = tempfile::tempdir().unwrap();
        let op = age::x25519::Identity::generate();
        let backup = age::x25519::Identity::generate();
        let admin_secret = SecretKey::generate();

        let db = dir.path().join("bunker.sqlite");
        let mut store = Store::open(&db).unwrap();
        store
            .init(
                &op.to_public().to_string(),
                &backup.to_public().to_string(),
                &admin_secret.public().to_string(),
                "admin",
            )
            .unwrap();

        let bunker = Bunker::new(store, op).unwrap();
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let router = Router::builder(endpoint)
            .accept(ALPN, bunker.clone())
            .accept(SYNC_ALPN, bunker.sync_handler())
            .spawn();
        let addr = router.endpoint().addr();

        let admin_ep = Endpoint::builder(presets::Minimal)
            .secret_key(admin_secret)
            .bind()
            .await
            .unwrap();
        let admin = Client::with_endpoint(admin_ep, addr.clone()).await.unwrap();
        TestBunker { admin, addr, router, _dir: dir }
    }

    pub async fn create_group(&self, group: &str) {
        let r = self.admin.request(&Request::CreateGroup { name: group.into() }).await.unwrap();
        assert_eq!(r, Response::Ok);
    }

    pub async fn add_reader(&self, name: &str, secret: &SecretKey) {
        let r = self
            .admin
            .request(&Request::AddIdentity {
                name: name.into(),
                endpoint_id: secret.public().to_string(),
                service_admin: false,
            })
            .await
            .unwrap();
        assert_eq!(r, Response::Ok);
    }

    pub async fn grant_read(&self, group: &str, identity: &str) {
        let r = self
            .admin
            .request(&Request::Grant { group: group.into(), identity: identity.into(), perms: 1 })
            .await
            .unwrap();
        assert_eq!(r, Response::Ok);
    }

    pub async fn put(&self, group: &str, name: &str, value: &[u8], expected_version: u64) -> u64 {
        match self
            .admin
            .request(&Request::Put {
                group: group.into(),
                name: name.into(),
                value: value.to_vec(),
                expected_version,
            })
            .await
            .unwrap()
        {
            Response::Version { version } => version,
            other => panic!("put: {other:?}"),
        }
    }

    pub async fn delete(&self, group: &str, name: &str, expected_version: u64) {
        let r = self
            .admin
            .request(&Request::Delete { group: group.into(), name: name.into(), expected_version })
            .await
            .unwrap();
        assert_eq!(r, Response::Ok);
    }

    /// Spawn an embedded replica for `secret` against this bunker, hermetically.
    pub async fn replica_for(
        &self,
        secret: SecretKey,
        store_path: &std::path::Path,
    ) -> (Replica, tokio::sync::broadcast::Receiver<ReplicaEvent>) {
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(secret.clone())
            .address_lookup(iroh::address_lookup::MemoryLookup::from_endpoint_info([
                self.addr.clone(),
            ]))
            .bind()
            .await
            .unwrap();
        let replica = Replica::builder()
            .store_path(store_path)
            .secret_key(secret)
            .authoritative(self.addr.id)
            .endpoint(ep)
            .spawn()
            .await
            .unwrap();
        let rx = replica.subscribe();
        (replica, rx)
    }
}

/// Await one event with the same 30 s deadline style as the upstream e2e suite.
pub async fn next_event(
    rx: &mut tokio::sync::broadcast::Receiver<ReplicaEvent>,
) -> ReplicaEvent {
    tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv())
        .await
        .expect("timed out waiting for a replica event")
        .expect("replica event channel closed")
}

/// Await a specific event, skipping a bounded number of others.
pub async fn await_event(
    rx: &mut tokio::sync::broadcast::Receiver<ReplicaEvent>,
    want: &ReplicaEvent,
) {
    for _ in 0..64 {
        if next_event(rx).await == *want {
            return;
        }
    }
    panic!("event {want:?} never arrived");
}

/// Poll until the replica's mirror can serve (group, name) or the deadline hits.
pub async fn await_mirrored(replica: &Replica, group: &str, name: &str) -> Vec<u8> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Ok(v) = replica.get(group, name) {
            return v.to_vec();
        }
        assert!(std::time::Instant::now() < deadline, "mirror never served {group}/{name}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
```

- [ ] **Step 2: Write failing tests (operator/tests/replica_source.rs)**

```rust
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::TestBunker;
use iroh::SecretKey;
use secret_bunker_operator::bunker::{ReplicaSource, Staleness, spawn_replica};
use secret_bunker_operator::render::{SecretSource, SourceError};

#[tokio::test]
async fn replica_source_serves_and_classifies() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"hunter2", 0).await;

    let dir = tempfile::tempdir().unwrap();
    let (replica, _rx) = bunker.replica_for(reader, &dir.path().join("mirror.sqlite")).await;
    common::await_mirrored(&replica, "prod", "pw").await;

    let source = ReplicaSource(Arc::new(replica));
    assert_eq!(source.get("prod", "pw").unwrap(), b"hunter2".to_vec());
    assert_eq!(source.list("prod").unwrap(), vec!["pw".to_string()]);
    assert_eq!(source.get("nope", "x").unwrap_err(), SourceError::MissingGroup);
    assert_eq!(source.list("nope").unwrap_err(), SourceError::MissingGroup);
    assert_eq!(source.get("prod", "nope").unwrap_err(), SourceError::MissingSecret);
}

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
    std::fs::write(&key_file, secret_bunker_iroh::keys::encode_endpoint_key(&reader)).unwrap();

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
    assert!(!addrs.is_empty(), "in-process bunker must expose an IP transport addr");

    let replica = spawn_replica(
        &bunker.addr.id.to_string(),
        &addrs,
        &key_file,
        &dir.path().join("mirror.sqlite"),
    )
    .await
    .unwrap();
    let got = common::await_mirrored(&replica, "g", "s").await;
    assert_eq!(got, b"v".to_vec());
    // Missing key file must be a hard error (never auto-generate an identity).
    let err = spawn_replica(
        &bunker.addr.id.to_string(),
        &addrs,
        &dir.path().join("missing.key"),
        &dir.path().join("mirror2.sqlite"),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("reading endpoint key"), "{err}");
}

#[test]
fn staleness_tracks_disconnection() {
    let s = Staleness::new();
    // Fresh state counts as disconnected-since-startup.
    assert!(s.disconnected_for().is_some());
    s.set_connected(true);
    assert_eq!(s.disconnected_for(), None);
    s.set_connected(false);
    assert!(s.disconnected_for().unwrap() < Duration::from_secs(1));
}
```

Note for the implementer: `spawn_replica` with explicit `addrs` still binds the
default n0-preset endpoint (relay config present but unused for direct dial); the
hermetic reachability comes from `authoritative_addrs`. If the test proves flaky
because discovery is attempted, this is the one place where flakiness may
originate — the fallback is to poll `await_mirrored` with the full 30 s deadline
(already the case). `bunker.addr.addrs` field name: check `EndpointAddr`'s public
API in the iroh 1.0.3 docs if the filter_map does not compile
(`iroh::TransportAddr::Ip(SocketAddr)` is the variant used by the root crate at
src/replica.rs:511).

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p secret-bunker-operator --test replica_source`
Expected: compile error — `bunker` module missing.

- [ ] **Step 4: Implement bunker.rs**

```rust
//! Embedded-replica integration: spawning, SecretSource impl, staleness clock.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use secret_bunker_iroh::keys;
use secret_bunker_iroh::replica::Replica;

use crate::render::{SecretSource, SourceError};

/// Wraps the replica for the render pipeline. Classification probes the mirror
/// (groups/list) instead of parsing anyhow messages.
pub struct ReplicaSource(pub Arc<Replica>);

impl SecretSource for ReplicaSource {
    fn list(&self, group: &str) -> Result<Vec<String>, SourceError> {
        if !group_exists(&self.0, group)? {
            return Err(SourceError::MissingGroup);
        }
        let entries = self.0.list(group).map_err(|e| SourceError::Other(e.to_string()))?;
        Ok(entries.into_iter().map(|(name, _version)| name).collect())
    }

    fn get(&self, group: &str, name: &str) -> Result<Vec<u8>, SourceError> {
        match self.0.get(group, name) {
            Ok(v) => Ok(v.to_vec()),
            Err(e) => {
                if !group_exists(&self.0, group)? {
                    return Err(SourceError::MissingGroup);
                }
                let names = self.0.list(group).map_err(|e| SourceError::Other(e.to_string()))?;
                if !names.iter().any(|(n, _)| n == name) {
                    return Err(SourceError::MissingSecret);
                }
                // Present in the mirror but unreadable: DEK wrap race — retryable.
                Err(SourceError::NotYetSynced(e.to_string()))
            }
        }
    }
}

fn group_exists(replica: &Replica, group: &str) -> Result<bool, SourceError> {
    let groups = replica.groups().map_err(|e| SourceError::Other(e.to_string()))?;
    Ok(groups.iter().any(|g| g == group))
}

/// Tracks how long the sync session has been down. Starts "disconnected" at
/// process start so a bunker that is unreachable from boot still trips the
/// staleness threshold.
pub struct Staleness {
    disconnected_since: Mutex<Option<Instant>>,
}

impl Staleness {
    pub fn new() -> Staleness {
        Staleness { disconnected_since: Mutex::new(Some(Instant::now())) }
    }

    pub fn set_connected(&self, connected: bool) {
        let mut guard = self.disconnected_since.lock().unwrap();
        if connected {
            *guard = None;
        } else if guard.is_none() {
            *guard = Some(Instant::now());
        }
    }

    pub fn disconnected_for(&self) -> Option<Duration> {
        self.disconnected_since.lock().unwrap().map(|t| t.elapsed())
    }
}

impl Default for Staleness {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn the embedded replica from operator config. The key path must exist —
/// keys::load_endpoint_key never auto-generates (an accidental fresh identity
/// would have no grants and sync nothing, silently).
pub async fn spawn_replica(
    id: &str,
    addrs: &[SocketAddr],
    key_file: &Path,
    mirror_path: &Path,
) -> anyhow::Result<Replica> {
    let authoritative: iroh::EndpointId =
        id.parse().context("parsing --bunker-id as an EndpointId")?;
    let secret = keys::load_endpoint_key(key_file)?;
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

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p secret-bunker-operator --test replica_source`
Expected: 3 tests pass (two are multi-second: real QUIC handshakes in-process).

- [ ] **Step 6: Commit**

```bash
git add operator/src operator/tests
git commit -m "feat: replica spawn/config, SecretSource over the mirror, staleness clock"
```

---

### Task 7: Event bridge

**Files:**
- Create: `operator/src/events.rs`; add `pub mod events;` to lib.rs
- Test: unit tests in `operator/src/events.rs` (synthetic broadcast channel — no live replica needed)

**Interfaces:**
- Consumes: `crd::BunkerSecret` (+ `referenced_groups()`), `bunker::Staleness`, `metrics::Metrics`, `secret_bunker_iroh::replica::ReplicaEvent`.
- Produces: `spawn_event_bridge(rx, crs, staleness, threshold, metrics) -> impl Stream<Item = ObjectRef<BunkerSecret>>` — exact signature in the interfaces block. `crs` is a `Box<dyn Fn() -> Vec<Arc<BunkerSecret>> + Send>`; production passes `Box::new(move || store.state())`, tests pass fixtures.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bunker::Staleness;
    use crate::crd::{BunkerSecret, BunkerSecretSpec};
    use crate::metrics::Metrics;
    use futures::StreamExt;
    use secret_bunker_iroh::replica::ReplicaEvent;
    use std::sync::Arc;
    use std::time::Duration;

    fn cr(name: &str, ns: &str, group: &str) -> Arc<BunkerSecret> {
        let spec: BunkerSecretSpec = serde_yaml::from_str(&format!(
            "dataFrom: [{{group: {{name: {group}}}}}]"
        ))
        .unwrap();
        let mut cr = BunkerSecret::new(name, spec);
        cr.metadata.namespace = Some(ns.to_string());
        Arc::new(cr)
    }

    async fn next_ref(
        stream: &mut (impl futures::Stream<Item = kube::runtime::reflector::ObjectRef<BunkerSecret>>
                  + Unpin),
    ) -> (String, String) {
        let r = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timed out waiting for trigger")
            .expect("bridge stream ended");
        (r.namespace.clone().unwrap_or_default(), r.name.clone())
    }

    #[tokio::test]
    async fn secret_changed_triggers_only_referencing_crs() {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let crs = vec![cr("a", "ns1", "prod"), cr("b", "ns2", "staging")];
        let mut stream = Box::pin(spawn_event_bridge(
            rx,
            Box::new(move || crs.clone()),
            Arc::new(Staleness::new()),
            Duration::from_secs(600),
            Metrics::new().unwrap(),
        ));
        tx.send(ReplicaEvent::SecretChanged {
            group: "prod".into(),
            name: "pw".into(),
            version: 1,
        })
        .unwrap();
        assert_eq!(next_ref(&mut stream).await, ("ns1".to_string(), "a".to_string()));
        // No trigger for the staging CR: send a second prod event and confirm
        // the next item is again CR "a" (nothing for "b" queued between).
        tx.send(ReplicaEvent::GroupRemoved { group: "prod".into() }).unwrap();
        assert_eq!(next_ref(&mut stream).await, ("ns1".to_string(), "a".to_string()));
    }

    #[tokio::test]
    async fn connected_updates_staleness_not_stream() {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let staleness = Arc::new(Staleness::new());
        let crs = vec![cr("a", "ns1", "prod")];
        let mut stream = Box::pin(spawn_event_bridge(
            rx,
            Box::new(move || crs.clone()),
            staleness.clone(),
            Duration::from_secs(600),
            Metrics::new().unwrap(),
        ));
        assert!(staleness.disconnected_for().is_some());
        tx.send(ReplicaEvent::Connected).unwrap();
        // Follow with a data event so the stream yields something deterministic.
        tx.send(ReplicaEvent::SecretChanged { group: "prod".into(), name: "x".into(), version: 1 }).unwrap();
        assert_eq!(next_ref(&mut stream).await, ("ns1".to_string(), "a".to_string()));
        assert_eq!(staleness.disconnected_for(), None);
    }

    #[tokio::test]
    async fn closed_channel_triggers_reconcile_all_then_ends() {
        // Dropping the sender simulates replica shutdown; Lagged uses the same
        // reconcile-all path (drive_bridge handles both identically).
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let crs = vec![cr("a", "ns1", "prod"), cr("b", "ns2", "staging")];
        let mut stream = Box::pin(spawn_event_bridge(
            rx,
            Box::new(move || crs.clone()),
            Arc::new(Staleness::new()),
            Duration::from_secs(600),
            Metrics::new().unwrap(),
        ));
        drop(tx);
        // Channel-closed does NOT reconcile-all; the stream just ends.
        let r = tokio::time::timeout(Duration::from_secs(5), stream.next()).await.unwrap();
        assert!(r.is_none(), "stream should end when the replica goes away, got {r:?}");
    }
}
```

- [ ] **Step 2: Run to verify failure, then implement events.rs**

```rust
//! Bridges ReplicaEvents to controller reconcile triggers.
//!
//! Events are wake-ups only: reconcile always reads full state from the
//! mirror, so a missed event costs latency, never correctness. Lagged (the
//! broadcast buffer overflowed) triggers reconcile of ALL CRs.

use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use kube::runtime::reflector::ObjectRef;
use secret_bunker_iroh::replica::ReplicaEvent;
use tokio::sync::broadcast;

use crate::bunker::Staleness;
use crate::crd::BunkerSecret;
use crate::metrics::Metrics;

type CrLister = Box<dyn Fn() -> Vec<Arc<BunkerSecret>> + Send>;

pub fn spawn_event_bridge(
    rx: broadcast::Receiver<ReplicaEvent>,
    crs: CrLister,
    staleness: Arc<Staleness>,
    staleness_threshold: Duration,
    metrics: Metrics,
) -> impl Stream<Item = ObjectRef<BunkerSecret>> {
    let (tx, out) = futures::channel::mpsc::unbounded();
    tokio::spawn(drive_bridge(rx, crs, staleness, staleness_threshold, metrics, tx));
    out
}

fn obj_ref(cr: &BunkerSecret) -> ObjectRef<BunkerSecret> {
    let name = cr.metadata.name.clone().unwrap_or_default();
    match &cr.metadata.namespace {
        Some(ns) => ObjectRef::new(&name).within(ns),
        None => ObjectRef::new(&name),
    }
}

async fn drive_bridge(
    mut rx: broadcast::Receiver<ReplicaEvent>,
    crs: CrLister,
    staleness: Arc<Staleness>,
    staleness_threshold: Duration,
    metrics: Metrics,
    tx: futures::channel::mpsc::UnboundedSender<ObjectRef<BunkerSecret>>,
) {
    // The ticker exists to flip CRs to/from StaleReplica when nothing else is
    // reconciling; it fires rarely relative to the threshold.
    let mut tick = tokio::time::interval(staleness_threshold.min(Duration::from_secs(60)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut was_stale = false;

    loop {
        let trigger_all = |reason: &str| {
            tracing::debug!(reason, "triggering reconcile of all BunkerSecrets");
            for cr in crs() {
                let _ = tx.unbounded_send(obj_ref(&cr));
            }
        };

        tokio::select! {
            event = rx.recv() => match event {
                Ok(ev) => {
                    let (label, group) = match &ev {
                        ReplicaEvent::SecretChanged { group, .. } => ("secret_changed", Some(group.clone())),
                        ReplicaEvent::SecretDeleted { group, .. } => ("secret_deleted", Some(group.clone())),
                        ReplicaEvent::GroupAdded { group } => ("group_added", Some(group.clone())),
                        ReplicaEvent::GroupRemoved { group } => ("group_removed", Some(group.clone())),
                        ReplicaEvent::Connected => ("connected", None),
                        ReplicaEvent::Disconnected => ("disconnected", None),
                    };
                    metrics.events_total.with_label_values(&[label]).inc();
                    match ev {
                        ReplicaEvent::Connected => staleness.set_connected(true),
                        ReplicaEvent::Disconnected => staleness.set_connected(false),
                        _ => {
                            if let Some(g) = group {
                                for cr in crs() {
                                    if cr.referenced_groups().contains(&g) {
                                        let _ = tx.unbounded_send(obj_ref(&cr));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    metrics.events_total.with_label_values(&["lagged"]).inc();
                    tracing::warn!(missed = n, "replica event stream lagged; reconciling everything");
                    trigger_all("lagged");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::warn!("replica event channel closed; event bridge exiting");
                    return;
                }
            },
            _ = tick.tick() => {
                let stale = staleness
                    .disconnected_for()
                    .is_some_and(|d| d >= staleness_threshold);
                if stale != was_stale {
                    was_stale = stale;
                    trigger_all(if stale { "went-stale" } else { "recovered" });
                }
            }
        }
    }
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p secret-bunker-operator events`
Expected: 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add operator/src
git commit -m "feat: replica-event bridge with lagged fallback and staleness ticker"
```

---

### Task 8: Reconcile core — apply path, status, conditions

**Files:**
- Create: `operator/src/reconcile.rs`; add `pub mod reconcile;` to lib.rs
- Create: `operator/tests/kubemock/mod.rs` (canned kube API), `operator/tests/reconcile_apply.rs`

**Interfaces:**
- Consumes: everything produced so far.
- Produces: `Context`, `Error`, `reconcile()`, `error_policy()`, `apply_bunker_secret()`, `cleanup_bunker_secret()` (cleanup implemented in Task 9 — declare it now returning `Ok(Action::await_change())` so Task 8 compiles), condition helper `set_ready(status_out: &mut BunkerSecretStatus, cr: &BunkerSecret, ok: bool, reason: &str, message: &str)`.

**Reconcile decision table (implements the spec; the code follows it exactly):**

| Situation | Status | Secret | Return |
|---|---|---|---|
| `last_synced` is None | `Ready=False/AwaitingSync` | untouched | `Ok(requeue(5s))` |
| Render ok, no existing Secret | `Ready=True/Synced` (or `False/StaleReplica` if stale) | SSA create | `Ok(requeue(resync))` |
| Render ok, existing owned, hash equal | same | skipped (`applies_total{skipped}`) | `Ok(requeue(resync))` |
| Render ok, existing owned, hash differs | same | SSA apply | `Ok(requeue(resync))` |
| Existing Secret NOT owned by this CR | `Ready=False/Conflict` | untouched | `Ok(requeue(resync))` |
| `RenderError::MissingGroup`, never synced (`status.last_sync_time` None) | `Ready=False/MissingGroup` | untouched | `Ok(requeue(resync))` |
| `RenderError::MissingGroup`, previously synced | `Ready=False/AccessRevoked` + Warning event | untouched (frozen) | `Ok(requeue(resync))` |
| `RenderError::MissingSecret` | `Ready=False/MissingSecret` | untouched | `Ok(requeue(resync))` |
| `RenderError::InvalidKey` | `Ready=False/InvalidKey` (offenders in message) | untouched | `Ok(requeue(resync))` |
| `RenderError::Json/Pointer/NotObject` | `Ready=False/JsonError` | untouched | `Ok(requeue(resync))` |
| `RenderError::NotYetSynced` | unchanged | untouched | `Err(Transient)` → backoff |
| kube API error | unchanged | — | `Err(Kube)` → backoff |
| target renamed (status.target_secret_name != current) | — | old Secret: Delete policy → delete; Retain → strip ownerRefs | continues into normal apply |

- [ ] **Step 1: Write the canned kube API mock (operator/tests/kubemock/mod.rs)**

The mock is a scripted sequence: each expectation matches on (method, path-substring)
and returns a canned JSON response. Unexpected or missing calls fail the test.

```rust
//! Scripted mock of the kube apiserver over tower-test, kube 4.x style.
#![allow(dead_code)]

use http::{Request, Response};
use kube::client::Body;

pub struct Expectation {
    pub method: &'static str,
    pub path_contains: String,
    pub status: u16,
    pub respond: serde_json::Value,
    /// If set, the request body (JSON) is passed to this check.
    pub body_check: Option<Box<dyn Fn(&serde_json::Value) + Send>>,
}

pub fn expect(
    method: &'static str,
    path_contains: &str,
    status: u16,
    respond: serde_json::Value,
) -> Expectation {
    Expectation {
        method,
        path_contains: path_contains.to_string(),
        status,
        respond,
        body_check: None,
    }
}

pub fn expect_checked(
    method: &'static str,
    path_contains: &str,
    status: u16,
    respond: serde_json::Value,
    check: impl Fn(&serde_json::Value) + Send + 'static,
) -> Expectation {
    Expectation {
        method,
        path_contains: path_contains.to_string(),
        status,
        respond,
        body_check: Some(Box::new(check)),
    }
}

/// Returns a kube Client wired to the script and a JoinHandle that panics on
/// deviation. Await the handle after the code under test finishes.
pub fn scripted(script: Vec<Expectation>) -> (kube::Client, tokio::task::JoinHandle<()>) {
    let (mock_service, mut handle) =
        tower_test::mock::pair::<Request<Body>, Response<Body>>();
    let client = kube::Client::new(mock_service, "default");
    let join = tokio::spawn(async move {
        for (i, exp) in script.into_iter().enumerate() {
            let (request, send) = handle
                .next_request()
                .await
                .unwrap_or_else(|| panic!("expectation {i}: no more API calls, wanted {} {}", exp.method, exp.path_contains));
            let path = request.uri().path().to_string();
            assert_eq!(request.method().as_str(), exp.method, "expectation {i} on {path}");
            assert!(
                path.contains(&exp.path_contains),
                "expectation {i}: path {path} does not contain {}",
                exp.path_contains
            );
            if let Some(check) = exp.body_check {
                let bytes = {
                    use http_body_util::BodyExt;
                    request.into_body().collect().await.unwrap().to_bytes()
                };
                let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                check(&json);
            }
            let resp = Response::builder()
                .status(exp.status)
                .body(Body::from(serde_json::to_vec(&exp.respond).unwrap()))
                .unwrap();
            send.send_response(resp);
        }
        // Script exhausted: any further call errors inside the client (mock closed).
    });
    (client, join)
}
```

Add `http-body-util = "0.1"` to `[dev-dependencies]` in `operator/Cargo.toml`
(needed to collect mock request bodies; it is already in kube's own dep tree).

- [ ] **Step 2: Write failing integration tests (operator/tests/reconcile_apply.rs)**

```rust
mod common;
mod kubemock;

use std::sync::Arc;
use std::time::Duration;

use common::TestBunker;
use iroh::SecretKey;
use kubemock::{expect, expect_checked, scripted};
use secret_bunker_operator::bunker::{ReplicaSource, Staleness};
use secret_bunker_operator::crd::{BunkerSecret, BunkerSecretSpec, BunkerSecretStatus, HASH_ANNOTATION};
use secret_bunker_operator::metrics::Metrics;
use secret_bunker_operator::reconcile::{Context, apply_bunker_secret};
use serde_json::json;

fn cr_json(cr: &BunkerSecret) -> serde_json::Value {
    serde_json::to_value(cr).unwrap()
}

async fn synced_context(bunker: &TestBunker, reader: SecretKey, client: kube::Client) -> (Context, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let (replica, _rx) = bunker.replica_for(reader, &dir.path().join("m.sqlite")).await;
    // Deterministic tests need a converged mirror; production gates on last_synced.
    let replica = Arc::new(replica);
    let recorder = kube::runtime::events::Recorder::new(
        client.clone(),
        kube::runtime::events::Reporter { controller: "secret-bunker-operator".into(), instance: None },
    );
    let ctx = Context {
        client,
        source: ReplicaSource(replica.clone()),
        replica,
        metrics: Metrics::new().unwrap(),
        staleness: Arc::new(Staleness::new()),
        recorder,
        resync: Duration::from_secs(3600),
        staleness_threshold: Duration::from_secs(600),
    };
    (ctx, dir)
}

fn test_cr(yaml: &str) -> BunkerSecret {
    let spec: BunkerSecretSpec = serde_yaml::from_str(yaml).unwrap();
    let mut cr = BunkerSecret::new("app", spec);
    cr.metadata.namespace = Some("ns".into());
    cr.metadata.uid = Some("uid-1".into());
    cr.metadata.generation = Some(1);
    cr
}

#[tokio::test]
async fn happy_path_creates_secret_and_sets_ready() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"hunter2", 0).await;

    let cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    let script = vec![
        // 1. GET existing Secret → 404
        expect("GET", "/api/v1/namespaces/ns/secrets/app", 404, json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "reason": "NotFound", "code": 404
        })),
        // 2. SSA apply of the Secret; assert rendered content
        expect_checked("PATCH", "/api/v1/namespaces/ns/secrets/app", 200, json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "app", "namespace": "ns"}
        }), |body| {
            assert_eq!(body["data"]["PW"], json!(base64_encode(b"hunter2")));
            assert!(body["metadata"]["annotations"][HASH_ANNOTATION]
                .as_str().unwrap().starts_with("sha256:"));
            assert_eq!(body["metadata"]["ownerReferences"][0]["kind"], json!("BunkerSecret"));
        }),
        // 3. status patch; assert Ready=True/Synced + bookkeeping
        expect_checked("PATCH", "/apis/bunker.fables-for-robots.ch/v1alpha1/namespaces/ns/bunkersecrets/app/status", 200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            |body| {
                let c = &body["status"]["conditions"][0];
                assert_eq!(c["type"], json!("Ready"));
                assert_eq!(c["status"], json!("True"));
                assert_eq!(c["reason"], json!("Synced"));
                assert_eq!(body["status"]["syncedSecretKeys"], json!(["PW"]));
                assert_eq!(body["status"]["targetSecretName"], json!("app"));
            }),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    let action = apply_bunker_secret(&cr, &ctx).await.unwrap();
    assert_eq!(action, kube::runtime::controller::Action::requeue(Duration::from_secs(3600)));
    join.await.unwrap();
}

fn base64_encode(b: &[u8]) -> String {
    use data_encoding::BASE64;
    BASE64.encode(b)
}

#[tokio::test]
async fn hash_match_skips_apply() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"hunter2", 0).await;

    let cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    // Compute the same hash the operator will: render the same map.
    let mut data = std::collections::BTreeMap::new();
    data.insert("PW".to_string(), b"hunter2".to_vec());
    let hash = secret_bunker_operator::render::content_hash(&data);

    let script = vec![
        expect("GET", "/api/v1/namespaces/ns/secrets/app", 200, json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {
                "name": "app", "namespace": "ns",
                "annotations": {HASH_ANNOTATION: hash},
                "ownerReferences": [{"apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
                    "kind": "BunkerSecret", "name": "app", "uid": "uid-1", "controller": true}]
            }
        })),
        // No Secret PATCH — straight to status.
        expect("PATCH", "/bunkersecrets/app/status", 200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}})),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();
    // applies_total{skipped} == 1
    let fams = ctx.metrics.registry.gather();
    let fam = fams.iter().find(|f| f.name() == "bunker_secret_applies_total").unwrap();
    let m = fam.get_metric().iter().find(|m| {
        m.get_label().iter().any(|l| l.value() == "skipped")
    }).unwrap();
    assert_eq!(m.get_counter().value() as u64, 1);
}

#[tokio::test]
async fn unowned_secret_is_conflict_not_overwrite() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"x", 0).await;

    let cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    let script = vec![
        expect("GET", "/api/v1/namespaces/ns/secrets/app", 200, json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "app", "namespace": "ns"}   // no ownerReferences
        })),
        // Transition to a failure reason → one Warning k8s Event.
        expect("POST", "events", 201, json!({
            "apiVersion": "events.k8s.io/v1", "kind": "Event",
            "metadata": {"name": "app.warn", "namespace": "ns"}
        })),
        expect_checked("PATCH", "/bunkersecrets/app/status", 200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            |body| {
                let c = &body["status"]["conditions"][0];
                assert_eq!(c["status"], json!("False"));
                assert_eq!(c["reason"], json!("Conflict"));
            }),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn revocation_freezes_previously_synced_cr() {
    let bunker = TestBunker::spawn().await;
    bunker.create_group("prod").await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    bunker.grant_read("prod", "op").await;
    bunker.put("prod", "pw", b"x", 0).await;

    let mut cr = test_cr("data: [{secretKey: PW, remoteRef: {group: prod, name: pw}}]");
    // Previously synced: lastSyncTime present in status.
    cr.status = Some(BunkerSecretStatus {
        last_sync_time: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::chrono::Utc::now(),
        )),
        ..Default::default()
    });

    let script = vec![
        // No Secret GET/PATCH — the render fails first.
        // Transition to AccessRevoked → one Warning k8s Event, then status:
        expect("POST", "events", 201, json!({
            "apiVersion": "events.k8s.io/v1", "kind": "Event",
            "metadata": {"name": "app.warn", "namespace": "ns"}
        })),
        expect_checked("PATCH", "/bunkersecrets/app/status", 200,
            json!({"apiVersion": "bunker.fables-for-robots.ch/v1alpha1", "kind": "BunkerSecret",
                   "metadata": {"name": "app", "namespace": "ns"}, "spec": {}}),
            |body| {
                assert_eq!(body["status"]["conditions"][0]["reason"], json!("AccessRevoked"));
            }),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = synced_context(&bunker, reader, client).await;
    common::await_mirrored(&ctx.replica, "prod", "pw").await;

    // Revoke: remove the identity's read grant → mirror empties (GroupRemoved).
    let r = bunker.admin
        .request(&secret_bunker_iroh::proto::Request::Grant {
            group: "prod".into(), identity: "op".into(), perms: 0,
        }).await.unwrap();
    assert_eq!(r, secret_bunker_iroh::proto::Response::Ok);
    // Await the mirror actually emptying, with the usual deadline.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while ctx.replica.groups().map(|g| !g.is_empty()).unwrap_or(true) {
        assert!(std::time::Instant::now() < deadline, "mirror never emptied");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    apply_bunker_secret(&cr, &ctx).await.unwrap();
    join.await.unwrap();
}
```

Note: `k8s_openapi::chrono` is k8s-openapi's re-export (it uses chrono for `Time`);
if the re-export path differs, add `chrono` as a dev-dependency instead.
The `fam.name()`/`get_metric()` accessor spellings come from prometheus 0.14's
protobuf types; adjust to the compiler if the names drift (`get_name()` on older).
If `Grant { perms: 0 }` is not how revocation is spelled (check
`src/store.rs` `grant`/`revoke` handling of `perms: 0`), use the store's actual
revoke request — the root crate's e2e revocation test (tests/e2e.rs:881-897
region) shows the exact wire call; copy it.

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p secret-bunker-operator --test reconcile_apply`
Expected: compile error — `reconcile` module missing.

- [ ] **Step 4: Implement reconcile.rs**

```rust
//! The reconcile loop: render from the mirror, server-side apply, status.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as Finalizer, finalizer};
use kube::{Client, Resource, ResourceExt};
use serde_json::json;

use crate::bunker::{ReplicaSource, Staleness};
use crate::crd::{
    BunkerSecret, BunkerSecretStatus, DeletionPolicy, FIELD_MANAGER, FINALIZER, HASH_ANNOTATION,
};
use crate::metrics::Metrics;
use crate::render::{RenderError, render};
use crate::secretbuild::build_secret;
use secret_bunker_iroh::replica::Replica;

pub struct Context {
    pub client: Client,
    pub source: ReplicaSource,
    pub replica: Arc<Replica>,
    pub metrics: Metrics,
    pub staleness: Arc<Staleness>,
    pub resync: Duration,
    pub staleness_threshold: Duration,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("kube api: {0}")]
    Kube(#[from] kube::Error),
    #[error("finalizer: {0}")]
    Finalizer(#[source] Box<kube::runtime::finalizer::Error<Error>>),
    #[error("transient: {0}")]
    Transient(String),
}

pub async fn reconcile(cr: Arc<BunkerSecret>, ctx: Arc<Context>) -> Result<Action, Error> {
    let timer = ctx.metrics.reconcile_duration.start_timer();
    let ns = cr.namespace().unwrap_or_default();
    let api: Api<BunkerSecret> = Api::namespaced(ctx.client.clone(), &ns);
    let result = finalizer(&api, FINALIZER, cr, |event| async {
        match event {
            Finalizer::Apply(cr) => apply_bunker_secret(&cr, &ctx).await,
            Finalizer::Cleanup(cr) => cleanup_bunker_secret(&cr, &ctx).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)));
    timer.observe_duration();
    ctx.metrics
        .reconciles_total
        .with_label_values(&[if result.is_ok() { "success" } else { "error" }])
        .inc();
    result
}

pub fn error_policy(_cr: Arc<BunkerSecret>, err: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!(%err, "reconcile failed; backing off");
    Action::requeue(Duration::from_secs(10))
}

fn ready_condition(cr: &BunkerSecret, ok: bool, reason: &str, message: &str) -> Condition {
    Condition {
        type_: "Ready".to_string(),
        status: if ok { "True" } else { "False" }.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        last_transition_time: Time(k8s_openapi::chrono::Utc::now()),
        observed_generation: cr.metadata.generation,
    }
}

async fn patch_status(cr: &BunkerSecret, ctx: &Context, status: BunkerSecretStatus) -> Result<(), Error> {
    let ns = cr.namespace().unwrap_or_default();
    let api: Api<BunkerSecret> = Api::namespaced(ctx.client.clone(), &ns);
    let ready = status
        .conditions
        .first()
        .map(|c| c.status == "True")
        .unwrap_or(false);
    ctx.metrics
        .ready
        .with_label_values(&[&ns, &cr.name_any()])
        .set(if ready { 1 } else { 0 });
    let patch = Patch::Apply(json!({
        "apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
        "kind": "BunkerSecret",
        "status": status,
    }));
    api.patch_status(&cr.name_any(), &PatchParams::apply(FIELD_MANAGER).force(), &patch)
        .await?;
    Ok(())
}

fn status_with(cr: &BunkerSecret, condition: Condition) -> BunkerSecretStatus {
    // Carry forward sync bookkeeping so a degraded condition doesn't erase it.
    let prev = cr.status.clone().unwrap_or_default();
    BunkerSecretStatus {
        conditions: vec![condition],
        observed_generation: cr.metadata.generation,
        ..prev
    }
}

fn owned_by(secret: &Secret, cr: &BunkerSecret) -> bool {
    let Some(uid) = &cr.metadata.uid else { return false };
    secret
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|o| o.kind == "BunkerSecret" && &o.uid == uid)
}

/// The Apply arm of the finalizer. Public for direct testing.
pub async fn apply_bunker_secret(cr: &BunkerSecret, ctx: &Context) -> Result<Action, Error> {
    let ns = cr.namespace().unwrap_or_default();
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);

    // Gate: never render from an unsynced mirror (a boot-time empty mirror
    // must not look like mass deletion). Tests pre-converge, production waits.
    if ctx.replica.status().last_synced.is_none() {
        patch_status(cr, ctx, status_with(cr, ready_condition(cr, false, "AwaitingSync", "replica has not completed its initial sync"))).await?;
        return Ok(Action::requeue(Duration::from_secs(5)));
    }

    // Render.
    let data = match render(&cr.spec, &ctx.source) {
        Ok(data) => data,
        Err(e) => return handle_render_error(cr, ctx, e).await,
    };

    // Target rename cleanup: the previously applied Secret, if differently named.
    let target = cr.target_name();
    if let Some(prev) = cr.status.as_ref().and_then(|s| s.target_secret_name.clone())
        && prev != target
    {
        cleanup_target(&secrets, cr, &prev).await?;
    }

    // Fetch current state for ownership + hash-skip.
    let existing = match secrets.get(&target).await {
        Ok(s) => Some(s),
        Err(kube::Error::Api(ae)) if ae.code == 404 => None,
        Err(e) => return Err(e.into()),
    };
    if let Some(existing) = &existing
        && !owned_by(existing, cr)
    {
        let message = format!("Secret {ns}/{target} exists and is not owned by this BunkerSecret; refusing to adopt");
        publish_warning_on_transition(cr, ctx, "Conflict", &message).await;
        patch_status(cr, ctx, status_with(cr, ready_condition(cr, false, "Conflict", &message))).await?;
        return Ok(Action::requeue(ctx.resync));
    }

    let desired = build_secret(cr, &data);
    let desired_hash = desired.metadata.annotations.as_ref().unwrap()[HASH_ANNOTATION].clone();
    let existing_hash = existing
        .as_ref()
        .and_then(|s| s.metadata.annotations.as_ref())
        .and_then(|a| a.get(HASH_ANNOTATION).cloned());

    if existing_hash.as_deref() == Some(desired_hash.as_str()) {
        ctx.metrics.applies_total.with_label_values(&["skipped"]).inc();
    } else {
        secrets
            .patch(&target, &PatchParams::apply(FIELD_MANAGER).force(), &Patch::Apply(&desired))
            .await?;
        ctx.metrics.applies_total.with_label_values(&["applied"]).inc();
    }

    // Status: Ready, or degraded-but-serving when the replica is stale.
    let stale = ctx
        .staleness
        .disconnected_for()
        .is_some_and(|d| d >= ctx.staleness_threshold);
    let condition = if stale {
        ready_condition(cr, false, "StaleReplica", "bunker unreachable; serving last synced state")
    } else {
        ready_condition(cr, true, "Synced", "")
    };
    let last_synced = ctx.replica.status().last_synced.and_then(system_time_to_k8s);
    let status = BunkerSecretStatus {
        conditions: vec![condition],
        last_sync_time: last_synced,
        observed_generation: cr.metadata.generation,
        synced_secret_keys: data.keys().cloned().collect(),
        target_secret_name: Some(target),
    };
    patch_status(cr, ctx, status).await?;
    Ok(Action::requeue(ctx.resync))
}

fn system_time_to_k8s(t: SystemTime) -> Option<Time> {
    let secs = t.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    let dt = k8s_openapi::chrono::DateTime::from_timestamp(secs.as_secs() as i64, 0)?;
    Some(Time(dt))
}

async fn handle_render_error(cr: &BunkerSecret, ctx: &Context, e: RenderError) -> Result<Action, Error> {
    let previously_synced = cr
        .status
        .as_ref()
        .and_then(|s| s.last_sync_time.as_ref())
        .is_some();
    let (reason, message) = match &e {
        RenderError::MissingGroup { group } if previously_synced => (
            "AccessRevoked",
            format!("group '{group}' disappeared from the mirror after having synced; keeping the last applied Secret"),
        ),
        RenderError::MissingGroup { group } => ("MissingGroup", format!("group '{group}' is not in the mirror (no read grant, or not yet created)")),
        RenderError::MissingSecret { group, name } => ("MissingSecret", format!("secret '{group}/{name}' not found; keeping the last applied Secret")),
        RenderError::InvalidKey { keys } => ("InvalidKey", format!("rendered keys are not valid k8s Secret keys: {keys:?}; add rewrite rules or explicit data entries")),
        RenderError::Json { group, name, msg } => ("JsonError", format!("'{group}/{name}' is not valid JSON: {msg}")),
        RenderError::Pointer { group, name, pointer } => ("JsonError", format!("pointer '{pointer}' not found in '{group}/{name}'")),
        RenderError::NotObject { group, name } => ("JsonError", format!("'{group}/{name}' is not a JSON object; extract requires one")),
        RenderError::NotYetSynced { group, name, msg } => {
            return Err(Error::Transient(format!("'{group}/{name}' not yet decryptable: {msg}")));
        }
    };
    if reason == "AccessRevoked" {
        tracing::warn!(cr = %cr.name_any(), "access revoked; freezing synced Secret");
    }
    publish_warning_on_transition(cr, ctx, reason, &message).await;
    patch_status(cr, ctx, status_with(cr, ready_condition(cr, false, reason, &message))).await?;
    Ok(Action::requeue(ctx.resync))
}

/// Spec: a Warning k8s Event on every TRANSITION to a failure reason (repeat
/// reconciles with the same reason stay quiet). Event publish failures are
/// logged, never fatal — conditions are the source of truth.
async fn publish_warning_on_transition(cr: &BunkerSecret, ctx: &Context, reason: &str, message: &str) {
    let prev_reason = cr
        .status
        .as_ref()
        .and_then(|s| s.conditions.first())
        .map(|c| c.reason.clone());
    if prev_reason.as_deref() == Some(reason) {
        return;
    }
    use kube::runtime::events::{Event, EventType};
    let event = Event {
        type_: EventType::Warning,
        reason: reason.to_string(),
        note: Some(message.to_string()),
        action: "Reconcile".to_string(),
        secondary: None,
    };
    if let Err(e) = ctx.recorder.publish(&event, &cr.object_ref(&())).await {
        tracing::warn!(error = %e, "failed to publish warning event");
    }
}

/// Old target Secret cleanup on rename, honoring deletionPolicy.
async fn cleanup_target(secrets: &Api<Secret>, cr: &BunkerSecret, name: &str) -> Result<(), Error> {
    let existing = match secrets.get(name).await {
        Ok(s) => s,
        Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if !owned_by(&existing, cr) {
        return Ok(());
    }
    match cr.spec.deletion_policy {
        DeletionPolicy::Delete => {
            secrets.delete(name, &Default::default()).await?;
        }
        DeletionPolicy::Retain => {
            // Orphan: strip ownerReferences so GC never collects it.
            let patch = json!({"metadata": {"ownerReferences": null}});
            secrets
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
                .await?;
        }
    }
    Ok(())
}

/// The Cleanup arm of the finalizer — implemented in Task 9.
pub async fn cleanup_bunker_secret(cr: &BunkerSecret, ctx: &Context) -> Result<Action, Error> {
    let _ = (cr, ctx);
    Ok(Action::await_change())
}
```

`let ... && ...` chains: edition-2024 let-chains are stable on this toolchain; if
clippy objects, rewrite as nested ifs — behavior is what the decision table says.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p secret-bunker-operator --test reconcile_apply`
Expected: 4 tests pass. If the finalizer/SSA JSON details fight the mock, print
`request.uri()` from the mock to see the real paths kube 4.2 emits and adjust
`path_contains` — the assertions on bodies are the real contract.

- [ ] **Step 6: Commit**

```bash
git add operator/src operator/tests operator/Cargo.toml
git commit -m "feat: reconcile apply path — render, SSA, hash-skip, conditions"
```

---

### Task 9: Finalizer cleanup + deletion policies

**Files:**
- Modify: `operator/src/reconcile.rs` (implement `cleanup_bunker_secret`)
- Test: `operator/tests/reconcile_cleanup.rs`

**Interfaces:**
- Consumes: Task 8's `Context`, mock, harness.
- Produces: final `cleanup_bunker_secret` — Retain strips ownerReferences (orphan), Delete does nothing (ownerRef GC cascades), both clear the CR's `bunker_secret_ready` gauge.

- [ ] **Step 1: Write failing tests (operator/tests/reconcile_cleanup.rs)**

```rust
mod common;
mod kubemock;

use std::sync::Arc;
use std::time::Duration;

use common::TestBunker;
use iroh::SecretKey;
use kubemock::{expect, expect_checked, scripted};
use secret_bunker_operator::bunker::{ReplicaSource, Staleness};
use secret_bunker_operator::crd::{BunkerSecret, BunkerSecretSpec};
use secret_bunker_operator::metrics::Metrics;
use secret_bunker_operator::reconcile::{Context, cleanup_bunker_secret};
use serde_json::json;

async fn ctx_with(client: kube::Client) -> (Context, tempfile::TempDir) {
    let bunker = TestBunker::spawn().await;
    let reader = SecretKey::generate();
    bunker.add_reader("op", &reader).await;
    let dir = tempfile::tempdir().unwrap();
    let (replica, _rx) = bunker.replica_for(reader, &dir.path().join("m.sqlite")).await;
    let replica = Arc::new(replica);
    let recorder = kube::runtime::events::Recorder::new(
        client.clone(),
        kube::runtime::events::Reporter { controller: "secret-bunker-operator".into(), instance: None },
    );
    let ctx = Context {
        client,
        source: ReplicaSource(replica.clone()),
        replica,
        metrics: Metrics::new().unwrap(),
        staleness: Arc::new(Staleness::new()),
        recorder,
        resync: Duration::from_secs(3600),
        staleness_threshold: Duration::from_secs(600),
    };
    (ctx, dir)
}

fn deleting_cr(policy: &str) -> BunkerSecret {
    let spec: BunkerSecretSpec =
        serde_yaml::from_str(&format!("deletionPolicy: {policy}")).unwrap();
    let mut cr = BunkerSecret::new("app", spec);
    cr.metadata.namespace = Some("ns".into());
    cr.metadata.uid = Some("uid-1".into());
    cr
}

#[tokio::test]
async fn retain_strips_owner_references() {
    let script = vec![
        expect("GET", "/api/v1/namespaces/ns/secrets/app", 200, json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "app", "namespace": "ns",
                "ownerReferences": [{"apiVersion": "bunker.fables-for-robots.ch/v1alpha1",
                    "kind": "BunkerSecret", "name": "app", "uid": "uid-1", "controller": true}]}
        })),
        expect_checked("PATCH", "/api/v1/namespaces/ns/secrets/app", 200, json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": "app", "namespace": "ns"}
        }), |body| {
            assert!(body["metadata"]["ownerReferences"].is_null(),
                "Retain must orphan by clearing ownerReferences, got {body}");
        }),
    ];
    let (client, join) = scripted(script);
    let (ctx, _dir) = ctx_with(client).await;
    cleanup_bunker_secret(&deleting_cr("Retain"), &ctx).await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn delete_policy_leaves_gc_to_owner_reference() {
    // No API calls at all: GC cascades via the ownerReference.
    let (client, join) = scripted(vec![]);
    let (ctx, _dir) = ctx_with(client).await;
    cleanup_bunker_secret(&deleting_cr("Delete"), &ctx).await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn retain_tolerates_missing_or_unowned_secret() {
    // 404 → nothing to orphan; done.
    let script = vec![expect("GET", "/api/v1/namespaces/ns/secrets/app", 404, json!({
        "kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404
    }))];
    let (client, join) = scripted(script);
    let (ctx, _dir) = ctx_with(client).await;
    cleanup_bunker_secret(&deleting_cr("Retain"), &ctx).await.unwrap();
    join.await.unwrap();
}
```

- [ ] **Step 2: Run to verify failure** (`cargo test -p secret-bunker-operator --test reconcile_cleanup` — first test fails: stub makes no API calls but Retain script expects two)

- [ ] **Step 3: Implement cleanup_bunker_secret (replace the Task 8 stub)**

```rust
/// The Cleanup arm of the finalizer: runs when the CR is being deleted.
/// Delete policy: nothing to do — the ownerReference lets GC cascade.
/// Retain policy: orphan the Secret by clearing its ownerReferences.
pub async fn cleanup_bunker_secret(cr: &BunkerSecret, ctx: &Context) -> Result<Action, Error> {
    let ns = cr.namespace().unwrap_or_default();
    ctx.metrics.ready.with_label_values(&[&ns, &cr.name_any()]).set(0);
    if cr.spec.deletion_policy == DeletionPolicy::Retain {
        let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);
        let target = cr.target_name();
        match secrets.get(&target).await {
            Ok(existing) if owned_by(&existing, cr) => {
                let patch = json!({"metadata": {"ownerReferences": null}});
                secrets
                    .patch(&target, &PatchParams::default(), &Patch::Merge(&patch))
                    .await?;
            }
            Ok(_) => {}                                             // not ours — leave it
            Err(kube::Error::Api(ae)) if ae.code == 404 => {}       // already gone
            Err(e) => return Err(e.into()),
        }
    }
    Ok(Action::await_change())
}
```

- [ ] **Step 4: Run tests to verify all pass**

Run: `cargo test -p secret-bunker-operator --test reconcile_cleanup && cargo test -p secret-bunker-operator`
Expected: new tests pass; nothing else regressed.

- [ ] **Step 5: Commit**

```bash
git add operator/src operator/tests
git commit -m "feat: finalizer cleanup honoring deletionPolicy (Retain orphans, Delete cascades)"
```

---

### Task 10: main.rs wiring + graceful shutdown

**Files:**
- Modify: `operator/src/main.rs` (replace stub)
- Test: `cargo run -p secret-bunker-operator --bin operator -- --help` (manual smoke; full e2e is the kind job)

**Interfaces:**
- Consumes: everything.
- Produces: the `operator` binary. Flags exactly as in the spec's config table: `--bunker-id` (required, env `BUNKER_ID`), `--bunker-addr` (repeatable, env `BUNKER_ADDR`), `--key-file` (required, env `BUNKER_KEY_FILE`), `--mirror-path` (required, env `BUNKER_MIRROR_PATH`), `--resync-interval` (default `1h`, env `RESYNC_INTERVAL`), `--staleness-threshold` (default `10m`, env `STALENESS_THRESHOLD`), `--listen` (default `0.0.0.0:8080`, env `LISTEN`).

- [ ] **Step 1: Implement main.rs**

```rust
//! secret-bunker-operator: syncs bunker secrets into Kubernetes Secrets.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::controller::Controller;
use kube::runtime::watcher;
use kube::{Api, Client};

use secret_bunker_operator::bunker::{ReplicaSource, Staleness, spawn_replica};
use secret_bunker_operator::crd::BunkerSecret;
use secret_bunker_operator::events::spawn_event_bridge;
use secret_bunker_operator::http::{AppState, router};
use secret_bunker_operator::metrics::Metrics;
use secret_bunker_operator::reconcile::{Context, error_policy, reconcile};

#[derive(Parser, Debug)]
#[command(name = "operator", about = "secret-bunker → Kubernetes Secret sync operator")]
struct Args {
    /// EndpointId of the authoritative bunker (64-char hex).
    #[arg(long, env = "BUNKER_ID")]
    bunker_id: String,
    /// Direct host:port of the bunker; repeatable. Without it, iroh n0
    /// relay/discovery is used (remote bunker).
    #[arg(long, env = "BUNKER_ADDR")]
    bunker_addr: Vec<SocketAddr>,
    /// Path to the operator's iroh ed25519 key (pre-provisioned; never generated).
    #[arg(long, env = "BUNKER_KEY_FILE")]
    key_file: PathBuf,
    /// Replica mirror SQLite path (emptyDir volume).
    #[arg(long, env = "BUNKER_MIRROR_PATH")]
    mirror_path: PathBuf,
    /// Level-reconcile backstop interval (push events do the real work).
    #[arg(long, env = "RESYNC_INTERVAL", value_parser = humantime::parse_duration, default_value = "1h")]
    resync_interval: Duration,
    /// Disconnected longer than this degrades CR readiness to StaleReplica.
    #[arg(long, env = "STALENESS_THRESHOLD", value_parser = humantime::parse_duration, default_value = "10m")]
    staleness_threshold: Duration,
    /// Health + metrics listener.
    #[arg(long, env = "LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    let metrics = Metrics::new()?;
    let replica = Arc::new(
        spawn_replica(&args.bunker_id, &args.bunker_addr, &args.key_file, &args.mirror_path)
            .await
            .context("spawning embedded replica")?,
    );
    // Subscribe immediately after spawn — race-free window for the first events.
    let events_rx = replica.subscribe();
    let staleness = Arc::new(Staleness::new());

    let client = Client::try_default().await.context("building kube client")?;
    let crs: Api<BunkerSecret> = Api::all(client.clone());
    let secrets: Api<Secret> = Api::all(client.clone());

    let controller = Controller::new(crs, watcher::Config::default())
        .owns(secrets, watcher::Config::default());
    let store = controller.store();
    let bridge = spawn_event_bridge(
        events_rx,
        Box::new(move || store.state()),
        staleness.clone(),
        args.staleness_threshold,
        metrics.clone(),
    );

    // Replica gauges: connected / last-sync / group count.
    {
        let replica = replica.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let status = replica.status();
                metrics.connected.set(status.connected as i64);
                metrics.groups.set(status.groups.len() as i64);
                if let Some(t) = status.last_synced
                    && let Ok(d) = t.duration_since(std::time::SystemTime::UNIX_EPOCH)
                {
                    metrics.last_sync_ts.set(d.as_secs() as i64);
                }
            }
        });
    }

    let state = Arc::new(AppState { metrics: metrics.clone(), replica: replica.clone() });
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(listen = %args.listen, "health/metrics listening");
    let http = tokio::spawn(async move {
        axum::serve(listener, router(state))
            .with_graceful_shutdown(shutdown_signal())
            .await
    });

    let recorder = kube::runtime::events::Recorder::new(
        client.clone(),
        kube::runtime::events::Reporter {
            controller: "secret-bunker-operator".into(),
            instance: std::env::var("HOSTNAME").ok(),
        },
    );
    let ctx = Arc::new(Context {
        client,
        source: ReplicaSource(replica.clone()),
        replica: replica.clone(),
        metrics,
        staleness,
        recorder,
        resync: args.resync_interval,
        staleness_threshold: args.staleness_threshold,
    });

    controller
        .reconcile_on(bridge)
        .graceful_shutdown_on(shutdown_signal())
        .run(reconcile, error_policy, ctx.clone())
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => tracing::debug!(%obj, "reconciled"),
                Err(e) => tracing::warn!(error = %e, "reconcile stream error"),
            }
        })
        .await;

    tracing::info!("controller stopped; shutting down replica");
    http.abort();
    drop(ctx); // release the Context's Arc<Replica> holders
    match Arc::try_unwrap(replica) {
        Ok(r) => r.shutdown().await,
        Err(_) => tracing::warn!("replica still shared at shutdown; letting process exit reap it"),
    }
    Ok(())
}

async fn shutdown_signal() {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("sigterm handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}
```

Known wrinkle: the gauge-ticker task and `AppState` each hold an `Arc<Replica>`,
so `Arc::try_unwrap` may land in the `Err` arm and log the warning — acceptable
(process exit reaps the sync task; the mirror is emptyDir). If you want the clean
path, abort the gauge task and drop `state` before unwrapping; do it only if it
stays simple.

- [ ] **Step 2: Verify it compiles, help renders, clippy clean**

Run: `cargo run -p secret-bunker-operator --bin operator -- --help`
Expected: usage text listing all seven flags with env var names.

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: clean; full suite green.

- [ ] **Step 3: Commit**

```bash
git add operator/src
git commit -m "feat: operator main — controller wiring, event bridge, metrics server, shutdown"
```

---

### Task 11: Deploy manifests + docs

**Files:**
- Create: `operator/deploy/namespace.yaml`, `operator/deploy/rbac.yaml`, `operator/deploy/deployment.yaml` (crd.yaml exists since Task 2)
- Create: `operator/README.md`
- Modify: root `README.md` (short section pointing at the operator)

**Interfaces:**
- Consumes: the binary's flags/env; CRD identity.
- Produces: `kubectl apply -f operator/deploy/` brings up the operator (given the user-created identity Secret).

- [ ] **Step 1: Write the manifests**

`operator/deploy/namespace.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secret-bunker-system
```

`operator/deploy/rbac.yaml`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secret-bunker-operator
  namespace: secret-bunker-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-bunker-operator
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
  name: secret-bunker-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: secret-bunker-operator
subjects:
  - kind: ServiceAccount
    name: secret-bunker-operator
    namespace: secret-bunker-system
```

`operator/deploy/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secret-bunker-operator
  namespace: secret-bunker-system
spec:
  replicas: 1
  strategy:
    type: Recreate          # one identity, one replica: never two at once
  selector:
    matchLabels:
      app: secret-bunker-operator
  template:
    metadata:
      labels:
        app: secret-bunker-operator
    spec:
      serviceAccountName: secret-bunker-operator
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        fsGroup: 65532
      containers:
        - name: operator
          image: secret-bunker-operator:latest   # replace with your registry
          args:
            - --bunker-id=$(BUNKER_ID)
          env:
            - name: BUNKER_ID
              value: "REPLACE_WITH_BUNKER_ENDPOINT_ID"
            # Optional direct dial (in-cluster or fixed-address bunker):
            # - name: BUNKER_ADDR
            #   value: "10.0.0.5:4433"
            - name: BUNKER_KEY_FILE
              value: /etc/secret-bunker/identity.key
            - name: BUNKER_MIRROR_PATH
              value: /var/lib/secret-bunker/replica.sqlite
          ports:
            - containerPort: 8080
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
          volumeMounts:
            - name: identity
              mountPath: /etc/secret-bunker
              readOnly: true
            - name: mirror
              mountPath: /var/lib/secret-bunker
      volumes:
        - name: identity
          secret:
            secretName: secret-bunker-operator-identity
            defaultMode: 0400
        - name: mirror
          emptyDir: {}      # full resync each start, by design
```

- [ ] **Step 2: Write operator/README.md**

Contents (write full prose, not this outline): what the operator does (one
paragraph, link to the spec); the `BunkerSecret` CRD with the spec's full example
YAML and the value/precedence/deletion semantics tables copied from the spec;
the identity provisioning runbook (generate key → `client add-identity` +
`client grant --perms r` per group → create the k8s Secret
`secret-bunker-operator-identity` from the key file → deploy); the rotation
runbook (new identity, register+grant, update Secret, restart, revoke old —
noting revocation auto-rotates group DEKs); config flag table; metrics table;
conditions/reasons table; the staleness/freeze semantics (access loss never
deletes); a commented ServiceMonitor example; AGPL notice.

- [ ] **Step 3: Add a section to the root README.md**

After the existing replica section, add ~10 lines: "Kubernetes operator" —
what it is, `kubectl apply -f operator/deploy/`, one `BunkerSecret` example,
link to `operator/README.md`.

- [ ] **Step 4: Validate manifests**

Run: `cargo run -p secret-bunker-operator --bin crdgen | diff - operator/deploy/crd.yaml`
Expected: no diff (regenerate if the CRD changed since Task 2).

If `kubectl` is available (`which kubectl`), also run
`kubectl apply --dry-run=client -f operator/deploy/` and expect all four docs to
validate; if not available, note that the kind CI job covers it.

- [ ] **Step 5: Commit**

```bash
git add operator/deploy operator/README.md README.md
git commit -m "docs: deploy manifests, operator README, provisioning runbook"
```

---

### Task 12: Flake package + image, CI kind job

**Files:**
- Modify: `flake.nix` (packages output), `.github/workflows/ci.yml` (workflow_dispatch + e2e-kind job)

**Interfaces:**
- Consumes: the operator crate; deploy manifests.
- Produces: `nix build .#operator` (any system), `nix build .#operator-image` (Linux), manual CI smoke job.

- [ ] **Step 1: Add packages to flake.nix**

Inside the existing `outputs = { self, nixpkgs, systems }:` attrset, alongside
`devShells`, add (matching the existing `eachSystem` style):

```nix
      packages = eachSystem (system: pkgs:
        let
          operator = pkgs.rustPlatform.buildRustPackage {
            pname = "secret-bunker-operator";
            version = "0.1.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            buildAndTestSubdir = "operator";
          };
        in
        {
          inherit operator;
        }
        // nixpkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          operator-image = pkgs.dockerTools.buildLayeredImage {
            name = "secret-bunker-operator";
            tag = "latest";
            contents = [ pkgs.dockerTools.caCertificates ];
            config.Entrypoint = [ "${operator}/bin/operator" ];
          };
        });
```

Also append `kind kubectl` to the devShell `packages` list (local e2e tooling).

- [ ] **Step 2: Verify the flake evaluates and the package builds**

Run: `nix flake show 2>&1 | head -30`
Expected: `packages.<system>.operator` listed (operator-image only on Linux systems).

Run: `nix build .#operator --print-build-logs` (this compiles the workspace in the
nix sandbox — slow the first time)
Expected: `result/bin/operator` exists. Run `./result/bin/operator --help` — usage
prints. Remove the `result` symlink afterwards (`rm result`) per the
no-stray-binaries rule.

- [ ] **Step 3: Add the manual kind smoke job to CI**

In `.github/workflows/ci.yml`, extend `on:` with `workflow_dispatch:` and append:

```yaml
  e2e-kind:
    # Manual-only heavyweight smoke test: run from the Actions tab.
    if: github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - uses: DeterminateSystems/nix-installer-action@v16

      - name: Build operator container image
        run: nix build .#operator-image

      - uses: helm/kind-action@v1

      - name: Load operator image into kind
        run: |
          docker load < result
          kind load docker-image secret-bunker-operator:latest --name chart-testing

      - name: Deploy CRD + operator
        run: |
          kubectl create secret generic secret-bunker-operator-identity \
            --namespace default --from-literal=identity.key=placeholder || true
          kubectl apply -f operator/deploy/crd.yaml
          kubectl get crd bunkersecrets.bunker.fables-for-robots.ch
```

(The smoke job validates image build + CRD registration; a full bunker-in-cluster
flow is future work and the job says so in a comment.)

- [ ] **Step 4: Commit**

```bash
git add flake.nix .github/workflows/ci.yml
git commit -m "ci: nix package + container image for the operator, manual kind smoke job"
```

---

### Task 13: Full verification pass

**Files:** none new.

- [ ] **Step 1: Full workspace check**

Run, in order, expecting every one clean/green:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`cargo fmt --all --check` failing on plan-authored code: run `cargo fmt --all` and
re-check. Investigate and fix any clippy or test failure — do not allow/ignore
lints without a comment justifying each.

- [ ] **Step 2: Re-generate and diff the CRD**

Run: `cargo run -p secret-bunker-operator --bin crdgen | diff - operator/deploy/crd.yaml`
Expected: empty diff.

- [ ] **Step 3: Commit any fixups**

```bash
git add -A && git commit -m "chore: fmt/clippy fixups from verification pass" || echo "nothing to fix"
```

---

### Task 14: Pull request

- [ ] **Step 1: Push the branch**

```bash
git push -u origin k8s-operator
```

- [ ] **Step 2: Open the PR against main**

```bash
gh pr create --base main --title "Kubernetes operator: sync bunker secrets to k8s Secrets" --body "$(cat <<'EOF'
Implements the approved design in docs/superpowers/specs/2026-08-11-k8s-operator-design.md.

- New workspace member `operator/`: `secret-bunker-operator` embedding the Replica engine
- `BunkerSecret` CRD (bunker.fables-for-robots.ch/v1alpha1): data / dataFrom (group fan-out, JSON extract), JSON Pointer properties, rewrites; one CR → one Secret
- Push-driven sync: ReplicaEvents → targeted reconciles; Lagged → reconcile-all; global resync backstop
- Safety: content-hash change detection (ABA-proof), freeze-on-access-loss (never cascades), deletionPolicy Retain/Delete via finalizer, conflict refusal on unowned Secrets, AwaitingSync gate
- Observability: Ready conditions with typed reasons, /healthz /readyz, Prometheus metrics
- Packaging: deploy manifests, nix package + dockerTools image, CI workspace flags + manual kind smoke job

Test plan: unit tests (render pipeline, CRD serde, metrics), integration tests against an in-process bunker + embedded replica with a scripted kube API mock (apply/skip/conflict/revocation-freeze/cleanup policies).

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01WXiEfkF4cZWqrbHdRp9Tgq
EOF
)"
```

- [ ] **Step 3: Verify PR CI is green**

Run: `gh pr checks --watch` (or poll `gh pr checks`)
Expected: test + audit jobs pass. Fix and push if not.

---

## Plan self-review (completed by the plan author)

- **Spec coverage:** CRD schema/semantics → Tasks 2–4; reconcile flow + decision
  table → Task 8; deletion/access-loss → Tasks 8–9; event bridge + Lagged +
  staleness → Task 7; readiness gate + /readyz → Tasks 5, 8, 10; metrics → Task 5
  (names verbatim from spec); manifests + RBAC + runbook → Task 11; nix/CI →
  Task 12; PR → Task 14. Spec's "upstream asks" section is documentation only —
  no task needed. Warning k8s Events on failure-reason transitions →
  `publish_warning_on_transition` in Task 8 (transition-only, publish failures
  non-fatal), RBAC covers core + events.k8s.io event writes. If the
  `Recorder`/`Event` field names differ in kube 4.2 (`publish(&Event, &ObjectReference)`
  is from recent kube memory, not the online verification pass), consult
  docs.rs/kube/4.2.0/kube/runtime/events and adapt — the contract is the
  transition-only Warning, not the exact API spelling.
- **Placeholder scan:** every code step contains complete code; the two
  "adjust if the API drifts" notes (prometheus protobuf accessors, revocation
  wire call) each name the exact file to consult.
- **Type consistency:** interfaces block at the top is the single source of
  truth; task-local code was written against it.
