# secret-bunker-operator Helm chart

Installs the [secret-bunker-iroh Kubernetes operator](../../operator/README.md):
syncs bunker secrets into native Kubernetes `Secret`s, push-driven.

```sh
helm install bunker oci://ghcr.io/fables-for-robots/charts/secret-bunker-operator \
  --namespace secret-bunker-system --create-namespace \
  --set bunker.id=<64-char hex EndpointId>
```

Images: `ghcr.io/fables-for-robots/secret-bunker-operator` (amd64+arm64).
The chart's `appVersion` pins the image built from the same tag; `image.tag`
overrides.

## Identity

Managed by default: first boot generates an iroh key into
`identity.secretName` (annotation `bunker.fables-for-robots.ch/endpoint-id`
carries the id to grant); restarts reuse it. Set `identity.existingSecret`
for bring-your-own-key (mounted read-only, `--key-file`; nothing generated).
The private key never passes through Helm values in either mode.
`identity.secretName` is fixed per values, not per release, so run at most
one release per namespace — or override `identity.secretName` per release —
otherwise two releases in one namespace would silently share one iroh
identity, which the operator does not support.

## CRD lifecycle

`crds/` installs the `BunkerSecret` CRD on first install. Helm never
upgrades or deletes it (deliberate: uninstall must not cascade-delete your
synced Secrets). Before `helm upgrade`, apply CRD changes manually:

```sh
kubectl apply -f https://raw.githubusercontent.com/fables-for-robots/secret-bunker-iroh/main/operator/deploy/crd.yaml
```

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
