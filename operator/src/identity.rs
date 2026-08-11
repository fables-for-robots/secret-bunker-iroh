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
use kube::Client;
use kube::api::{Api, ObjectMeta, PostParams};
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
    match api
        .create(&PostParams::default(), &identity_secret(name, &key))
        .await
    {
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
            let existing = api.get(name).await.with_context(|| {
                format!("re-getting identity Secret {name} after create conflict")
            })?;
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
