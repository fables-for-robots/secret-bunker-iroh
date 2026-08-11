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
        data: Some(
            data.iter()
                .map(|(k, v)| (k.clone(), ByteString(v.clone())))
                .collect(),
        ),
        ..Default::default()
    }
}

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
