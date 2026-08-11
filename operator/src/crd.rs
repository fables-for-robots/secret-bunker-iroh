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

#[derive(Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DataFromEntry {
    /// Whole-group fan-out: each bunker secret name becomes a key.
    Group(GroupFrom),
    /// Explode one JSON-object-valued bunker secret into keys.
    Extract(ExtractFrom),
}

impl Serialize for DataFromEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            DataFromEntry::Group(g) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("group", g)?;
                map.end()
            }
            DataFromEntry::Extract(e) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("extract", e)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for DataFromEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct DataFromEntryVisitor;

        impl<'de> Visitor<'de> for DataFromEntryVisitor {
            type Value = DataFromEntry;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with single key 'group' or 'extract'")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                if let Some((key, value)) = map.next_entry::<String, serde_yaml::Value>()? {
                    let result = match key.as_str() {
                        "group" => {
                            let group = serde_yaml::from_value(value).map_err(de::Error::custom)?;
                            Ok(DataFromEntry::Group(group))
                        }
                        "extract" => {
                            let extract =
                                serde_yaml::from_value(value).map_err(de::Error::custom)?;
                            Ok(DataFromEntry::Extract(extract))
                        }
                        _ => Err(de::Error::unknown_field(&key, &["group", "extract"])),
                    }?;
                    // Ensure no additional keys exist
                    if let Some((extra_key, _)) = map.next_entry::<String, serde_yaml::Value>()? {
                        return Err(de::Error::custom(format!(
                            "dataFrom item has multiple keys; expected exactly one of 'group' or 'extract', found extra key '{}'",
                            extra_key
                        )));
                    }
                    Ok(result)
                } else {
                    Err(de::Error::missing_field("group or extract"))
                }
            }
        }

        deserializer.deserialize_map(DataFromEntryVisitor)
    }
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
        assert_eq!(
            spec.data[1].remote_ref.property.as_deref(),
            Some("/smtp/password")
        );
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
        cr.spec.target = Some(TargetSpec {
            name: Some("other".into()),
            r#type: None,
        });
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

    #[test]
    fn crd_schema_uses_lowercase_datfrom_property_names() {
        use kube::CustomResourceExt;
        let crd = BunkerSecret::crd();
        let yaml = serde_yaml::to_string(&crd).unwrap();
        // Verify that the schema properties use lowercase 'group' and 'extract', not PascalCase
        // This ensures CRs written per the spec won't be pruned by Kubernetes
        assert!(
            yaml.contains("group:") || yaml.contains("'group'"),
            "dataFrom schema should have lowercase 'group' property"
        );
        assert!(
            yaml.contains("extract:") || yaml.contains("'extract'"),
            "dataFrom schema should have lowercase 'extract' property"
        );
        // Make sure PascalCase variants don't appear
        assert!(
            !yaml.contains("Group:"),
            "dataFrom schema should not use PascalCase 'Group' property"
        );
        assert!(
            !yaml.contains("Extract:"),
            "dataFrom schema should not use PascalCase 'Extract' property"
        );
    }

    #[test]
    fn multi_key_datfrom_item_deserialize_fails() {
        let yaml = r#"
data: []
dataFrom:
  - group:
      name: prod
    extract:
      group: other
      name: config
"#;
        let result: Result<BunkerSecretSpec, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "dataFrom item with both 'group' and 'extract' keys should fail to deserialize"
        );
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("multiple keys") || err_msg.contains("extract"),
            "error message should indicate the issue with multiple keys: {}",
            err_msg
        );
    }
}
