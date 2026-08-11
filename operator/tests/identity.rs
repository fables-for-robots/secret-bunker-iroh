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
