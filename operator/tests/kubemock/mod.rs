//! Scripted mock of the kube apiserver over tower-test, kube 4.x style.
#![allow(dead_code)]
#![allow(clippy::type_complexity)]

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
    let (mock_service, mut handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
    let client = kube::Client::new(mock_service, "default");
    let join = tokio::spawn(async move {
        for (i, exp) in script.into_iter().enumerate() {
            let (request, send) = handle.next_request().await.unwrap_or_else(|| {
                panic!(
                    "expectation {i}: no more API calls, wanted {} {}",
                    exp.method, exp.path_contains
                )
            });
            let path = request.uri().path().to_string();
            assert_eq!(
                request.method().as_str(),
                exp.method,
                "expectation {i} on {path}"
            );
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
