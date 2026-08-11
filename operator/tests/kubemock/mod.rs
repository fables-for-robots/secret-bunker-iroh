//! Scripted mock of the kube apiserver over tower-test, kube 4.x style.
#![allow(dead_code)]
#![allow(clippy::type_complexity)]

use std::time::Duration;

use http::{Request, Response};
use kube::client::Body;

/// A missing call must fail the test fast, not hang the harness forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Expectation {
    pub method: &'static str,
    pub path_contains: String,
    pub status: u16,
    pub respond: serde_json::Value,
    /// If set, the request body (JSON) is passed to this check.
    pub body_check: Option<Box<dyn Fn(&serde_json::Value) + Send>>,
    /// Substrings that must all appear in the request's raw query string
    /// (e.g. `"force=true"`, `"fieldManager=secret-bunker-operator"`).
    pub query_contains: Vec<String>,
    /// If set, the request's `Content-Type` header must equal this exactly.
    pub content_type: Option<String>,
}

impl Expectation {
    /// Assert the query string contains `s` as a substring. Chainable, may
    /// be called more than once to require several substrings.
    pub fn with_query_contains(mut self, s: &str) -> Self {
        self.query_contains.push(s.to_string());
        self
    }

    /// Assert the request's `Content-Type` header equals `ct` exactly.
    pub fn with_content_type(mut self, ct: &str) -> Self {
        self.content_type = Some(ct.to_string());
        self
    }
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
        query_contains: Vec::new(),
        content_type: None,
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
        query_contains: Vec::new(),
        content_type: None,
    }
}

/// Returns a kube Client wired to the script and a JoinHandle that panics on
/// deviation. Await the handle after the code under test finishes.
///
/// Each expected call is awaited under a bounded timeout: if the code under
/// test never makes a call the script expects, the mock fails the test with
/// a clear panic message instead of hanging `next_request()` (and therefore
/// the test's `join.await`) forever.
pub fn scripted(script: Vec<Expectation>) -> (kube::Client, tokio::task::JoinHandle<()>) {
    let (mock_service, mut handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
    let client = kube::Client::new(mock_service, "default");
    let join = tokio::spawn(async move {
        for (i, exp) in script.into_iter().enumerate() {
            let (request, send) = tokio::time::timeout(REQUEST_TIMEOUT, handle.next_request())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "expectation {i}: timed out after {REQUEST_TIMEOUT:?} waiting for {} {} — the call was never made",
                        exp.method, exp.path_contains
                    )
                })
                .unwrap_or_else(|| {
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
            if !exp.query_contains.is_empty() {
                let query = request.uri().query().unwrap_or("").to_string();
                for q in &exp.query_contains {
                    assert!(
                        query.contains(q.as_str()),
                        "expectation {i}: query {query:?} does not contain {q:?}"
                    );
                }
            }
            if let Some(ct) = &exp.content_type {
                let actual = request
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                assert_eq!(
                    &actual, ct,
                    "expectation {i}: content-type {actual:?} != {ct:?}"
                );
            }
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
