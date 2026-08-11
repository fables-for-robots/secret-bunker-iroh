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
    if encoder
        .encode(&s.metrics.registry.gather(), &mut buf)
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, String::new()).into_response();
    }
    ([("content-type", "text/plain; version=0.0.4")], buf).into_response()
}
