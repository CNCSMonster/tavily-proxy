pub mod handler;
pub mod service;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use std::sync::Arc;
use tavily_core::ProxyCore;

/// Maximum payload limit for upstream requests (1 MiB).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Build the standard axum Router for Tavily Proxy.
pub fn router(core: Arc<ProxyCore>) -> Router {
    Router::new()
        .route("/search", post(handler::handle_search))
        .route("/extract", post(handler::handle_extract))
        .route("/usage", get(handler::handle_usage))
        .route("/health", get(handler::handle_health))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(core)
}
