use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value;
use tracing::{Instrument, info, info_span};

use tavily_core::{ProxyCore, ProxyError};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// The caller's proxy key, or the error to return when it is missing.
///
/// Tavily's own wording on purpose: a client must not be able to tell this
/// service apart from the official API, nor probe which keys exist.
fn required_proxy_key(headers: &HeaderMap) -> Result<&str, ProxyError> {
    extract_bearer_token(headers)
        .ok_or_else(|| ProxyError::Unauthorized("Unauthorized: missing or invalid API key.".into()))
}

fn error_response(err: &ProxyError) -> Response {
    let (status, body) = err.client_response();
    let mut response = (
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
        Json(body),
    )
        .into_response();
    if let Some(retry_after) = err.client_retry_after()
        && let Ok(val) = retry_after.parse()
    {
        response
            .headers_mut()
            .insert(axum::http::header::RETRY_AFTER, val);
    }
    response
}

pub async fn handle_search(
    State(core): State<Arc<ProxyCore>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    proxy(core, headers, body, "/search").await
}

pub async fn handle_extract(
    State(core): State<Arc<ProxyCore>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    proxy(core, headers, body, "/extract").await
}

pub async fn handle_usage(State(core): State<Arc<ProxyCore>>, headers: HeaderMap) -> Response {
    let proxy_key = match required_proxy_key(&headers) {
        Ok(k) => k,
        Err(err) => return error_response(&err),
    };

    let usage = match core.auth.query_usage(proxy_key) {
        Some(u) => u,
        None => {
            return error_response(&ProxyError::Unauthorized(
                "Unauthorized: missing or invalid API key.".into(),
            ));
        }
    };

    let plan_name = match &usage.name {
        Some(name) => format!("Proxy ({name})"),
        None => "Proxy".to_string(),
    };

    let body = serde_json::json!({
        "key": {
            "usage": usage.used_requests,
            "limit": usage.max_requests_per_month,
            "search_usage": usage.used_requests,
            "crawl_usage": 0,
            "extract_usage": 0,
            "map_usage": 0,
            "research_usage": 0,
        },
        "account": {
            "current_plan": plan_name,
            "plan_usage": usage.used_requests,
            "plan_limit": usage.max_requests_per_month,
            "search_usage": usage.used_requests,
            "crawl_usage": 0,
            "extract_usage": 0,
            "map_usage": 0,
            "research_usage": 0,
            "paygo_usage": 0,
            "paygo_limit": serde_json::Value::Null,
        }
    });

    (StatusCode::OK, Json(body)).into_response()
}

pub async fn handle_health(State(core): State<Arc<ProxyCore>>) -> impl IntoResponse {
    use std::sync::atomic::Ordering::Relaxed;
    Json(serde_json::json!({
        "status": "ok",
        "stats": {
            "total_requests": core.stats.total_requests.load(Relaxed),
            "status_200": core.stats.status_200.load(Relaxed),
            "status_400_blocked": core.stats.status_400_blocked.load(Relaxed),
            "status_429": core.stats.status_429.load(Relaxed),
            "status_5xx": core.stats.status_5xx.load(Relaxed),
            "tavily_calls": core.stats.tavily_calls.load(Relaxed),
            "tavily_ms_total": core.stats.tavily_ms_total.load(Relaxed),
            "filter_calls": core.stats.filter_calls.load(Relaxed),
            "filter_ms_total": core.stats.filter_ms_total.load(Relaxed),
        }
    }))
}

/// Proxy one call, with the log lines to go with it.
///
/// Everything logged while handling this request — key rotation, filter verdicts,
/// upstream failures — happens inside one span, so the log stays readable per
/// request even when several are in flight. The span never includes the
/// credential: only the caller's configured name, or `-`.
async fn proxy(
    core: Arc<ProxyCore>,
    headers: HeaderMap,
    body: Value,
    endpoint: &'static str,
) -> Response {
    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let span = info_span!("request", id = request_id, endpoint);

    async move {
        let started = Instant::now();

        let outcome = match required_proxy_key(&headers) {
            Err(err) => Outcome::Rejected {
                err,
                key_name: None,
            },
            Ok(proxy_key) => {
                // Resolve the caller's name here for the access log. The core
                // authenticates again — it must not trust its caller — but that
                // check has no side effects, so the second one costs a lookup.
                match core.authenticate(proxy_key) {
                    Err(err) => Outcome::Rejected {
                        err,
                        key_name: None,
                    },
                    Ok(key_name) => {
                        let response = match endpoint {
                            "/search" => core.search(proxy_key, body).await,
                            _ => core.extract(proxy_key, body).await,
                        };
                        match response {
                            Ok(proxied) => Outcome::Proxied {
                                body: proxied.body,
                                timing: proxied.timing,
                                key_name,
                            },
                            Err(err) => Outcome::Rejected { err, key_name },
                        }
                    }
                }
            }
        };

        // One summary line per request: status and latency for the access log,
        // plus which client key it was, so usage can be counted per client.
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match outcome {
            Outcome::Proxied {
                body,
                timing,
                key_name,
            } => {
                info!(
                    status = 200,
                    elapsed_ms,
                    tavily_ms = timing.tavily_ms,
                    filter_input_ms = timing.filter_input_ms,
                    filter_output_ms = timing.filter_output_ms,
                    filter_calls = timing.filter_calls,
                    blocked_items = timing.blocked_items,
                    key = timing.upstream_key.as_deref().unwrap_or("-"),
                    key_name = key_name.as_deref().unwrap_or("-"),
                    "request served"
                );
                (StatusCode::OK, Json(body)).into_response()
            }
            Outcome::Rejected { err, key_name } => {
                let (status, body) = err.client_response();
                info!(
                    status,
                    elapsed_ms,
                    key_name = key_name.as_deref().unwrap_or("-"),
                    reason = %body["detail"]["error"].as_str().unwrap_or("-"),
                    "request rejected"
                );
                let mut response = (
                    StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                    Json(body),
                )
                    .into_response();
                if let Some(retry_after) = err.client_retry_after()
                    && let Ok(val) = retry_after.parse()
                {
                    response
                        .headers_mut()
                        .insert(axum::http::header::RETRY_AFTER, val);
                }
                response
            }
        }
    }
    .instrument(span)
    .await
}

/// The two ways a proxied call can end. Kept apart so the summary line is written
/// once, after whatever the inner calls logged.
enum Outcome {
    Proxied {
        body: Value,
        timing: tavily_core::RequestTiming,
        key_name: Option<String>,
    },
    Rejected {
        err: ProxyError,
        key_name: Option<String>,
    },
}
