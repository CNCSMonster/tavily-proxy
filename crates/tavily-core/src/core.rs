use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tracing::{error, info, warn};

use crate::auth::{Auth, AuthResult};
use crate::config::Config;
use crate::egress::{DirectEgress, Egress, EgressOutcome};
use crate::filter::{
    ChainResult, ChainVerdict, FilterChain, OutputBlockMode, ReportFiltered, ScanUnit, Stage,
};
use crate::key_pool::KeyPool;
use crate::redact::redact_secrets;

/// How long one request will wait out an upstream 429 before giving up on
/// waiting and passing the 429 through. The cap keeps the caller from being
/// held hostage by a rate limit: past a few seconds its own timeout and backoff
/// policy are better judges of how long to wait than this service is.
const MAX_SAME_KEY_429_WAIT_SECS: u64 = 5;

/// A TLS handshake to Tavily can die before a response is ever produced (observed
/// in this environment: DNS resolves `api.tavily.com` through a transparent
/// proxy, and the odd handshake comes back as `SSL_ERROR_SYSCALL` while the very
/// next attempt on the same client succeeds). A handshake that never completed
/// cannot have reached Tavily, so retrying it costs nothing upstream.
const CONNECT_ATTEMPTS: u32 = 3;
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_millis(200);

const DEFAULT_UPSTREAM_BASE: &str = "https://api.tavily.com";

/// Which upstream endpoint a response came from.
///
/// The two report a removed entry differently: `/extract` has an official field
/// for "this URL produced nothing", `/search` has no equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamEndpoint {
    Search,
    Extract,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct ServerStats {
    pub total_requests: AtomicU64,
    pub status_200: AtomicU64,
    pub status_400_blocked: AtomicU64,
    pub status_429: AtomicU64,
    pub status_5xx: AtomicU64,
    pub tavily_calls: AtomicU64,
    pub tavily_ms_total: AtomicU64,
    pub filter_calls: AtomicU64,
    pub filter_ms_total: AtomicU64,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RequestTiming {
    pub total_ms: u64,
    pub tavily_ms: u64,
    pub filter_input_ms: u64,
    pub filter_output_ms: u64,
    pub filter_calls: u32,
    pub blocked_items: u32,
    pub upstream_key: Option<String>,
    pub egress: Option<String>,
}

pub struct ProxyCore {
    pub key_pool: KeyPool,
    pub auth: Arc<Auth>,
    /// The default chain — every enabled rule — for tokens without a route.
    pub filters: Arc<FilterChain>,
    /// Chains selected per token via `[[proxy_keys]] filter = [...]` (ISSUE-0006).
    key_routes: HashMap<String, Arc<FilterChain>>,
    /// One `(label, rules)` pair per explicit route, for the startup log.
    pub filter_routes: Vec<(String, String)>,
    pub egress: Arc<dyn Egress>,
    pub stats: Arc<ServerStats>,
    upstream_base: String,
}

#[derive(Debug)]
pub enum ProxyError {
    Unauthorized(String),
    QuotaExceeded {
        key_name: Option<String>,
    },
    AllKeysExhausted,
    InputBlocked {
        filter: String,
        /// The filter's own message; forwarded to the caller as-is.
        message: String,
        confidence: f64,
    },
    OutputBlocked {
        filter: String,
        message: String,
        confidence: f64,
    },
    SafetyCheckUnavailable {
        filter: String,
        stage: String,
        detail: String,
    },
    /// Tavily itself refused. `status` and `message` are passed through so the
    /// caller sees what Tavily would have told it directly.
    UpstreamError {
        status: u16,
        message: Option<String>,
    },
    /// Tavily rate-limited the pooled key (429) and waiting it out would have
    /// held the caller too long. The caller sees Tavily's own 429, and the
    /// upstream `Retry-After` travels with it, so backing off is exactly what
    /// the caller would do against the official API.
    RateLimited {
        message: Option<String>,
        /// Upstream's `Retry-After` header value, forwarded verbatim — even an
        /// unparseable one, since fidelity to the official reply beats
        /// re-encoding it.
        retry_after: Option<String>,
    },
    NetworkError(String),
    ParseError(String),
}

/// Tavily's one error shape: `{"detail":{"error":"..."}}`.
///
/// Every client-facing message goes through here, and here every
/// credential-shaped token is scrubbed: one chokepoint at the exit, so no caller
/// of this function has to remember to redact.
fn detail_error(message: impl Into<String>) -> Value {
    json!({"detail": {"error": redact_secrets(&message.into())}})
}

impl ProxyError {
    /// Status and JSON body the *client* is allowed to see.
    ///
    /// The whole client-facing surface mimics Tavily's own replies: this exact
    /// envelope, and a status code the caller already knows how to handle. Two
    /// consequences are deliberate:
    ///
    /// * no field of ours ever appears (`retryable`, `filter`, `stage`, ...) —
    ///   a client that validates against Tavily's schema keeps working;
    /// * upstream text reaches the client only through [`detail_message`], which
    ///   extracts a single string out of Tavily's envelope and drops everything
    ///   else. Tavily's 422 echoes the submitted `api_key` back inside a
    ///   validation *array*, so a whole-body pass-through would hand an attacker
    ///   the pooled credential on request.
    pub fn client_response(&self) -> (u16, Value) {
        match self {
            ProxyError::Unauthorized(message) => (401, detail_error(message.clone())),
            ProxyError::QuotaExceeded { key_name } => {
                let suffix = key_name
                    .as_deref()
                    .map(|name| format!(" for proxy key {name:?}"))
                    .unwrap_or_default();
                (
                    429,
                    detail_error(format!("This proxy key is over its monthly quota{suffix}.")),
                )
            }
            ProxyError::AllKeysExhausted => {
                (503, detail_error("No Tavily API key is currently usable."))
            }
            // The filter's message is quoted, not rewritten: what the caller is
            // told about a block is the checker's own wording, so a checker can be
            // as specific or as vague as it likes.
            ProxyError::InputBlocked { message, .. } => (
                400,
                detail_error(format!(
                    "Request blocked by the content safety filter: {message}"
                )),
            ),
            ProxyError::OutputBlocked { message, .. } => (
                403,
                detail_error(format!(
                    "Response blocked by the content safety filter: {message}"
                )),
            ),
            ProxyError::SafetyCheckUnavailable { filter, stage, .. } => (
                503,
                detail_error(format!(
                    "Content safety check unavailable ({filter} at the {stage} stage); refusing to \
                     serve unverified content. Retry shortly."
                )),
            ),
            ProxyError::UpstreamError { status, message } => (
                *status,
                // The one upstream string that is passed through on purpose (as
                // in `RateLimited`): the caller should see exactly what Tavily
                // would have told it.
                detail_error(message.as_deref().unwrap_or("Tavily returned an error.")),
            ),
            ProxyError::RateLimited { message, .. } => (
                429,
                // Same pass-through as `UpstreamError`, for the same reason.
                detail_error(message.as_deref().unwrap_or("Tavily returned an error.")),
            ),
            ProxyError::NetworkError(_) => {
                (502, detail_error("Failed to reach Tavily. Retry shortly."))
            }
            ProxyError::ParseError(_) => (502, detail_error("Failed to parse Tavily's response.")),
        }
    }

    /// The upstream `Retry-After` to hand the caller, if any.
    ///
    /// Only the 429 pass-through can carry one: every other client-facing error
    /// is either ours or a refusal the caller has no way to wait out, and
    /// inventing a `Retry-After` there would be a lie about the upstream.
    pub fn client_retry_after(&self) -> Option<&str> {
        match self {
            ProxyError::RateLimited { retry_after, .. } => retry_after.as_deref(),
            _ => None,
        }
    }
}

pub struct ProxyResponse {
    pub body: Value,
    pub timing: RequestTiming,
}

impl std::fmt::Debug for ProxyResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The body is an upstream payload; keep it out of `{:?}` output so a
        // stray debug print cannot dump search results into a log.
        f.debug_struct("ProxyResponse").finish_non_exhaustive()
    }
}

impl ProxyCore {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let filters = Arc::new(FilterChain::from_config(config.filter.as_ref())?);
        let (key_routes, filter_routes) = build_filter_routes(config)?;
        let quota_path = config.resolve_quota_path();
        let retention_days = config.retention_days();
        let max_file_size_bytes = config.max_file_size_bytes();
        Ok(Self {
            key_pool: KeyPool::from_config(config),
            auth: Arc::new(Auth::new_with_options(
                &config.proxy_keys,
                quota_path,
                retention_days,
                max_file_size_bytes,
            )),
            filters,
            key_routes,
            filter_routes,
            egress: Arc::new(DirectEgress::new()?),
            stats: Arc::new(ServerStats::default()),
            upstream_base: DEFAULT_UPSTREAM_BASE.to_string(),
        })
    }

    pub fn with_egress(mut self, egress: Arc<dyn Egress>) -> Self {
        self.egress = egress;
        self
    }

    pub fn with_filter_chain(mut self, filters: FilterChain) -> Self {
        self.filters = Arc::new(filters);
        self
    }

    /// The chain this caller's token selects: its own route when it has one,
    /// otherwise the global chain (ISSUE-0006).
    fn chain_for(&self, proxy_key: &str) -> &FilterChain {
        self.key_routes
            .get(proxy_key)
            .map(Arc::as_ref)
            .unwrap_or(&self.filters)
    }

    /// Point the core at a different Tavily-compatible base URL (tests use a
    /// local stub to observe exactly what leaves the process).
    pub fn with_upstream_base(mut self, base: impl Into<String>) -> Self {
        self.upstream_base = base.into().trim_end_matches('/').to_string();
        self
    }

    pub fn authenticate(&self, proxy_key: &str) -> Result<Option<String>, ProxyError> {
        match self.auth.authenticate(proxy_key) {
            AuthResult::Ok { name } => Ok(name),
            // Same wording Tavily uses, so a client cannot tell this service from
            // the real thing — and cannot probe which keys exist.
            AuthResult::InvalidKey => Err(ProxyError::Unauthorized(
                "Unauthorized: missing or invalid API key.".into(),
            )),
            AuthResult::QuotaExceeded { name } => Err(ProxyError::QuotaExceeded { key_name: name }),
        }
    }

    pub async fn search(&self, proxy_key: &str, body: Value) -> Result<ProxyResponse, ProxyError> {
        self.proxy_request(proxy_key, body, "/search", UpstreamEndpoint::Search)
            .await
    }

    pub async fn extract(&self, proxy_key: &str, body: Value) -> Result<ProxyResponse, ProxyError> {
        self.proxy_request(proxy_key, body, "/extract", UpstreamEndpoint::Extract)
            .await
    }

    async fn proxy_request(
        &self,
        proxy_key: &str,
        mut body: Value,
        upstream_path: &str,
        endpoint: UpstreamEndpoint,
    ) -> Result<ProxyResponse, ProxyError> {
        let start_total = Instant::now();
        let mut timing = RequestTiming {
            egress: Some(self.egress.name().to_string()),
            ..Default::default()
        };

        let res = self
            .proxy_request_inner(proxy_key, &mut body, upstream_path, endpoint, &mut timing)
            .await;

        timing.total_ms = start_total.elapsed().as_millis() as u64;

        match &res {
            Ok(_) => {
                self.record_metrics_event(&timing, 200, upstream_path, None);
            }
            Err(err) => {
                let (status, _) = err.client_response();
                self.record_metrics_event(
                    &timing,
                    status,
                    upstream_path,
                    Some(&format!("{err:?}")),
                );
            }
        }

        res
    }

    async fn proxy_request_inner(
        &self,
        proxy_key: &str,
        body: &mut Value,
        upstream_path: &str,
        endpoint: UpstreamEndpoint,
        timing: &mut RequestTiming,
    ) -> Result<ProxyResponse, ProxyError> {
        let _key_name = self.authenticate(proxy_key)?;
        let chain = self.chain_for(proxy_key);
        let mut guard = self
            .auth
            .acquire_slot(proxy_key, Duration::from_secs(MAX_SAME_KEY_429_WAIT_SECS))
            .await
            .map_err(|e| match e {
                crate::auth::SlotAcquireResult::InvalidKey => {
                    ProxyError::Unauthorized("Unauthorized: missing or invalid API key.".into())
                }
                crate::auth::SlotAcquireResult::QuotaExceeded { name } => {
                    ProxyError::QuotaExceeded { key_name: name }
                }
                crate::auth::SlotAcquireResult::ConcurrencyLimitReached { name: _ } => {
                    ProxyError::RateLimited {
                        message: Some("Proxy key concurrency limit reached.".into()),
                        retry_after: Some("1".into()),
                    }
                }
                crate::auth::SlotAcquireResult::RateLimitExceeded {
                    name: _,
                    wait_needed,
                } => ProxyError::RateLimited {
                    message: Some("Proxy key rate limit exceeded.".into()),
                    retry_after: Some(format!("{}", wait_needed.as_secs().max(1))),
                },
                crate::auth::SlotAcquireResult::Ok => unreachable!(),
            })?;

        let start_in = Instant::now();
        match self.check_input(body, chain).await {
            Ok(in_calls) => {
                timing.filter_input_ms = start_in.elapsed().as_millis() as u64;
                timing.filter_calls += in_calls;
            }
            Err(e) => {
                timing.filter_input_ms = start_in.elapsed().as_millis() as u64;
                timing.filter_calls += 1;
                return Err(e);
            }
        }

        let upstream_url = format!("{}{upstream_path}", self.upstream_base);

        let max_attempts = self.key_pool.total_keys().max(1);

        for _ in 0..max_attempts {
            let tavily_key = match self
                .key_pool
                .acquire(Duration::from_secs(MAX_SAME_KEY_429_WAIT_SECS))
                .await
            {
                crate::key_pool::KeyAcquireResult::Acquired(key) => key,
                crate::key_pool::KeyAcquireResult::AllRateLimited { min_wait_needed } => {
                    warn!(
                        wait_secs = min_wait_needed.as_secs_f64(),
                        "upstream rate budget exhausted"
                    );
                    return Err(ProxyError::RateLimited {
                        message: Some("Upstream rate budget is exhausted. Retry shortly.".into()),
                        retry_after: Some(format!("{}", min_wait_needed.as_secs().max(1))),
                    });
                }
                crate::key_pool::KeyAcquireResult::NoKeys => break,
            };

            timing.upstream_key = Some(redact_secrets(&tavily_key));

            if let Some(obj) = body.as_object_mut() {
                obj.remove("api_key");
                obj.insert("api_key".into(), Value::String(tavily_key.clone()));
            }

            let start_tavily = Instant::now();
            let response = self
                .send_to_tavily(&upstream_url, body)
                .await
                .map_err(|e| {
                    timing.tavily_ms += start_tavily.elapsed().as_millis() as u64;
                    let outcome = EgressOutcome {
                        status_code: None,
                        latency: start_tavily.elapsed(),
                        is_delivery_error: true,
                        retry_after: None,
                    };
                    self.egress.record_outcome(&outcome);
                    let detail = redact_secrets(&format!("{e:?}"));
                    error!(error = %detail, "failed to reach tavily");
                    ProxyError::NetworkError(detail)
                })?;
            timing.tavily_ms += start_tavily.elapsed().as_millis() as u64;

            let status = response.status();
            let status_code = status.as_u16();

            let outcome = EgressOutcome {
                status_code: Some(status_code),
                latency: Duration::from_millis(timing.tavily_ms),
                is_delivery_error: false,
                retry_after: None,
            };
            self.egress.record_outcome(&outcome);

            // 401: Tavily rejects the pooled credential itself (invalid or revoked).
            // Terminal verdict on the key -> mark revoked and retry the next key.
            if status_code == 401 {
                let error_body = response.text().await.unwrap_or_default();
                warn!(
                    %status,
                    error_body = %redact_secrets(&error_body),
                    "tavily rejected the pooled key (401); removing it from rotation"
                );
                self.key_pool.mark_revoked_current();
                continue;
            }

            // 429: Tavily rate-limited the pooled key.
            // NEVER rotate to another key on 429! Rate limits are IP-scoped and cross-key retries cause request storms.
            if status_code == 429 {
                let retry_after_header = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let retry_after_secs = retry_after_header
                    .as_deref()
                    .and_then(|s| s.parse::<u64>().ok());
                let error_body = response.text().await.unwrap_or_default();

                warn!(
                    %status,
                    error_body = %redact_secrets(&error_body),
                    retry_after_secs = retry_after_secs.unwrap_or(0),
                    "tavily key rate-limited (429)"
                );

                if let Some(wait_secs) = retry_after_secs
                    && wait_secs <= MAX_SAME_KEY_429_WAIT_SECS
                {
                    info!(wait_secs, "waiting out upstream 429 on same key");
                    tokio::time::sleep(Duration::from_secs(wait_secs)).await;

                    let start_retry = Instant::now();
                    let retry_resp =
                        self.send_to_tavily(&upstream_url, body)
                            .await
                            .map_err(|e| {
                                timing.tavily_ms += start_retry.elapsed().as_millis() as u64;
                                let detail = redact_secrets(&format!("{e:?}"));
                                error!(error = %detail, "failed to reach tavily on 429 retry");
                                ProxyError::NetworkError(detail)
                            })?;
                    timing.tavily_ms += start_retry.elapsed().as_millis() as u64;

                    let retry_status = retry_resp.status();
                    let retry_code = retry_status.as_u16();

                    if retry_status.is_success() {
                        self.key_pool.record_usage();
                        guard.commit();
                        let mut result: Value = retry_resp.json().await.map_err(|e| {
                            let message = redact_secrets(&e.to_string());
                            error!(error = %message, "failed to parse tavily response");
                            ProxyError::ParseError(message)
                        })?;

                        let start_out = Instant::now();
                        let (removed, out_calls) = match self
                            .apply_output_filters(&mut result, endpoint, chain)
                            .await
                        {
                            Ok(pair) => pair,
                            Err(e) => {
                                timing.filter_output_ms += start_out.elapsed().as_millis() as u64;
                                timing.filter_calls += 1;
                                return Err(e);
                            }
                        };
                        timing.filter_output_ms += start_out.elapsed().as_millis() as u64;
                        timing.filter_calls += out_calls;
                        timing.blocked_items += removed as u32;

                        info!("request proxied successfully after 429 retry");
                        return Ok(ProxyResponse {
                            body: result,
                            timing: timing.clone(),
                        });
                    }

                    let retry_body = retry_resp.text().await.unwrap_or_default();
                    if retry_code == 429 {
                        return Err(ProxyError::RateLimited {
                            message: detail_message(&retry_body),
                            retry_after: retry_after_header,
                        });
                    }
                    if retry_code == 401 {
                        self.key_pool.mark_revoked_current();
                        continue;
                    }
                    if matches!(retry_code, 432 | 433) {
                        self.key_pool.mark_exhausted_current();
                        continue;
                    }
                    if (400..=499).contains(&retry_code) {
                        guard.commit();
                    }
                    return Err(ProxyError::UpstreamError {
                        status: retry_code,
                        message: detail_message(&retry_body),
                    });
                }

                // If wait > 5s or unparseable: pass 429 and Retry-After straight to caller.
                return Err(ProxyError::RateLimited {
                    message: detail_message(&error_body),
                    retry_after: retry_after_header,
                });
            }

            // 432/433: monthly quota or PAYGO cap — exhausted for this cycle
            if matches!(status_code, 432 | 433) {
                let error_body = response.text().await.unwrap_or_default();
                warn!(
                    %status,
                    error_body = %redact_secrets(&error_body),
                    "tavily key quota exhausted (432/433)"
                );
                self.key_pool.mark_exhausted_current();
                continue;
            }

            if !status.is_success() {
                let error_body = response.text().await.unwrap_or_default();
                error!(
                    %status,
                    error_body = %redact_secrets(&error_body),
                    "tavily upstream error"
                );
                if (400..=499).contains(&status_code) {
                    guard.commit();
                }
                return Err(ProxyError::UpstreamError {
                    status: status_code,
                    message: detail_message(&error_body),
                });
            }

            self.key_pool.record_usage();
            guard.commit();

            let mut result: Value = response.json().await.map_err(|e| {
                let message = redact_secrets(&e.to_string());
                error!(error = %message, "failed to parse tavily response");
                ProxyError::ParseError(message)
            })?;

            let start_out = Instant::now();
            let (removed, out_calls) = match self
                .apply_output_filters(&mut result, endpoint, chain)
                .await
            {
                Ok(pair) => pair,
                Err(e) => {
                    timing.filter_output_ms += start_out.elapsed().as_millis() as u64;
                    timing.filter_calls += 1;
                    return Err(e);
                }
            };
            timing.filter_output_ms += start_out.elapsed().as_millis() as u64;
            timing.filter_calls += out_calls;
            timing.blocked_items += removed as u32;

            info!("request proxied successfully");
            return Ok(ProxyResponse {
                body: result,
                timing: timing.clone(),
            });
        }

        Err(ProxyError::AllKeysExhausted)
    }

    pub fn record_metrics_event(
        &self,
        timing: &RequestTiming,
        status: u16,
        endpoint: &str,
        error_msg: Option<&str>,
    ) {
        self.stats.total_requests.fetch_add(1, Relaxed);
        match status {
            200 => {
                self.stats.status_200.fetch_add(1, Relaxed);
            }
            400 => {
                self.stats.status_400_blocked.fetch_add(1, Relaxed);
            }
            429 => {
                self.stats.status_429.fetch_add(1, Relaxed);
            }
            500..=599 => {
                self.stats.status_5xx.fetch_add(1, Relaxed);
            }
            _ => {}
        }
        self.stats
            .tavily_ms_total
            .fetch_add(timing.tavily_ms, Relaxed);
        self.stats
            .filter_calls
            .fetch_add(timing.filter_calls as u64, Relaxed);
        let filter_total_ms = timing.filter_input_ms + timing.filter_output_ms;
        self.stats
            .filter_ms_total
            .fetch_add(filter_total_ms, Relaxed);

        info!(
            target: "metrics",
            status,
            endpoint,
            total_ms = timing.total_ms,
            tavily_ms = timing.tavily_ms,
            filter_input_ms = timing.filter_input_ms,
            filter_output_ms = timing.filter_output_ms,
            filter_calls = timing.filter_calls,
            blocked_items = timing.blocked_items,
            key = timing.upstream_key.as_deref().unwrap_or("-"),
            error = error_msg.unwrap_or("none"),
            "METRIC_LOG"
        );

        let metrics_file =
            std::env::var("METRICS_FILE").unwrap_or_else(|_| "target/metrics.jsonl".into());
        if !metrics_file.is_empty() {
            use std::io::Write;
            if let Some(parent) = std::path::Path::new(&metrics_file).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&metrics_file)
            {
                let record = metrics_record(timing, status, endpoint, error_msg);
                let _ = writeln!(file, "{record}");
            }
        }
    }

    /// POST to Tavily, giving a connection-level failure another chance.
    ///
    /// Only failures that happened *before* a response can exist are retried
    /// ([`never_reached_tavily`]): a request that Tavily may already have
    /// processed is never sent twice, so a retry can neither double-bill a search
    /// nor double-consume a key's quota. HTTP responses — including Tavily's
    /// refusals — go back to the caller untouched, and the key rotation above is
    /// what deals with those.
    async fn send_to_tavily(
        &self,
        url: &str,
        body: &Value,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut attempt = 1;

        loop {
            match self.egress.send_upstream(url, body).await {
                Ok(response) => return Ok(response),
                Err(error) if attempt < CONNECT_ATTEMPTS && never_reached_tavily(&error) => {
                    warn!(
                        attempt,
                        error = %redact_secrets(&format!("{error:?}")),
                        "tavily connection failed before any response; retrying"
                    );
                    tokio::time::sleep(CONNECT_RETRY_BACKOFF * attempt).await;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Scan the caller-controlled text before spending a backend key on it.
    ///
    /// The query goes first, on its own: a blocked query means the URLs are
    /// never sent to a checker at all — the short-circuit the per-unit path
    /// had. The URLs travel as one group, so N of them cost one batch.
    ///
    /// With the default `stages = ["output"]` this whole stage is skipped:
    /// the query belongs to the caller, who holds a proxy key we issued.
    async fn check_input(&self, body: &Value, chain: &FilterChain) -> Result<u32, ProxyError> {
        if !chain.checks_input() {
            return Ok(0);
        }
        let mut calls = 0u32;
        if let Some(query) = body.get("query").and_then(Value::as_str) {
            calls += self
                .scan_units(&[ScanUnit::Query(query)], Stage::Input, chain)
                .await?;
        }
        if let Some(urls) = body.get("urls").and_then(Value::as_array) {
            let units: Vec<ScanUnit<'_>> = urls
                .iter()
                .filter_map(Value::as_str)
                .map(ScanUnit::Url)
                .collect();
            if !units.is_empty() {
                calls += self.scan_units(&units, Stage::Input, chain).await?;
            }
        }
        Ok(calls)
    }

    /// Run the chain over a group of units and surface the first unit that
    /// fails the call — verdicts are already decided; this stops the caller's
    /// request at the same place one-at-a-time scanning would have.
    ///
    /// Returns the checker invocations the run actually cost.
    async fn scan_units(
        &self,
        units: &[ScanUnit<'_>],
        stage: Stage,
        chain: &FilterChain,
    ) -> Result<u32, ProxyError> {
        let (results, calls) = chain.run_many_counted(units).await;
        for (unit, result) in units.iter().zip(results) {
            surface_chain_result(result, *unit, stage)?;
        }
        Ok(calls)
    }

    /// Scan what Tavily is about to hand the caller.
    ///
    /// Nothing Tavily sent is rewritten: a blocked entry is either gone, moved to
    /// the endpoint's own failure list (`/extract` has `failed_results`), or — if
    /// the operator opted in — counted in one extra `proxy_filtered` field. What
    /// was removed is always in the log, which is where this service talks about
    /// itself.
    async fn apply_output_filters(
        &self,
        body: &mut Value,
        endpoint: UpstreamEndpoint,
        chain: &FilterChain,
    ) -> Result<(usize, u32), ProxyError> {
        if chain.is_empty() || !chain.checks_output() {
            return Ok((0, 0));
        }

        // Everything held back, so the caller can be told how much is missing
        // without the kernel composing a message per entry.
        let mut removed = 0usize;
        let mut calls = 0u32;
        // `/extract` says which URL produced nothing, in Tavily's own field.
        let mut failed: Vec<Value> = Vec::new();

        // `answer` is model-written prose addressed to the reading agent, which
        // makes it the most valuable injection target in the payload.
        if let Some(answer) = body
            .get("answer")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            let answer_unit = [ScanUnit::Answer(&answer)];
            let (results, answer_calls) = chain.run_many_counted(&answer_unit).await;
            calls += answer_calls;
            let result = results
                .into_iter()
                .next()
                .expect("one unit in, one verdict out");
            match surface_chain_result(result, ScanUnit::Answer(&answer), Stage::Output) {
                Ok(()) => {}
                Err(blocked @ ProxyError::OutputBlocked { .. }) => {
                    if chain.output_block() == OutputBlockMode::WholeResponse {
                        return Err(blocked);
                    }
                    // Tavily's own "no answer available" shape.
                    body["answer"] = Value::Null;
                    removed += 1;
                }
                Err(other) => return Err(other),
            }
        }

        // Take the array out so entries can be scanned while `body` stays
        // borrowable, then judge every entry in one chain run: how that run is
        // executed (serially, concurrently, one call) is the filter's plan.
        match body.get_mut("results").map(Value::take) {
            Some(Value::Array(items)) => {
                let mut slots: Vec<Option<Value>> = items.into_iter().map(Some).collect();

                // Owned texts: units borrow them while `slots` is mutated below.
                let texts: Vec<String> = slots
                    .iter()
                    .map(|slot| {
                        slot.as_ref()
                            .map(|item| result_text(item, chain.scan_raw_content()))
                            .unwrap_or_default()
                    })
                    .collect();
                let units: Vec<ScanUnit<'_>> = texts
                    .iter()
                    .enumerate()
                    .map(|(index, text)| ScanUnit::ResultItem { index, text })
                    .collect();

                let (results, batch_calls) = chain.run_many_counted(&units).await;
                calls += batch_calls;

                for ((unit, slot), result) in units.iter().zip(slots.iter_mut()).zip(results) {
                    match surface_chain_result(result, *unit, Stage::Output) {
                        Ok(()) => {}
                        Err(ProxyError::OutputBlocked {
                            filter,
                            message,
                            confidence,
                        }) => {
                            if chain.output_block() == OutputBlockMode::WholeResponse {
                                return Err(ProxyError::OutputBlocked {
                                    filter,
                                    message,
                                    confidence,
                                });
                            }
                            if let Some(url) = slot
                                .as_ref()
                                .and_then(|item| item.get("url"))
                                .and_then(Value::as_str)
                            {
                                failed.push(json!({ "url": url, "error": message }));
                            }
                            // The unit's index addresses the array as received,
                            // which is what the log line points at.
                            removed += 1;
                            *slot = None;
                        }
                        Err(other) => return Err(other),
                    }
                }

                let kept: Vec<Value> = slots.into_iter().flatten().collect();
                body["results"] = Value::Array(kept);
            }
            Some(other) => {
                // Not an array: leave it exactly as it arrived.
                body["results"] = other;
            }
            None => {}
        }

        self.report_removed(body, endpoint, removed, failed, chain);
        Ok((removed, calls))
    }

    /// Say how much was held back, using the endpoint's own protocol where it has
    /// one.
    fn report_removed(
        &self,
        body: &mut Value,
        endpoint: UpstreamEndpoint,
        removed: usize,
        failed: Vec<Value>,
        chain: &FilterChain,
    ) {
        if removed == 0 {
            return;
        }

        match endpoint {
            // Tavily defines `failed_results` for entries it could not process, so
            // a blocked URL goes there with the checker's own sentence as the
            // reason: no field of ours is added.
            UpstreamEndpoint::Extract => match body.get_mut("failed_results") {
                Some(Value::Array(existing)) => existing.extend(failed),
                Some(_) => {
                    warn!("extract response had a non-array failed_results; leaving it untouched")
                }
                None => body["failed_results"] = Value::Array(failed),
            },
            // `/search` has no such field, so this is the one place the service
            // may add a key Tavily never sends — and only when the operator asked
            // for it.
            UpstreamEndpoint::Search => {
                if chain.report_filtered() != ReportFiltered::Field {
                    return;
                }
                let message = chain
                    .report_message()
                    .replace("{count}", &removed.to_string());
                body["proxy_filtered"] = json!({ "count": removed, "message": message });
            }
        }
    }
}

/// One line of `metrics.jsonl`: the per-request metric record.
///
/// Public because the field set is an interface — the analysis scripts read it by
/// key, and the key that used to name a lane is gone with the lanes (ADR-0003).
pub fn metrics_record(
    timing: &RequestTiming,
    status: u16,
    endpoint: &str,
    error_msg: Option<&str>,
) -> Value {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    json!({
        "timestamp_ms": now_ms,
        "status": status,
        "endpoint": endpoint,
        "total_ms": timing.total_ms,
        "tavily_ms": timing.tavily_ms,
        "filter_input_ms": timing.filter_input_ms,
        "filter_output_ms": timing.filter_output_ms,
        "filter_calls": timing.filter_calls,
        "blocked_items": timing.blocked_items,
        "key": timing.upstream_key,
        "error": error_msg,
    })
}

/// Per-token chains keyed by the proxy key (a credential: held in memory,
/// never logged), plus one `(label, rules)` line per route for the startup log.
type FilterRoutes = (HashMap<String, Arc<FilterChain>>, Vec<(String, String)>);

/// Build the per-token chains of `[[proxy_keys]] filter = [...]` (ISSUE-0006).
///
/// Identical selections share one built chain; a selection that fails to build
/// fails the whole startup, exactly like a broken global rule. The key itself
/// is a credential and never reaches `log_lines` — an unnamed key is addressed
/// by its position in the config instead.
fn build_filter_routes(config: &Config) -> anyhow::Result<FilterRoutes> {
    let mut routes = HashMap::new();
    let mut log_lines = Vec::new();
    let mut cache: HashMap<&[String], Arc<FilterChain>> = HashMap::new();

    for (index, key) in config.proxy_keys.iter().enumerate() {
        let Some(selection) = key.filter.as_ref() else {
            continue;
        };
        let chain = if selection.is_empty() {
            // The explicit exemption: a chain with no rules short-circuits both
            // stages through the branches that already exist.
            Arc::new(FilterChain::empty())
        } else if let Some(cached) = cache.get(selection.as_slice()) {
            Arc::clone(cached)
        } else {
            let built = Arc::new(FilterChain::from_config_selected(
                config.filter.as_ref(),
                selection,
            )?);
            cache.insert(selection.as_slice(), Arc::clone(&built));
            built
        };
        let label = key
            .name
            .clone()
            .unwrap_or_else(|| format!("unnamed#{}", index + 1));
        let rules = if selection.is_empty() {
            "skip".to_string()
        } else {
            format!("{selection:?}")
        };
        log_lines.push((label, rules));
        routes.insert(key.key.clone(), chain);
    }
    Ok((routes, log_lines))
}

/// Did this failure happen before Tavily could have processed anything?
///
/// `reqwest::Error::is_connect` is not enough on its own: the handshake failure
/// observed here arrives as `kind: Request` with a `Connect` error in its source
/// chain, which only `Debug` exposes. Timeouts are deliberately excluded — those
/// can mean the request did land and Tavily was merely slow to answer.
fn never_reached_tavily(error: &reqwest::Error) -> bool {
    error.is_connect() || format!("{error:?}").contains("Connect")
}

/// The text a result entry contributes to scanning.
///
/// `raw_content` is a whole page and is excluded unless asked for: free for a
/// keyword match, but a token-priced model would be billed for an entire
/// document per result.
fn result_text(item: &Value, include_raw_content: bool) -> String {
    const FIELDS: [&str; 3] = ["title", "url", "content"];

    let mut text = String::new();
    for field in FIELDS {
        if let Some(value) = item.get(field).and_then(Value::as_str) {
            text.push_str(value);
            text.push('\n');
        }
    }
    if include_raw_content && let Some(raw) = item.get("raw_content").and_then(Value::as_str) {
        text.push_str(raw);
    }
    text
}

/// Tavily's own error text, when the body is the simple `{"detail":{"error":...}}`
/// shape — the only upstream content ever considered for the client.
///
/// Anything else (notably the 422 validation *array*, which echoes the submitted
/// request including the `api_key` this service injected) yields `None`, so the
/// caller gets a generic message instead. The message is redacted as a second
/// line of defence against a future Tavily response that quotes the credential.
fn detail_message(body: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(body).ok()?;
    let message = parsed.get("detail")?.get("error")?.as_str()?;
    Some(redact_secrets(message))
}

/// Log the outcome of one check.
///
/// Log-only by design: the client sees exactly Tavily's reply, so this is where
/// observability lives.
/// Log one unit's chain result, then turn it into the call's verdict.
///
/// A verdict only ever fails the call when it is `Blocked` or `Unavailable`;
/// a `Flagged` unit passes (it is below the configured threshold) and shows
/// up only in the log.
fn surface_chain_result(
    result: ChainResult,
    unit: ScanUnit<'_>,
    stage: Stage,
) -> Result<(), ProxyError> {
    log_chain_result(&result, unit, stage);

    match result.verdict {
        ChainVerdict::Pass | ChainVerdict::Flagged { .. } => Ok(()),
        ChainVerdict::Blocked {
            filter,
            message,
            confidence,
        } => Err(match stage {
            Stage::Input => ProxyError::InputBlocked {
                filter,
                message,
                confidence,
            },
            Stage::Output => ProxyError::OutputBlocked {
                filter,
                message,
                confidence,
            },
        }),
        ChainVerdict::Unavailable { filter, detail } => Err(ProxyError::SafetyCheckUnavailable {
            filter,
            stage: stage.as_str().to_string(),
            detail,
        }),
    }
}

fn log_chain_result(result: &ChainResult, unit: ScanUnit<'_>, stage: Stage) {
    let kind = unit.kind();
    let index = unit.index().unwrap_or(0);

    for failure in &result.failures {
        warn!(
            stage = stage.as_str(),
            unit = kind,
            index,
            filter = %failure.filter,
            detail = %failure.detail,
            "content filter failed"
        );
    }

    match &result.verdict {
        ChainVerdict::Pass => {}
        ChainVerdict::Flagged {
            filter,
            message,
            confidence,
        } => warn!(
            stage = stage.as_str(),
            unit = kind,
            index,
            filter = %filter,
            message = %redact_secrets(message),
            confidence,
            "content flagged below the block threshold; passing it through"
        ),
        ChainVerdict::Blocked {
            filter,
            message,
            confidence,
        } => warn!(
            stage = stage.as_str(),
            unit = kind,
            index,
            filter = %filter,
            message = %redact_secrets(message),
            confidence,
            "content blocked"
        ),
        ChainVerdict::Unavailable { filter, detail } => warn!(
            stage = stage.as_str(),
            unit = kind,
            index,
            filter = %filter,
            detail = %detail,
            "content filter unavailable; failing closed"
        ),
    }
}
