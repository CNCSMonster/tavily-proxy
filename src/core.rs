use std::time::Duration;

use anyhow::Context;
use serde_json::{Value, json};
use tracing::{error, info, warn};

use crate::auth::{Auth, AuthResult};
use crate::config::Config;
use crate::filter::{
    ChainResult, ChainVerdict, FilterChain, OutputBlockMode, ReportFiltered, ScanUnit, Stage,
};
use crate::key_pool::KeyPool;
use crate::redact::redact_secrets;

const DEFAULT_COOLDOWN_SECS: u64 = 60;

/// A TLS handshake to Tavily can die before a response is ever produced (observed
/// in this environment: DNS resolves `api.tavily.com` through a transparent
/// proxy, and the odd handshake comes back as `SSL_ERROR_SYSCALL` while the very
/// next attempt on the same client succeeds). A handshake that never completed
/// cannot have reached Tavily, so retrying it costs nothing upstream.
const CONNECT_ATTEMPTS: u32 = 3;
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// Bounds on a single upstream attempt. Without them a stalled connection holds
/// the caller's request (and a socket) forever, which is both a bad experience
/// and a cheap way to exhaust the service.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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

pub struct ProxyCore {
    pub key_pool: KeyPool,
    pub auth: Auth,
    pub filters: FilterChain,
    pub http_client: reqwest::Client,
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
                // The one upstream string that is passed through on purpose: the
                // caller should see exactly what Tavily would have told it.
                detail_error(message.as_deref().unwrap_or("Tavily returned an error.")),
            ),
            ProxyError::NetworkError(_) => {
                (502, detail_error("Failed to reach Tavily. Retry shortly."))
            }
            ProxyError::ParseError(_) => (502, detail_error("Failed to parse Tavily's response.")),
        }
    }
}

pub struct ProxyResponse {
    pub body: Value,
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
        Ok(Self {
            key_pool: KeyPool::new(&config.tavily_keys),
            auth: Auth::new(&config.proxy_keys),
            filters: FilterChain::from_config(config.filter.as_ref())?,
            http_client: reqwest::Client::builder()
                .timeout(UPSTREAM_TIMEOUT)
                .connect_timeout(UPSTREAM_CONNECT_TIMEOUT)
                .build()
                .context("failed to build the Tavily HTTP client")?,
            upstream_base: DEFAULT_UPSTREAM_BASE.to_string(),
        })
    }

    pub fn with_filter_chain(mut self, filters: FilterChain) -> Self {
        self.filters = filters;
        self
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
        let _key_name = self.authenticate(proxy_key)?;
        self.check_input(&body).await?;

        let upstream_url = format!("{}{upstream_path}", self.upstream_base);

        // One attempt per pooled key. A key that refuses is marked and the same
        // request is retried on the next one: rotation has to stay invisible to
        // the caller, otherwise every request pays a 503 per depleted key — and
        // since the pool always starts at index 0, that would be the first request
        // after every restart.
        let attempts = self.key_pool.total_keys().max(1);
        let mut last_refusal: Option<(u16, Option<String>)> = None;

        for _ in 0..attempts {
            let Some(tavily_key) = self.key_pool.get_key() else {
                break;
            };

            // Replace whatever credential the caller sent: only pooled keys ever
            // reach Tavily, and the client's own key is never forwarded upstream.
            if let Some(obj) = body.as_object_mut() {
                obj.remove("api_key");
                obj.insert("api_key".into(), Value::String(tavily_key));
            }

            let response = self
                .send_to_tavily(&upstream_url, &body)
                .await
                .map_err(|e| {
                    // `Display` on a reqwest error stops at "error sending
                    // request"; the cause (DNS, connect, TLS) only shows up in the
                    // `source` chain, which `Debug` renders.
                    let detail = redact_secrets(&format!("{e:?}"));
                    error!(error = %detail, "failed to reach tavily");
                    ProxyError::NetworkError(detail)
                })?;

            let status = response.status();
            let status_code = status.as_u16();

            if is_limiting_status(status_code) {
                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                let error_body = response.text().await.unwrap_or_default();

                warn!(
                    %status,
                    error_body = %redact_secrets(&error_body),
                    retry_after_secs = retry_after.unwrap_or(0),
                    "tavily key limited"
                );

                match status_code {
                    // 429: transient RPM rate limit — cooldown then reuse
                    429 => {
                        self.key_pool.mark_cooldown(Duration::from_secs(
                            retry_after.unwrap_or(DEFAULT_COOLDOWN_SECS),
                        ));
                    }
                    // 432/433: monthly quota or PAYGO cap — exhausted for this cycle
                    _ => {
                        self.key_pool.mark_exhausted_current();
                    }
                }

                // Remember Tavily's own verdict: if no key survives, the caller
                // gets the same status and wording it would have got directly.
                last_refusal = Some((status_code, detail_message(&error_body)));
                continue;
            }

            if !status.is_success() {
                let error_body = response.text().await.unwrap_or_default();
                error!(%status, error_body = %redact_secrets(&error_body), "tavily upstream error");
                return Err(ProxyError::UpstreamError {
                    status: status_code,
                    message: detail_message(&error_body),
                });
            }

            self.key_pool.record_usage();
            self.auth.record_usage(proxy_key);

            let mut result: Value = response.json().await.map_err(|e| {
                let message = redact_secrets(&e.to_string());
                error!(error = %message, "failed to parse tavily response");
                ProxyError::ParseError(message)
            })?;

            self.apply_output_filters(&mut result, endpoint).await?;

            info!("request proxied successfully");
            return Ok(ProxyResponse { body: result });
        }

        match last_refusal {
            Some((status, message)) => Err(ProxyError::UpstreamError { status, message }),
            None => Err(ProxyError::AllKeysExhausted),
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
            match self.http_client.post(url).json(body).send().await {
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
    async fn check_input(&self, body: &Value) -> Result<(), ProxyError> {
        if let Some(query) = body.get("query").and_then(Value::as_str) {
            self.scan(ScanUnit::Query(query), Stage::Input).await?;
        }
        if let Some(urls) = body.get("urls").and_then(Value::as_array) {
            for url in urls.iter().filter_map(Value::as_str) {
                self.scan(ScanUnit::Url(url), Stage::Input).await?;
            }
        }
        Ok(())
    }

    /// Run the chain on one unit.
    ///
    /// A verdict only ever fails the call when it is `Blocked` or
    /// `Unavailable`; a `Flagged` unit passes (it is below the configured
    /// threshold) and only shows up in the log.
    async fn scan(&self, unit: ScanUnit<'_>, stage: Stage) -> Result<(), ProxyError> {
        let result = self.filters.run(unit).await;
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
            ChainVerdict::Unavailable { filter, detail } => {
                Err(ProxyError::SafetyCheckUnavailable {
                    filter,
                    stage: stage.as_str().to_string(),
                    detail,
                })
            }
        }
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
    ) -> Result<(), ProxyError> {
        if self.filters.is_empty() {
            return Ok(());
        }

        // Everything held back, so the caller can be told how much is missing
        // without the kernel composing a message per entry.
        let mut removed = 0usize;
        // `/extract` says which URL produced nothing, in Tavily's own field.
        let mut failed: Vec<Value> = Vec::new();

        // `answer` is model-written prose addressed to the reading agent, which
        // makes it the most valuable injection target in the payload.
        if let Some(answer) = body
            .get("answer")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            match self.scan(ScanUnit::Answer(&answer), Stage::Output).await {
                Ok(()) => {}
                Err(blocked @ ProxyError::OutputBlocked { .. }) => {
                    if self.filters.output_block() == OutputBlockMode::WholeResponse {
                        return Err(blocked);
                    }
                    // Tavily's own "no answer available" shape.
                    body["answer"] = Value::Null;
                    removed += 1;
                }
                Err(other) => return Err(other),
            }
        }

        // Take the array out so entries can be scanned by reference without
        // holding a borrow of `body` across an await.
        match body.get_mut("results").map(Value::take) {
            Some(Value::Array(items)) => {
                let mut slots: Vec<Option<Value>> = items.into_iter().map(Some).collect();

                for (index, slot) in slots.iter_mut().enumerate() {
                    // Owned text, so no borrow of `slot` is held across the await.
                    let text = slot
                        .as_ref()
                        .map(|item| result_text(item, self.filters.scan_raw_content()))
                        .unwrap_or_default();

                    match self
                        .scan(ScanUnit::ResultItem { index, text: &text }, Stage::Output)
                        .await
                    {
                        Ok(()) => {}
                        Err(ProxyError::OutputBlocked {
                            filter,
                            message,
                            confidence,
                        }) => {
                            if self.filters.output_block() == OutputBlockMode::WholeResponse {
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
                            // `index` addresses the array as received, which is
                            // what the log line needs to point at.
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

        self.report_removed(body, endpoint, removed, failed);
        Ok(())
    }

    /// Say how much was held back, using the endpoint's own protocol where it has
    /// one.
    fn report_removed(
        &self,
        body: &mut Value,
        endpoint: UpstreamEndpoint,
        removed: usize,
        failed: Vec<Value>,
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
                if self.filters.report_filtered() != ReportFiltered::Field {
                    return;
                }
                let message = self
                    .filters
                    .report_message()
                    .replace("{count}", &removed.to_string());
                body["proxy_filtered"] = json!({ "count": removed, "message": message });
            }
        }
    }
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

/// The status codes Tavily uses to say "not this key, not now": 429 per-minute
/// rate limit, 432 monthly quota, 433 PAYGO cap.
fn is_limiting_status(status_code: u16) -> bool {
    matches!(status_code, 429 | 432 | 433)
}
