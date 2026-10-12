use anyhow::{Context, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use reqwest::{Client, Response};
use serde_json::Value;
use std::time::{Duration, Instant};
use tracing::warn;

pub const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_MIN_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default)]
pub struct EgressOutcome {
    pub status_code: Option<u16>,
    pub latency: Duration,
    pub is_delivery_error: bool,
    pub retry_after: Option<Duration>,
}

#[derive(Debug)]
pub enum EgressError {
    Transport(reqwest::Error),
    Backpressure { retry_after_secs: u64 },
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressError::Transport(e) => write!(f, "HTTP transport error: {e}"),
            EgressError::Backpressure { retry_after_secs } => {
                write!(
                    f,
                    "Gateway backpressure: all available egress capacity exhausted (retry after {retry_after_secs}s)"
                )
            }
        }
    }
}

impl std::error::Error for EgressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EgressError::Transport(e) => Some(e),
            EgressError::Backpressure { .. } => None,
        }
    }
}

impl From<reqwest::Error> for EgressError {
    fn from(e: reqwest::Error) -> Self {
        EgressError::Transport(e)
    }
}

/// Upstream HTTP request transport context.
#[derive(Debug, Clone)]
pub struct EgressContext {
    /// The default Tavily API key suggested by core.
    pub suggested_api_key: String,
    /// The actual Tavily API key used by the egress implementation.
    pub effective_api_key: Option<String>,
}

impl EgressContext {
    pub fn new(suggested_api_key: String) -> Self {
        Self {
            suggested_api_key,
            effective_api_key: None,
        }
    }

    pub fn set_effective_api_key(&mut self, key: String) {
        self.effective_api_key = Some(key);
    }

    pub fn effective_api_key(&self) -> &str {
        self.effective_api_key
            .as_deref()
            .unwrap_or(&self.suggested_api_key)
    }
}

#[async_trait]
pub trait Egress: Send + Sync {
    /// Logical name of the egress (e.g. "direct", "corporate-proxy")
    fn name(&self) -> &str;

    /// Whether this egress is currently available (not in 429 cooldown, has token)
    fn is_available(&self) -> bool;

    /// Send HTTP request to upstream URL (POST with JSON body by default)
    async fn send_upstream(
        &self,
        url: &str,
        body: &Value,
        ctx: &mut EgressContext,
    ) -> Result<Response, EgressError> {
        self.send_upstream_request(reqwest::Method::POST, url, Some(body), ctx)
            .await
    }

    /// Send HTTP request to upstream URL with arbitrary method and optional body
    async fn send_upstream_request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&Value>,
        ctx: &mut EgressContext,
    ) -> Result<Response, EgressError>;

    /// Record outcome of a request (updates cooldown, metrics, etc.)
    fn record_outcome(&self, outcome: &EgressOutcome);
}

pub struct DirectEgress {
    client: Client,
    state: Mutex<DirectEgressState>,
}

struct DirectEgressState {
    cooling_until: Option<Instant>,
}

impl DirectEgress {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(DEFAULT_UPSTREAM_TIMEOUT)
            .connect_timeout(DEFAULT_UPSTREAM_CONNECT_TIMEOUT)
            .build()
            .context("failed to build DirectEgress HTTP client")?;
        Ok(Self {
            client,
            state: Mutex::new(DirectEgressState {
                cooling_until: None,
            }),
        })
    }

    pub fn with_client(client: Client) -> Self {
        Self {
            client,
            state: Mutex::new(DirectEgressState {
                cooling_until: None,
            }),
        }
    }
}

#[async_trait]
impl Egress for DirectEgress {
    fn name(&self) -> &str {
        "direct"
    }

    fn is_available(&self) -> bool {
        let state = self.state.lock();
        if let Some(until) = state.cooling_until {
            Instant::now() >= until
        } else {
            true
        }
    }

    async fn send_upstream(
        &self,
        url: &str,
        body: &Value,
        ctx: &mut EgressContext,
    ) -> Result<Response, EgressError> {
        self.send_upstream_request(reqwest::Method::POST, url, Some(body), ctx)
            .await
    }

    async fn send_upstream_request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&Value>,
        ctx: &mut EgressContext,
    ) -> Result<Response, EgressError> {
        ctx.set_effective_api_key(ctx.suggested_api_key.clone());
        let mut req = self
            .client
            .request(method, url)
            .bearer_auth(&ctx.suggested_api_key);
        if let Some(b) = body {
            req = req.json(b);
        }
        req.send().await.map_err(EgressError::from)
    }

    fn record_outcome(&self, outcome: &EgressOutcome) {
        if outcome.status_code == Some(429) {
            let base_cooldown = outcome
                .retry_after
                .unwrap_or(DEFAULT_MIN_COOLDOWN)
                .max(DEFAULT_MIN_COOLDOWN);
            // Non-negative jitter: 0..5000 ms
            let jitter = Duration::from_millis(fastrand::u64(0..5000));
            let total_cooldown = base_cooldown + jitter;
            let until = Instant::now() + total_cooldown;

            let mut state = self.state.lock();
            state.cooling_until = Some(until);
            warn!(
                cooldown_secs = total_cooldown.as_secs(),
                "direct egress entering 429 cooldown"
            );
        } else if outcome.status_code == Some(200) {
            let mut state = self.state.lock();
            if state.cooling_until.is_some() {
                state.cooling_until = None;
            }
        }
    }
}
