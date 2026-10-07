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

#[async_trait]
pub trait Egress: Send + Sync {
    /// Logical name of the egress (e.g. "direct", "hk-proxy-1")
    fn name(&self) -> &str;

    /// Whether this egress is currently available (not in 429 cooldown, has token)
    fn is_available(&self) -> bool;

    /// Send HTTP request to upstream URL
    async fn send_upstream(&self, url: &str, body: &Value) -> Result<Response, reqwest::Error>;

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

    async fn send_upstream(&self, url: &str, body: &Value) -> Result<Response, reqwest::Error> {
        self.client.post(url).json(body).send().await
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
