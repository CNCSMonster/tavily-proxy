use parking_lot::Mutex;
use std::time::Duration;
use tracing::{info, warn};

use crate::config::{Config, TavilyKeyConfig};
use crate::rate_limiter::{DEFAULT_DEV_RPM, TokenBucket, default_rpm_for_key};

struct KeyState {
    key: String,
    max_requests: Option<u64>,
    used_requests: u64,
    status: KeyStatus,
}

/// A key is either serving or gone for this cycle. Deliberately no "rate
/// limited" state: a 429 is a per-minute verdict the same key recovers from on
/// its own, so it is either waited out on that key or handed to the caller.
/// Recording it here would only tempt the pool into switching credentials to
/// dodge a rate limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    Available,
    Exhausted,
    // Upstream 401: the credential is invalid or was revoked. Terminal like
    // Exhausted, but semantically distinct — Exhausted means the quota ran out
    // (it may refill next cycle), Revoked means the credential itself is gone
    // and no amount of waiting brings it back.
    Revoked,
}

/// The upstream key pool: one ordered, flat lane of keys.
///
/// Requests stick to the current key until it hits a terminal verdict (432/433
/// quota exhausted, or 401 revoked). 429 rate limits are handled on the same key
/// and never trigger rotation.
///
/// One rate bucket covers the whole pool, because the bucket models the egress
/// IP's budget, not the key's: upstream counts requests per source IP, so
/// splitting the pool into lanes would only let the local ledger exceed that
/// budget (ADR-0003).
pub struct KeyPool {
    keys: Mutex<Vec<KeyState>>,
    current_index: Mutex<usize>,
    rpm: u32,
    rate_limiter: Option<TokenBucket>,
}

/// Outcome of one pool acquisition.
#[derive(Debug)]
pub enum KeyAcquireResult {
    /// A key that may be used right now (the rate bucket had room for it).
    Acquired(String),
    /// A key exists, but the IP budget is spent for this minute.
    AllRateLimited { min_wait_needed: Duration },
    /// Every key is terminally dead — waiting would not bring one back.
    NoKeys,
}

impl KeyPool {
    /// Pool whose bucket follows the first key's plan (dev 90 / prod 900).
    pub fn new(configs: &[TavilyKeyConfig]) -> Self {
        let rpm = configs
            .first()
            .map(|c| default_rpm_for_key(&c.key))
            .unwrap_or(DEFAULT_DEV_RPM);
        Self::with_rpm(configs, rpm)
    }

    /// Pool with an explicit bucket size; `rpm == 0` means no rate limiting.
    pub fn with_rpm(configs: &[TavilyKeyConfig], rpm: u32) -> Self {
        let keys: Vec<KeyState> = configs
            .iter()
            .map(|c| KeyState {
                key: c.key.clone(),
                max_requests: c.max_requests,
                used_requests: 0,
                status: KeyStatus::Available,
            })
            .collect();

        let rate_limiter = if rpm > 0 {
            Some(TokenBucket::new(rpm))
        } else {
            None
        };

        Self {
            keys: Mutex::new(keys),
            current_index: Mutex::new(0),
            rpm,
            rate_limiter,
        }
    }

    pub fn from_config(config: &Config) -> Self {
        Self::with_rpm(&config.flatten_keys(), config.resolve_upstream_rpm())
    }

    /// The bucket size, i.e. this egress IP's request budget per minute.
    pub fn rpm(&self) -> u32 {
        self.rpm
    }

    pub fn get_key(&self) -> Option<String> {
        let mut keys = self.keys.lock();
        let mut idx = self.current_index.lock();
        let len = keys.len();
        if len == 0 {
            return None;
        }

        for _ in 0..len {
            let state = &mut keys[*idx];

            match state.status {
                KeyStatus::Available => {
                    let over_limit = state
                        .max_requests
                        .is_some_and(|max| state.used_requests >= max);

                    if over_limit {
                        state.status = KeyStatus::Exhausted;
                        let masked = mask_key(&state.key);
                        warn!(
                            key = %masked,
                            "key marked as exhausted (local quota reached)"
                        );
                        *idx = (*idx + 1) % len;
                        continue;
                    }

                    return Some(state.key.clone());
                }
                KeyStatus::Exhausted | KeyStatus::Revoked => {
                    *idx = (*idx + 1) % len;
                }
            }
        }

        None
    }

    /// Pick the key first, then take the rate token: a request that has no key
    /// to go out on must not spend a slot of the IP budget.
    pub async fn acquire(&self, max_wait: Duration) -> KeyAcquireResult {
        let Some(key) = self.get_key() else {
            return KeyAcquireResult::NoKeys;
        };

        let Some(limiter) = &self.rate_limiter else {
            return KeyAcquireResult::Acquired(key);
        };

        match limiter.acquire(max_wait).await {
            Ok(()) => KeyAcquireResult::Acquired(key),
            Err(wait_needed) => KeyAcquireResult::AllRateLimited {
                min_wait_needed: wait_needed,
            },
        }
    }

    /// How long the bucket would have to wait for the next token. Zero when no
    /// bucket is configured.
    pub fn estimate_rate_wait(&self) -> Duration {
        self.rate_limiter
            .as_ref()
            .map(TokenBucket::estimate_wait)
            .unwrap_or(Duration::ZERO)
    }

    pub fn record_usage(&self) {
        let mut keys = self.keys.lock();
        let idx = *self.current_index.lock();
        if let Some(state) = keys.get_mut(idx) {
            state.used_requests += 1;
            let masked = mask_key(&state.key);
            info!(key = %masked, used = state.used_requests, "recorded usage");
        }
    }

    /// Mark the current key as permanently exhausted for this cycle (432/433).
    pub fn mark_exhausted_current(&self) {
        let mut keys = self.keys.lock();
        let mut idx = self.current_index.lock();
        let len = keys.len();
        if len == 0 {
            return;
        }
        if let Some(state) = keys.get_mut(*idx) {
            state.status = KeyStatus::Exhausted;
            let masked = mask_key(&state.key);
            warn!(key = %masked, "key marked as exhausted (monthly quota depleted)");
        }
        *idx = (*idx + 1) % len;
        let masked = mask_key(&keys[*idx].key);
        info!(next_key = %masked, "rotated to next key after exhaustion");
    }

    /// Mark the current key as revoked upstream (401) and rotate away from it.
    pub fn mark_revoked_current(&self) {
        let mut keys = self.keys.lock();
        let mut idx = self.current_index.lock();
        let len = keys.len();
        if len == 0 {
            return;
        }
        if let Some(state) = keys.get_mut(*idx) {
            state.status = KeyStatus::Revoked;
            let masked = mask_key(&state.key);
            warn!(key = %masked, "key revoked upstream (401), removed from rotation");
        }
        *idx = (*idx + 1) % len;
        let masked = mask_key(&keys[*idx].key);
        info!(next_key = %masked, "rotated to next key after revocation");
    }

    pub fn mark_exhausted(&self, index: usize) {
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(index) {
            state.status = KeyStatus::Exhausted;
            let masked = mask_key(&state.key);
            warn!(key = %masked, "key marked as exhausted");
        }
    }

    pub fn rotate_to_next(&self) {
        let keys = self.keys.lock();
        let mut idx = self.current_index.lock();
        let len = keys.len();
        if len > 0 {
            *idx = (*idx + 1) % len;
            let masked = mask_key(&keys[*idx].key);
            info!(next_key = %masked, "rotated to next key");
        }
    }

    pub fn current_index(&self) -> usize {
        *self.current_index.lock()
    }

    pub fn total_keys(&self) -> usize {
        self.keys.lock().len()
    }

    pub fn available_keys(&self) -> usize {
        self.keys
            .lock()
            .iter()
            .filter(|k| matches!(k.status, KeyStatus::Available))
            .count()
    }

    pub fn all_terminally_dead(&self) -> bool {
        let keys = self.keys.lock();
        keys.is_empty()
            || keys
                .iter()
                .all(|k| matches!(k.status, KeyStatus::Exhausted | KeyStatus::Revoked))
    }
}

pub fn mask_key(key: &str) -> String {
    if key.len() <= 10 {
        return "***".to_string();
    }
    format!("{}...{}", &key[..7], &key[key.len() - 4..])
}
