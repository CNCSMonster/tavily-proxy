use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{NaiveDate, Utc};
use parking_lot::Mutex;
use tracing::warn;

use crate::config::ProxyKeyConfig;
use crate::quota::{TokenUsageBucket, load_quota_or_recover, save_quota_atomic};
use crate::rate_limiter::TokenBucket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUsage {
    pub name: Option<String>,
    pub used_requests: u64,
    pub max_requests_per_month: Option<u64>,
}

struct ProxyKeyState {
    name: Option<String>,
    max_requests_per_month: Option<u64>,
    bucket: TokenUsageBucket,
    rate_limiter: Option<Arc<TokenBucket>>,
    max_concurrency: Option<usize>,
    active_concurrency: usize,
}

pub struct Auth {
    keys: Arc<Mutex<HashMap<String, ProxyKeyState>>>,
    storage_path: Option<PathBuf>,
    retention_days: u32,
    max_file_size_bytes: usize,
    dirty: Arc<AtomicBool>,
}

pub enum AuthResult {
    Ok { name: Option<String> },
    InvalidKey,
    QuotaExceeded { name: Option<String> },
}

#[derive(Debug)]
pub enum SlotAcquireResult {
    Ok,
    InvalidKey,
    QuotaExceeded {
        name: Option<String>,
    },
    ConcurrencyLimitReached {
        name: Option<String>,
    },
    RateLimitExceeded {
        name: Option<String>,
        wait_needed: Duration,
    },
}

/// RAII Slot Guard: manages in-flight concurrency count and quota reservation.
///
/// On explicit `commit()`, the reservation is settled into today's bucket and in_flight is decremented.
/// On drop without commit, reservation is automatically aborted (in_flight decremented without billing).
/// In either case, the concurrency slot is released on drop.
pub struct SlotGuard {
    auth: Arc<Auth>,
    key: String,
    committed: bool,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.auth.abort_quota_reservation(&self.key);
        }
        self.auth.release_concurrency(&self.key);
    }
}

impl SlotGuard {
    /// Explicitly commit the reservation: record usage to today's daily bucket and decrement in_flight.
    pub fn commit(&mut self) {
        if !self.committed {
            self.committed = true;
            self.auth.commit_quota_reservation(&self.key);
        }
    }
}

pub type ConcurrencyGuard = SlotGuard;
pub type QuotaSlotGuard = SlotGuard;

impl Auth {
    pub fn new(configs: &[ProxyKeyConfig]) -> Self {
        Self::new_with_options(
            configs,
            None,
            crate::config::DEFAULT_RETENTION_DAYS,
            (crate::config::DEFAULT_MAX_FILE_SIZE_MB as usize) * 1024 * 1024,
        )
    }

    pub fn new_with_path(configs: &[ProxyKeyConfig], storage_path: Option<PathBuf>) -> Self {
        Self::new_with_options(
            configs,
            storage_path,
            crate::config::DEFAULT_RETENTION_DAYS,
            (crate::config::DEFAULT_MAX_FILE_SIZE_MB as usize) * 1024 * 1024,
        )
    }

    pub fn new_with_options(
        configs: &[ProxyKeyConfig],
        storage_path: Option<PathBuf>,
        retention_days: u32,
        max_file_size_bytes: usize,
    ) -> Self {
        let mut initial_buckets = storage_path
            .as_deref()
            .map(|p| load_quota_or_recover(p, retention_days))
            .unwrap_or_default();

        let today = Utc::now().date_naive();
        let mut keys = HashMap::new();
        for c in configs {
            let rate_limiter = c.rpm.map(|rpm| Arc::new(TokenBucket::new(rpm)));
            let mut bucket = initial_buckets.remove(&c.key).unwrap_or_default();
            bucket.prune_retention(today, retention_days);
            keys.insert(
                c.key.clone(),
                ProxyKeyState {
                    name: c.name.clone(),
                    max_requests_per_month: c.max_requests_per_month,
                    bucket,
                    rate_limiter,
                    max_concurrency: c.max_concurrency,
                    active_concurrency: 0,
                },
            );
        }

        Self {
            keys: Arc::new(Mutex::new(keys)),
            storage_path,
            retention_days,
            max_file_size_bytes,
            dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn authenticate(&self, key: &str) -> AuthResult {
        let today = Utc::now().date_naive();
        let keys = self.keys.lock();
        match keys.get(key) {
            None => AuthResult::InvalidKey,
            Some(state) => {
                if let Some(max) = state.max_requests_per_month {
                    let settled = state.bucket.settled_in_window(today);
                    if settled + state.bucket.in_flight >= max {
                        warn!(
                            proxy_key_name = state.name.as_deref().unwrap_or("unnamed"),
                            settled,
                            in_flight = state.bucket.in_flight,
                            max,
                            "proxy key quota exceeded"
                        );
                        return AuthResult::QuotaExceeded {
                            name: state.name.clone(),
                        };
                    }
                }
                AuthResult::Ok {
                    name: state.name.clone(),
                }
            }
        }
    }

    /// Acquire in-flight concurrency slot, rate-limiter token, and reserve quota for a proxy key.
    pub async fn acquire_slot(
        self: &Arc<Self>,
        key: &str,
        max_wait: Duration,
    ) -> Result<SlotGuard, SlotAcquireResult> {
        let today = Utc::now().date_naive();
        let (name, rate_limiter) = {
            let mut keys = self.keys.lock();
            let Some(state) = keys.get_mut(key) else {
                return Err(SlotAcquireResult::InvalidKey);
            };

            if let Some(max) = state.max_requests_per_month {
                let settled = state.bucket.settled_in_window(today);
                if settled + state.bucket.in_flight >= max {
                    return Err(SlotAcquireResult::QuotaExceeded {
                        name: state.name.clone(),
                    });
                }
            }

            if let Some(max_c) = state.max_concurrency
                && state.active_concurrency >= max_c
            {
                warn!(
                    proxy_key_name = state.name.as_deref().unwrap_or("unnamed"),
                    active = state.active_concurrency,
                    max = max_c,
                    "proxy key concurrency limit reached"
                );
                return Err(SlotAcquireResult::ConcurrencyLimitReached {
                    name: state.name.clone(),
                });
            }

            state.bucket.in_flight += 1;
            state.active_concurrency += 1;
            (state.name.clone(), state.rate_limiter.clone())
        };

        let guard = SlotGuard {
            auth: Arc::clone(self),
            key: key.to_string(),
            committed: false,
        };

        if let Some(limiter) = rate_limiter
            && let Err(wait_needed) = limiter.acquire(max_wait).await
        {
            warn!(
                proxy_key_name = name.as_deref().unwrap_or("unnamed"),
                wait_secs = wait_needed.as_secs_f64(),
                "proxy key rate limit exceeded"
            );
            return Err(SlotAcquireResult::RateLimitExceeded { name, wait_needed });
        }

        Ok(guard)
    }

    pub fn commit_quota_reservation(&self, key: &str) {
        let today = Utc::now().date_naive();
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(key) {
            state.bucket.in_flight = state.bucket.in_flight.saturating_sub(1);
            *state.bucket.daily.entry(today).or_insert(0) += 1;
            self.dirty.store(true, Ordering::Release);
        }
    }

    pub fn abort_quota_reservation(&self, key: &str) {
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(key) {
            state.bucket.in_flight = state.bucket.in_flight.saturating_sub(1);
        }
    }

    pub fn release_concurrency(&self, key: &str) {
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(key) {
            state.active_concurrency = state.active_concurrency.saturating_sub(1);
        }
    }

    pub fn record_usage(&self, key: &str) {
        let today = Utc::now().date_naive();
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(key) {
            *state.bucket.daily.entry(today).or_insert(0) += 1;
            self.dirty.store(true, Ordering::Release);
        }
    }

    pub fn query_usage(&self, key: &str) -> Option<KeyUsage> {
        let today = Utc::now().date_naive();
        self.query_rolling_usage(key, today)
    }

    pub fn query_rolling_usage(&self, key: &str, today: NaiveDate) -> Option<KeyUsage> {
        let keys = self.keys.lock();
        keys.get(key).map(|state| KeyUsage {
            name: state.name.clone(),
            used_requests: state.bucket.settled_in_window(today),
            max_requests_per_month: state.max_requests_per_month,
        })
    }

    pub fn flush_quota_sync(&self) {
        if let Some(path) = &self.storage_path {
            let mut buckets = BTreeMap::new();
            {
                let keys = self.keys.lock();
                for (k, state) in keys.iter() {
                    buckets.insert(k.clone(), state.bucket.clone());
                }
            }
            if let Err(e) = save_quota_atomic(
                path,
                &buckets,
                self.retention_days,
                self.max_file_size_bytes,
            ) {
                warn!(path = %path.display(), error = %e, "Failed to flush quota file synchronously");
            } else {
                self.dirty.store(false, Ordering::Release);
            }
        }
    }

    pub fn start_persistence_worker(&self) {
        if let Some(path) = &self.storage_path {
            let dirty = Arc::clone(&self.dirty);
            let keys = Arc::clone(&self.keys);
            let path = path.clone();
            let retention_days = self.retention_days;
            let max_file_size_bytes = self.max_file_size_bytes;
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(2));
                    loop {
                        interval.tick().await;
                        if dirty.swap(false, Ordering::AcqRel) {
                            let mut buckets = BTreeMap::new();
                            {
                                let lock = keys.lock();
                                for (k, state) in lock.iter() {
                                    buckets.insert(k.clone(), state.bucket.clone());
                                }
                            }
                            if let Err(e) = save_quota_atomic(
                                &path,
                                &buckets,
                                retention_days,
                                max_file_size_bytes,
                            ) {
                                warn!(path = %path.display(), error = %e, "Failed to save debounced quota file");
                            }
                        }
                    }
                });
            }
        }
    }
}
