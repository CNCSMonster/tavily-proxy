use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use chrono::{NaiveDate, Utc};
use parking_lot::Mutex;
use tracing::warn;

use crate::config::ProxyKeyConfig;
use crate::quota::{TokenUsageBucket, UsageCategory, load_quota_or_recover, save_quota_atomic};
use crate::rate_limiter::TokenBucket;

pub const PENALTY_CONSECUTIVE_THRESHOLD: u32 = 60;
pub const PENALTY_LEVEL_1_DURATION: Duration = Duration::from_secs(5 * 60);
pub const PENALTY_LEVEL_2_DURATION: Duration = Duration::from_secs(60 * 60);
pub const PENALTY_LEVEL_3_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PenaltyBox {
    pub consecutive_bad_requests: u32,
    pub escalation_level: u8,
    pub jailed_until: Option<Instant>,
    pub permanently_locked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUsage {
    pub name: Option<String>,
    pub used_requests: u64,
    pub max_requests_per_month: Option<u64>,
    /// 按操作类型分类的 30 天滚动用量（ISSUE-0009）：
    /// `search_usage` 只含 /search，依此类推；总账 = 各类之和（历史无分类数据除外）。
    pub categories: BTreeMap<UsageCategory, u64>,
}

struct ProxyKeyState {
    name: Option<String>,
    max_requests_per_month: Option<u64>,
    bucket: TokenUsageBucket,
    rate_limiter: Option<Arc<TokenBucket>>,
    max_concurrency: Option<usize>,
    active_concurrency: usize,
    penalty: PenaltyBox,
}

pub struct Auth {
    keys: Arc<Mutex<HashMap<String, ProxyKeyState>>>,
    storage_path: Option<PathBuf>,
    retention_days: u32,
    max_file_size_bytes: usize,
    dirty: Arc<AtomicBool>,
}

pub enum AuthResult {
    Ok {
        name: Option<String>,
    },
    InvalidKey,
    QuotaExceeded {
        name: Option<String>,
    },
    Jailed {
        escalation_level: u8,
        unlock_in_secs: Option<u64>,
    },
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
    Jailed {
        escalation_level: u8,
        unlock_in_secs: Option<u64>,
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
    /// 本请求的操作类型，结算时归入对应分类账（ISSUE-0009）。
    category: UsageCategory,
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
            self.auth.commit_quota_reservation(&self.key, self.category);
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
                    penalty: PenaltyBox::default(),
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
        let mut keys = self.keys.lock();
        match keys.get_mut(key) {
            None => AuthResult::InvalidKey,
            Some(state) => {
                if state.penalty.permanently_locked {
                    return AuthResult::Jailed {
                        escalation_level: state.penalty.escalation_level,
                        unlock_in_secs: None,
                    };
                }
                if let Some(until) = state.penalty.jailed_until {
                    let now = Instant::now();
                    if now < until {
                        let remaining = (until - now).as_secs().max(1);
                        return AuthResult::Jailed {
                            escalation_level: state.penalty.escalation_level,
                            unlock_in_secs: Some(remaining),
                        };
                    } else {
                        state.penalty.jailed_until = None;
                    }
                }

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
        category: UsageCategory,
        max_wait: Duration,
    ) -> Result<SlotGuard, SlotAcquireResult> {
        let today = Utc::now().date_naive();
        let (name, rate_limiter) = {
            let mut keys = self.keys.lock();
            let Some(state) = keys.get_mut(key) else {
                return Err(SlotAcquireResult::InvalidKey);
            };

            if state.penalty.permanently_locked {
                return Err(SlotAcquireResult::Jailed {
                    escalation_level: state.penalty.escalation_level,
                    unlock_in_secs: None,
                });
            }
            if let Some(until) = state.penalty.jailed_until {
                let now = Instant::now();
                if now < until {
                    let remaining = (until - now).as_secs().max(1);
                    return Err(SlotAcquireResult::Jailed {
                        escalation_level: state.penalty.escalation_level,
                        unlock_in_secs: Some(remaining),
                    });
                } else {
                    state.penalty.jailed_until = None;
                }
            }

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
            category,
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

    pub fn commit_quota_reservation(&self, key: &str, category: UsageCategory) {
        let today = Utc::now().date_naive();
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(key) {
            state.bucket.in_flight = state.bucket.in_flight.saturating_sub(1);
            state.bucket.record_settled(today, category);
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

    pub fn record_usage(&self, key: &str, category: UsageCategory) {
        let today = Utc::now().date_naive();
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(key) {
            state.bucket.record_settled(today, category);
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
            categories: crate::quota::USAGE_CATEGORIES
                .iter()
                .map(|&category| {
                    (
                        category,
                        state.bucket.settled_in_window_by_category(today, category),
                    )
                })
                .collect(),
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

    /// Record a client-side bad request (4xx).
    ///
    /// Escalates through progressive penalty levels (5m -> 1h -> 24h -> permanent)
    /// if consecutive bad requests hit `PENALTY_CONSECUTIVE_THRESHOLD`.
    pub fn record_bad_request(&self, key: &str) {
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(key) {
            state.penalty.consecutive_bad_requests += 1;
            if state.penalty.consecutive_bad_requests >= PENALTY_CONSECUTIVE_THRESHOLD {
                state.penalty.consecutive_bad_requests = 0;
                state.penalty.escalation_level = (state.penalty.escalation_level + 1).min(4);
                match state.penalty.escalation_level {
                    1 => {
                        state.penalty.jailed_until =
                            Some(Instant::now() + PENALTY_LEVEL_1_DURATION);
                    }
                    2 => {
                        state.penalty.jailed_until =
                            Some(Instant::now() + PENALTY_LEVEL_2_DURATION);
                    }
                    3 => {
                        state.penalty.jailed_until =
                            Some(Instant::now() + PENALTY_LEVEL_3_DURATION);
                    }
                    _ => {
                        state.penalty.permanently_locked = true;
                        state.penalty.jailed_until = None;
                    }
                }
                warn!(
                    proxy_key = %crate::key_pool::mask_key(key),
                    level = state.penalty.escalation_level,
                    permanently_locked = state.penalty.permanently_locked,
                    "proxy key jailed due to excessive consecutive bad requests"
                );
            }
        }
    }

    /// Record a successful request (200), resetting consecutive bad requests counter.
    pub fn record_success(&self, key: &str) {
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(key) {
            state.penalty.consecutive_bad_requests = 0;
        }
    }

    /// Reset penalty state for a given proxy key (administrator / testing unjail).
    pub fn reset_penalty(&self, key: &str) {
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(key) {
            state.penalty = PenaltyBox::default();
        }
    }

    /// Inspect penalty box state for observation and testing.
    pub fn get_penalty_box(&self, key: &str) -> Option<PenaltyBox> {
        let keys = self.keys.lock();
        keys.get(key).map(|s| s.penalty.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_penalty_box_escalation_ladder() {
        let cfg = ProxyKeyConfig {
            key: "test-client-key".to_string(),
            name: Some("test-client".to_string()),
            max_requests_per_month: None,
            rpm: None,
            max_concurrency: None,
            filter: None,
        };
        let auth = Arc::new(Auth::new(&[cfg]));

        // Normal authentication should succeed
        assert!(matches!(
            auth.authenticate("test-client-key"),
            AuthResult::Ok { .. }
        ));

        // Trigger Level 1 penalty: 60 bad requests
        for _ in 0..PENALTY_CONSECUTIVE_THRESHOLD {
            auth.record_bad_request("test-client-key");
        }
        match auth.authenticate("test-client-key") {
            AuthResult::Jailed {
                escalation_level,
                unlock_in_secs,
            } => {
                assert_eq!(escalation_level, 1);
                assert!(unlock_in_secs.is_some());
            }
            _ => panic!("expected Level 1 jail"),
        }

        // Fast-forward or trigger Level 2
        for _ in 0..PENALTY_CONSECUTIVE_THRESHOLD {
            auth.record_bad_request("test-client-key");
        }
        match auth.authenticate("test-client-key") {
            AuthResult::Jailed {
                escalation_level, ..
            } => {
                assert_eq!(escalation_level, 2);
            }
            _ => panic!("expected Level 2 jail"),
        }

        // Trigger Level 3
        for _ in 0..PENALTY_CONSECUTIVE_THRESHOLD {
            auth.record_bad_request("test-client-key");
        }
        assert!(matches!(
            auth.authenticate("test-client-key"),
            AuthResult::Jailed {
                escalation_level: 3,
                ..
            }
        ));

        // Trigger Level 4: permanent lock
        for _ in 0..PENALTY_CONSECUTIVE_THRESHOLD {
            auth.record_bad_request("test-client-key");
        }
        match auth.authenticate("test-client-key") {
            AuthResult::Jailed {
                escalation_level,
                unlock_in_secs,
            } => {
                assert_eq!(escalation_level, 4);
                assert_eq!(unlock_in_secs, None); // permanent!
            }
            _ => panic!("expected permanent lock"),
        }

        // Reset penalty unjails the client
        auth.reset_penalty("test-client-key");
        assert!(matches!(
            auth.authenticate("test-client-key"),
            AuthResult::Ok { .. }
        ));
    }
}
