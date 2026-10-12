use parking_lot::Mutex;
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

use crate::config::{Config, TavilyKeyConfig};
use crate::quota_cycle::next_monthly_reset;
use crate::rate_limiter::{DEFAULT_DEV_RPM, TokenBucket, default_rpm_for_key};

struct KeyState {
    key: String,
    max_requests: Option<u64>,
    used_requests: u64,
    status: KeyStatus,
    /// When an upstream 432/433 (`Exhausted`) key may be tried again: the next
    /// monthly quota reset (ISSUE-0014). `None` = never — either the local
    /// `max_requests` fuse (instance lifetime) or `Revoked` (401).
    exhausted_until: Option<SystemTime>,
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
                exhausted_until: None,
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
        reactivate_due_keys(&mut keys);

        for _ in 0..len {
            let state = &mut keys[*idx];

            match state.status {
                KeyStatus::Available => {
                    let over_limit = state
                        .max_requests
                        .is_some_and(|max| state.used_requests >= max);

                    if over_limit {
                        state.status = KeyStatus::Exhausted;
                        state.exhausted_until = None;
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

    pub fn record_usage_for_key(&self, key: &str) {
        let mut keys = self.keys.lock();
        if let Some(state) = keys.iter_mut().find(|k| k.key == key) {
            state.used_requests += 1;
            let masked = mask_key(&state.key);
            info!(key = %masked, used = state.used_requests, "recorded usage for key");
        } else {
            let idx = *self.current_index.lock();
            if let Some(state) = keys.get_mut(idx) {
                state.used_requests += 1;
                let masked = mask_key(&state.key);
                info!(key = %masked, used = state.used_requests, "recorded usage (fallback index)");
            }
        }
    }

    /// Mark the current key exhausted for the rest of the billing month
    /// (432/433): it rejoins rotation at the monthly quota reset (ISSUE-0014).
    ///
    /// **Test-sim only.** Production 432/433 paths use the identity variant
    /// [`Self::mark_exhausted_key`] — under concurrency the index has usually
    /// already rotated past the key that actually failed (ISSUE-0017).
    pub fn mark_exhausted_current(&self) {
        let mut keys = self.keys.lock();
        let mut idx = self.current_index.lock();
        let len = keys.len();
        if len == 0 {
            return;
        }
        if let Some(state) = keys.get_mut(*idx) {
            let until = next_monthly_reset(SystemTime::now());
            state.status = KeyStatus::Exhausted;
            state.exhausted_until = Some(until);
            let masked = mask_key(&state.key);
            warn!(
                key = %masked,
                reset_utc = ?until,
                "key marked as exhausted (monthly quota depleted); reactivates at monthly reset"
            );
        }
        *idx = (*idx + 1) % len;
        let masked = mask_key(&keys[*idx].key);
        info!(next_key = %masked, "rotated to next key after exhaustion");
    }

    /// Mark the current key as revoked upstream (401) and rotate away from it.
    ///
    /// **Test-sim only** — production uses [`Self::mark_revoked_key`]
    /// (ISSUE-0017).
    pub fn mark_revoked_current(&self) {
        let mut keys = self.keys.lock();
        let mut idx = self.current_index.lock();
        let len = keys.len();
        if len == 0 {
            return;
        }
        if let Some(state) = keys.get_mut(*idx) {
            state.status = KeyStatus::Revoked;
            state.exhausted_until = None;
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
            state.exhausted_until = Some(next_monthly_reset(SystemTime::now()));
            let masked = mask_key(&state.key);
            warn!(key = %masked, "key marked as exhausted");
        }
    }

    /// Mark a **specific** key exhausted (432/433) until the monthly reset
    /// (ISSUE-0014). Identity-based: a concurrent cohort of 432s must never
    /// mark whatever index the rotation happens to point at (ISSUE-0017).
    pub fn mark_exhausted_key(&self, key: &str) {
        let mut keys = self.keys.lock();
        let Some(idx) = keys.iter().position(|k| k.key == key) else {
            warn!(key = %mask_key(key), "432 for a key not in the pool; ignoring");
            return;
        };
        {
            let state = &mut keys[idx];
            if state.status != KeyStatus::Exhausted {
                let until = next_monthly_reset(SystemTime::now());
                state.status = KeyStatus::Exhausted;
                state.exhausted_until = Some(until);
                let masked = mask_key(&state.key);
                warn!(
                    key = %masked,
                    reset_utc = ?until,
                    "key marked as exhausted (monthly quota depleted); reactivates at monthly reset"
                );
            }
        }
        let mut cur = self.current_index.lock();
        if *cur == idx {
            *cur = (idx + 1) % keys.len();
            let masked = mask_key(&keys[*cur].key);
            info!(next_key = %masked, "rotated to next key after exhaustion");
        }
    }

    /// Mark a **specific** key revoked (401) — permanent, never reactivates.
    /// Identity-based for the same reason as [`Self::mark_exhausted_key`].
    pub fn mark_revoked_key(&self, key: &str) {
        let mut keys = self.keys.lock();
        let Some(idx) = keys.iter().position(|k| k.key == key) else {
            warn!(key = %mask_key(key), "401 for a key not in the pool; ignoring");
            return;
        };
        {
            let state = &mut keys[idx];
            if state.status != KeyStatus::Revoked {
                state.status = KeyStatus::Revoked;
                state.exhausted_until = None;
                let masked = mask_key(&state.key);
                warn!(key = %masked, "key revoked upstream (401), removed from rotation");
            }
        }
        let mut cur = self.current_index.lock();
        if *cur == idx {
            *cur = (idx + 1) % keys.len();
            let masked = mask_key(&keys[*cur].key);
            info!(next_key = %masked, "rotated to next key after revocation");
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
        let mut keys = self.keys.lock();
        reactivate_due_keys(&mut keys);
        keys.iter()
            .filter(|k| matches!(k.status, KeyStatus::Available))
            .count()
    }

    pub fn all_terminally_dead(&self) -> bool {
        let mut keys = self.keys.lock();
        reactivate_due_keys(&mut keys);
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

/// Sweep: an `Exhausted` (432/433) key whose monthly reset deadline has
/// passed rejoins the pool (ISSUE-0014). `Revoked` (401) and the local
/// `max_requests` fuse carry no deadline and never revive.
fn reactivate_due_keys(keys: &mut [KeyState]) {
    let now = SystemTime::now();
    for state in keys.iter_mut() {
        if state.status == KeyStatus::Exhausted
            && let Some(until) = state.exhausted_until
            && now >= until
        {
            state.status = KeyStatus::Available;
            state.exhausted_until = None;
            info!(
                key = %mask_key(&state.key),
                "monthly reset reached; exhausted key reactivated"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_key_pool() -> KeyPool {
        KeyPool::with_rpm(&[TavilyKeyConfig::new("tvly-virtual-unit-test")], 0)
    }

    #[test]
    fn exhausted_key_frozen_until_a_future_monthly_reset() {
        let pool = single_key_pool();
        pool.mark_exhausted_current();
        assert_eq!(
            pool.get_key(),
            None,
            "432 key must stay out before the reset"
        );
        let until = pool.keys.lock()[0].exhausted_until;
        let until = until.expect("432 sets a reset deadline");
        assert!(until > SystemTime::now(), "deadline must be in the future");
        assert!(pool.all_terminally_dead(), "still dead while frozen");
    }

    #[test]
    fn exhausted_key_reactivates_once_reset_passed() {
        let pool = single_key_pool();
        pool.mark_exhausted_current();
        // Simulate the monthly reset having arrived.
        pool.keys.lock()[0].exhausted_until = Some(SystemTime::now() - Duration::from_secs(1));
        assert_eq!(pool.get_key().as_deref(), Some("tvly-virtual-unit-test"));
        assert!(
            pool.keys.lock()[0].exhausted_until.is_none(),
            "deadline cleared"
        );
        assert_eq!(pool.available_keys(), 1);
    }

    #[test]
    fn all_dead_fast_path_wakes_up_after_reset() {
        let pool = single_key_pool();
        pool.mark_exhausted_current();
        assert!(pool.all_terminally_dead(), "503 fast-path while frozen");
        pool.keys.lock()[0].exhausted_until = Some(SystemTime::now() - Duration::from_secs(1));
        assert!(
            !pool.all_terminally_dead(),
            "fast-path must not stick after reset"
        );
    }

    #[test]
    fn revoked_key_never_reactivates() {
        let pool = single_key_pool();
        pool.mark_revoked_current();
        assert_eq!(pool.get_key(), None);
        assert!(pool.keys.lock()[0].exhausted_until.is_none());
    }

    #[test]
    fn local_fuse_is_permanent_for_the_instance() {
        let pool = KeyPool::with_rpm(
            &[TavilyKeyConfig::new("tvly-virtual-unit-test").with_limit(0)],
            0,
        );
        assert_eq!(pool.get_key(), None);
        assert!(
            pool.keys.lock()[0].exhausted_until.is_none(),
            "no calendar revival for the local max_requests fuse"
        );
    }

    fn two_key_pool() -> KeyPool {
        KeyPool::with_rpm(
            &[
                TavilyKeyConfig::new("tvly-virtual-bench-1"),
                TavilyKeyConfig::new("tvly-virtual-bench-2"),
            ],
            0,
        )
    }

    #[test]
    fn duplicate_cohort_432_marks_only_the_failing_key() {
        let pool = two_key_pool();
        // Two 432s for the same key, as a concurrent cohort of requests would
        // deliver: the index has already rotated after the first, so a
        // downstream caller re-marking by index would hit the innocent key.
        pool.mark_exhausted_key("tvly-virtual-bench-1");
        pool.mark_exhausted_key("tvly-virtual-bench-1");
        assert_eq!(
            pool.available_keys(),
            1,
            "the innocent key must survive a duplicate cohort 432"
        );
        assert_eq!(pool.get_key().as_deref(), Some("tvly-virtual-bench-2"));
        assert!(!pool.all_terminally_dead());
    }

    #[test]
    fn mark_exhausted_key_unknown_is_noop() {
        let pool = single_key_pool();
        pool.mark_exhausted_key("tvly-virtual-nope");
        assert_eq!(
            pool.available_keys(),
            1,
            "an unknown key must not exhaust anything"
        );
        assert_eq!(pool.get_key().as_deref(), Some("tvly-virtual-unit-test"));
    }

    #[test]
    fn cohort_revoked_marks_only_the_failing_key() {
        let pool = two_key_pool();
        pool.mark_revoked_key("tvly-virtual-bench-1");
        pool.mark_revoked_key("tvly-virtual-bench-1");
        assert_eq!(
            pool.available_keys(),
            1,
            "the innocent key must survive a repeated 401 for its peer"
        );
        assert_eq!(pool.get_key().as_deref(), Some("tvly-virtual-bench-2"));
    }
}
