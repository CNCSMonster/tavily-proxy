use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{info, warn};

use crate::config::TavilyKeyConfig;

struct KeyState {
    key: String,
    max_requests: Option<u64>,
    used_requests: u64,
    status: KeyStatus,
}

#[derive(Clone, Debug)]
enum KeyStatus {
    Available,
    Cooldown { until: Instant },
    Exhausted,
}

pub struct KeyPool {
    keys: Mutex<Vec<KeyState>>,
    current_index: Mutex<usize>,
}

impl KeyPool {
    pub fn new(configs: &[TavilyKeyConfig]) -> Self {
        let keys = configs
            .iter()
            .map(|c| KeyState {
                key: c.key.clone(),
                max_requests: c.max_requests,
                used_requests: 0,
                status: KeyStatus::Available,
            })
            .collect();

        Self {
            keys: Mutex::new(keys),
            current_index: Mutex::new(0),
        }
    }

    pub fn get_key(&self) -> Option<String> {
        let mut keys = self.keys.lock();
        let mut idx = self.current_index.lock();
        let len = keys.len();
        let now = Instant::now();

        for _ in 0..len {
            let state = &mut keys[*idx];

            // Check cooldown expiry
            if let KeyStatus::Cooldown { until } = state.status {
                if now >= until {
                    let masked = mask_key(&state.key);
                    info!(key = %masked, "key cooldown expired, now available");
                    state.status = KeyStatus::Available;
                }
            }

            match state.status {
                KeyStatus::Available => {
                    let over_limit = state
                        .max_requests
                        .is_some_and(|max| state.used_requests >= max);

                    if over_limit {
                        state.status = KeyStatus::Exhausted;
                        let masked = mask_key(&state.key);
                        warn!(key = %masked, "key marked as exhausted (local quota reached)");
                        *idx = (*idx + 1) % len;
                        continue;
                    }

                    return Some(state.key.clone());
                }
                KeyStatus::Cooldown { .. } | KeyStatus::Exhausted => {
                    *idx = (*idx + 1) % len;
                }
            }
        }

        None
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

    /// Mark the current key as temporarily rate-limited (429).
    /// It will become available again after `cooldown` duration.
    pub fn mark_cooldown(&self, cooldown: Duration) {
        let mut keys = self.keys.lock();
        let mut idx = self.current_index.lock();
        let len = keys.len();
        if let Some(state) = keys.get_mut(*idx) {
            state.status = KeyStatus::Cooldown {
                until: Instant::now() + cooldown,
            };
            let masked = mask_key(&state.key);
            warn!(key = %masked, cooldown_secs = cooldown.as_secs(), "key in cooldown (rate limited)");
        }
        *idx = (*idx + 1) % len;
        let masked = mask_key(&keys[*idx].key);
        info!(next_key = %masked, "rotated to next key after cooldown");
    }

    /// Mark the current key as permanently exhausted for this cycle (432/433).
    pub fn mark_exhausted_current(&self) {
        let mut keys = self.keys.lock();
        let mut idx = self.current_index.lock();
        let len = keys.len();
        if let Some(state) = keys.get_mut(*idx) {
            state.status = KeyStatus::Exhausted;
            let masked = mask_key(&state.key);
            warn!(key = %masked, "key marked as exhausted (monthly quota depleted)");
        }
        *idx = (*idx + 1) % len;
        let masked = mask_key(&keys[*idx].key);
        info!(next_key = %masked, "rotated to next key after exhaustion");
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
        *idx = (*idx + 1) % len;
        let masked = mask_key(&keys[*idx].key);
        info!(next_key = %masked, "rotated to next key");
    }

    pub fn current_index(&self) -> usize {
        *self.current_index.lock()
    }

    pub fn total_keys(&self) -> usize {
        self.keys.lock().len()
    }

    pub fn available_keys(&self) -> usize {
        let now = Instant::now();
        self.keys
            .lock()
            .iter()
            .filter(|k| match k.status {
                KeyStatus::Available => true,
                KeyStatus::Cooldown { until } => now >= until,
                KeyStatus::Exhausted => false,
            })
            .count()
    }
}

fn mask_key(key: &str) -> String {
    if key.len() <= 10 {
        return "***".to_string();
    }
    format!("{}...{}", &key[..7], &key[key.len() - 4..])
}
