use parking_lot::Mutex;
use std::time::{Duration, Instant};

/// Default rate limit for Tavily free/dev keys (`tvly-dev-` prefix):
/// upstream limit is 100 RPM; with 10% safety margin we cap at 90 RPM.
pub const DEFAULT_DEV_RPM: u32 = 90;

/// Default rate limit for Tavily production keys:
/// upstream limit is 1000 RPM; with 10% safety margin we cap at 900 RPM.
pub const DEFAULT_PROD_RPM: u32 = 900;

/// Deduce safe default RPM from a Tavily API key prefix.
pub fn default_rpm_for_key(key: &str) -> u32 {
    if key.starts_with("tvly-dev-") {
        DEFAULT_DEV_RPM
    } else {
        DEFAULT_PROD_RPM
    }
}

/// Token bucket rate limiter.
///
/// Smoothly refills tokens over time up to capacity (equal to RPM).
/// An RPM of 0 disables rate limiting entirely.
#[derive(Debug)]
pub struct TokenBucket {
    rpm: u32,
    capacity: f64,
    refill_rate_per_sec: f64,
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    pub fn new(rpm: u32) -> Self {
        let capacity = rpm as f64;
        let refill_rate_per_sec = if rpm > 0 { rpm as f64 / 60.0 } else { 0.0 };
        let now = Instant::now();

        Self {
            rpm,
            capacity,
            refill_rate_per_sec,
            state: Mutex::new(BucketState {
                tokens: capacity,
                last_update: now,
            }),
        }
    }

    pub fn rpm(&self) -> u32 {
        self.rpm
    }

    /// Estimate wait time until at least 1.0 token is available.
    pub fn estimate_wait(&self) -> Duration {
        if self.rpm == 0 {
            return Duration::ZERO;
        }

        let now = Instant::now();
        let mut state = self.state.lock();
        self.refill(&mut state, now);

        if state.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let needed = 1.0 - state.tokens;
            let wait_secs = needed / self.refill_rate_per_sec;
            Duration::from_secs_f64(wait_secs)
        }
    }

    /// Try to acquire one token without waiting. Returns true if acquired.
    pub fn try_acquire(&self) -> bool {
        if self.rpm == 0 {
            return true;
        }

        let now = Instant::now();
        let mut state = self.state.lock();
        self.refill(&mut state, now);

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Acquire one token, waiting up to `max_wait` if the bucket is temporarily empty.
    ///
    /// If the required wait is within `max_wait`, reserves the slot and sleeps asynchronously.
    /// If the required wait exceeds `max_wait`, returns `Err(wait_needed)` without deducting.
    pub async fn acquire(&self, max_wait: Duration) -> Result<(), Duration> {
        if self.rpm == 0 {
            return Ok(());
        }

        let wait_time = {
            let now = Instant::now();
            let mut state = self.state.lock();
            self.refill(&mut state, now);

            if state.tokens >= 1.0 {
                state.tokens -= 1.0;
                Duration::ZERO
            } else {
                let needed = 1.0 - state.tokens;
                let wait_secs = needed / self.refill_rate_per_sec;
                let wait_duration = Duration::from_secs_f64(wait_secs);

                if wait_duration <= max_wait {
                    // Reserve the token
                    state.tokens -= 1.0;
                    wait_duration
                } else {
                    return Err(wait_duration);
                }
            }
        };

        if wait_time > Duration::ZERO {
            tokio::time::sleep(wait_time).await;
        }

        Ok(())
    }

    fn refill(&self, state: &mut BucketState, now: Instant) {
        if now > state.last_update {
            let elapsed = now.duration_since(state.last_update).as_secs_f64();
            state.tokens = (state.tokens + elapsed * self.refill_rate_per_sec).min(self.capacity);
            state.last_update = now;
        }
    }
}
