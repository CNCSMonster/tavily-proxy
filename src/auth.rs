use parking_lot::Mutex;
use std::collections::HashMap;
use tracing::warn;

use crate::config::ProxyKeyConfig;

struct ProxyKeyState {
    name: Option<String>,
    max_requests_per_month: Option<u64>,
    used_requests: u64,
}

pub struct Auth {
    keys: Mutex<HashMap<String, ProxyKeyState>>,
}

pub enum AuthResult {
    Ok { name: Option<String> },
    InvalidKey,
    QuotaExceeded { name: Option<String> },
}

impl Auth {
    pub fn new(configs: &[ProxyKeyConfig]) -> Self {
        let mut keys = HashMap::new();
        for c in configs {
            keys.insert(
                c.key.clone(),
                ProxyKeyState {
                    name: c.name.clone(),
                    max_requests_per_month: c.max_requests_per_month,
                    used_requests: 0,
                },
            );
        }
        Self {
            keys: Mutex::new(keys),
        }
    }

    pub fn authenticate(&self, key: &str) -> AuthResult {
        let keys = self.keys.lock();
        match keys.get(key) {
            None => AuthResult::InvalidKey,
            Some(state) => {
                if let Some(max) = state.max_requests_per_month {
                    if state.used_requests >= max {
                        warn!(
                            proxy_key_name = state.name.as_deref().unwrap_or("unnamed"),
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

    pub fn record_usage(&self, key: &str) {
        let mut keys = self.keys.lock();
        if let Some(state) = keys.get_mut(key) {
            state.used_requests += 1;
        }
    }
}
