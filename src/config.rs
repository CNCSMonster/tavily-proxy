use serde::Deserialize;
use std::path::Path;

use crate::filter::FilterConfig;
use crate::redact::{literal_secrets_in_toml, redact_literals, redact_secrets};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tavily_keys: Vec<TavilyKeyConfig>,
    pub proxy_keys: Vec<ProxyKeyConfig>,
    /// Content safety checks. Absent means no checks at all: filtering is opt-in.
    pub filter: Option<FilterConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
}

#[derive(Debug, Deserialize)]
pub struct TavilyKeyConfig {
    pub key: String,
    pub max_requests: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ProxyKeyConfig {
    pub key: String,
    pub name: Option<String>,
    pub max_requests_per_month: Option<u64>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|err| anyhow::anyhow!("failed to read {}: {err}", path.display()))?;
        let config: Config = toml::from_str(&content).map_err(|err| {
            // A TOML parse error quotes the offending source line, which can be a
            // key line; scrub it before it can reach a terminal or the log file.
            // The parsed values do not exist yet — this is the parse that failed —
            // so candidate secrets are read off the text by key name first.
            let literals = literal_secrets_in_toml(&content);
            let values: Vec<&str> = literals.iter().map(String::as_str).collect();
            anyhow::anyhow!(
                "failed to parse {}: {}",
                path.display(),
                redact_secrets(&redact_literals(&err.to_string(), &values))
            )
        })?;
        config.validate()?;
        config.warn_insecure_settings(path);
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.tavily_keys.is_empty(),
            "at least one tavily key must be configured"
        );
        anyhow::ensure!(
            !self.proxy_keys.is_empty(),
            "at least one proxy key must be configured"
        );
        for (i, tk) in self.tavily_keys.iter().enumerate() {
            anyhow::ensure!(
                tk.key.starts_with("tvly-"),
                "tavily_keys[{i}]: key should start with 'tvly-'"
            );
        }
        Ok(())
    }

    /// Report the two settings that let a backend key escape. Neither stops the
    /// service, so they are warnings rather than errors.
    pub fn warn_insecure_settings(&self, path: &Path) {
        if let Some(mode) = loose_mode(path) {
            tracing::warn!(
                path = %path.display(),
                mode = %format!("{mode:o}"),
                "config file is readable by other users; run `chmod 600 {}` — it holds backend Tavily keys",
                path.display()
            );
        }
        if !listens_on_loopback(&self.server.listen) {
            tracing::warn!(
                listen = %self.server.listen,
                "listening on a non-loopback address; the client key travels in plaintext and this service has no TLS — put a TLS reverse proxy in front before exposing it"
            );
        }
    }
}

/// Permission bits readable by group or other, if any.
#[cfg(unix)]
fn loose_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let mode = std::fs::metadata(path).ok()?.mode() & 0o777;
    (mode & 0o077 != 0).then_some(mode)
}

#[cfg(not(unix))]
fn loose_mode(_path: &Path) -> Option<u32> {
    None
}

fn listens_on_loopback(listen: &str) -> bool {
    let Some((host, _port)) = listen.rsplit_once(':') else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}
