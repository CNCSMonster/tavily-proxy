use serde::Deserialize;
use std::path::Path;

use crate::filter::FilterConfig;
use crate::rate_limiter::{DEFAULT_DEV_RPM, default_rpm_for_key};
use crate::redact::{literal_secrets_in_toml, redact_literals, redact_secrets};

/// Every section is parsed strictly (`deny_unknown_fields`): a field name nobody
/// typo-checks is a control that silently stops working, which is worse than a
/// refused start. Deprecated fields are the one exception — they still parse,
/// and [`Config::deprecations`] reports them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    /// Upstream budget. Absent means the bucket size is deduced (see
    /// [`Config::resolve_upstream_rpm`]).
    pub upstream: Option<UpstreamConfig>,
    #[serde(default)]
    pub tavily_keys: Vec<TavilyKeyConfig>,
    /// Deprecated label-only grouping (ADR-0003). Parsed for one more release,
    /// then rejected.
    #[serde(default)]
    pub groups: Vec<GroupConfig>,
    pub proxy_keys: Vec<ProxyKeyConfig>,
    /// Optional storage settings (e.g. quota state file location).
    #[serde(default)]
    pub storage: Option<StorageConfig>,
    /// Content safety checks. Absent means no checks at all: filtering is opt-in.
    pub filter: Option<FilterConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
}

/// The `[upstream]` section: the single rate bucket shared by every pooled key.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Requests per minute this service may send to Tavily. Upstream counts
    /// against the egress IP, so this is one IP's budget, not one key's.
    /// `0` disables rate limiting.
    pub rpm: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupConfig {
    pub name: String,
    /// Deprecated: the bucket is per IP, not per group (ADR-0003).
    pub rpm: Option<u32>,
    #[serde(default)]
    pub keys: Vec<TavilyKeyConfig>,
}

pub const DEFAULT_RETENTION_DAYS: u32 = 365;
pub const DEFAULT_MAX_FILE_SIZE_MB: u32 = 10;

fn default_retention_days() -> u32 {
    DEFAULT_RETENTION_DAYS
}

fn default_max_file_size_mb() -> u32 {
    DEFAULT_MAX_FILE_SIZE_MB
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub quota_file: Option<std::path::PathBuf>,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            quota_file: None,
            retention_days: DEFAULT_RETENTION_DAYS,
            max_file_size_mb: DEFAULT_MAX_FILE_SIZE_MB,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TavilyKeyConfig {
    pub key: String,
    /// 单进程生命周期累计请求上限（熔断保险丝，0 或 None 表示无限制）。
    /// 注意：这不是月度配额。真实月度配额耗尽由上游 432/433 响应自动驱动封锁，
    /// 此处仅作单进程实例生命周期内的异常失控应急防护。
    #[serde(default)]
    pub max_requests: Option<u64>,
    /// Deprecated label (ADR-0003): the pool is flat and this schedules nothing.
    #[serde(default)]
    pub group: Option<String>,
    /// Deprecated: use `[upstream] rpm` — a per-key limit was never a thing,
    /// the value only ever reached the group bucket it belonged to.
    #[serde(default)]
    pub rpm: Option<u32>,
}

impl TavilyKeyConfig {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            max_requests: None,
            group: None,
            rpm: None,
        }
    }

    pub fn with_limit(mut self, max: u64) -> Self {
        self.max_requests = Some(max);
        self
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyKeyConfig {
    pub key: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub max_requests_per_month: Option<u64>,
    #[serde(default)]
    pub rpm: Option<u32>,
    #[serde(default)]
    pub max_concurrency: Option<usize>,
    /// Which filter rules judge this token's requests, in order.
    ///
    /// Absent = inherit the global chain (today's behaviour); an explicit empty
    /// list = this token is exempt from checks. See ISSUE-0006.
    #[serde(default)]
    pub filter: Option<Vec<String>>,
}

impl ProxyKeyConfig {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            name: None,
            max_requests_per_month: None,
            rpm: None,
            max_concurrency: None,
            filter: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_limit(mut self, max: u64) -> Self {
        self.max_requests_per_month = Some(max);
        self
    }

    pub fn with_rpm(mut self, rpm: u32) -> Self {
        self.rpm = Some(rpm);
        self
    }

    pub fn with_max_concurrency(mut self, max: usize) -> Self {
        self.max_concurrency = Some(max);
        self
    }
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
            // Name the table the parser tripped in: `unknown field 'x'` alone
            // cannot say *which* `[[filter.rules]]` entry it was (ISSUE-0012).
            let located = err
                .span()
                .map(|span| table_location(&content, span.end))
                .unwrap_or_default();
            anyhow::anyhow!(
                "failed to parse {}: {located}{}",
                path.display(),
                redact_secrets(&redact_literals(&err.to_string(), &values))
            )
        })?;
        config.validate()?;
        config.warn_insecure_settings(path);
        Ok(config)
    }

    /// The pool, in the order the key lane serves it.
    ///
    /// Order is the one `[[groups]]` used to produce, so a config written for
    /// lanes keeps the same key sequence and the same rotation: declared groups
    /// in declaration order, each group's own keys first, then `[[tavily_keys]]`
    /// appended to the lane it was tagged into (ungtagged keys to `default`).
    pub fn flatten_keys(&self) -> Vec<TavilyKeyConfig> {
        self.flatten_lanes().into_iter().map(|k| k.0).collect()
    }

    fn flatten_lanes(&self) -> Vec<(TavilyKeyConfig, bool)> {
        let mut lanes: Vec<(&str, Vec<(TavilyKeyConfig, bool)>)> = Vec::new();

        for g in &self.groups {
            let keys = g.keys.iter().cloned().map(|k| (k, true));
            match lanes.iter_mut().find(|(name, _)| *name == g.name) {
                Some((_, existing)) => existing.extend(keys),
                None => lanes.push((g.name.as_str(), keys.collect())),
            }
        }

        for tk in &self.tavily_keys {
            let lane = tk.group.as_deref().unwrap_or("default");
            match lanes.iter_mut().find(|(name, _)| *name == lane) {
                Some((_, existing)) => existing.push((tk.clone(), false)),
                None => lanes.push((lane, vec![(tk.clone(), false)])),
            }
        }

        lanes.into_iter().flat_map(|(_, keys)| keys).collect()
    }

    /// Size of the single upstream bucket, in requests per minute.
    ///
    /// Explicit `[upstream] rpm` wins; otherwise the smallest deprecated
    /// per-key/per-group `rpm` (a config that named several must not end up with
    /// a bucket above any one of them); otherwise the first key's plan default.
    pub fn resolve_upstream_rpm(&self) -> u32 {
        self.upstream_budget().0
    }

    /// The bucket size and, for the operator-facing lines, which rule produced
    /// it — the resolution order above, stated once.
    pub fn upstream_budget(&self) -> (u32, &'static str) {
        if let Some(rpm) = self.upstream.as_ref().and_then(|u| u.rpm) {
            return (rpm, "[upstream] rpm 显式设置");
        }

        let deprecated = self
            .groups
            .iter()
            .filter_map(|g| g.rpm)
            .chain(self.tavily_keys.iter().filter_map(|k| k.rpm));
        if let Some(min) = deprecated.min() {
            return (min, "已弃用 rpm 的最小值");
        }

        let rpm = self
            .flatten_keys()
            .first()
            .map(|k| default_rpm_for_key(&k.key))
            .unwrap_or(DEFAULT_DEV_RPM);
        (rpm, "按首个 key 前缀取默认")
    }

    /// Deprecated fields this config still uses: warnings, never errors, until
    /// the format drops them.
    pub fn deprecations(&self) -> Vec<String> {
        let mut out = Vec::new();

        if !self.groups.is_empty() {
            out.push(format!(
                "[[groups]] 已弃用（ADR-0003）：配置写了 {} 个组。上游按出口 IP 计限，分组不增加容量；\
                 本版本起拍平为单池（顺序不变），组名仅作标签并告警，下一版将拒绝启动。预算请用 \
                 [upstream] rpm 显式设置。",
                self.groups.len()
            ));
        }

        for g in &self.groups {
            if g.rpm.is_some() {
                out.push(format!(
                    "[[groups]] \"{}\" 的 rpm 已弃用：只有一个桶（该出口 IP 的预算），\
                     多组取值以最小值兜底；请改用 [upstream] rpm。",
                    g.name
                ));
            }
        }

        for (i, tk) in self.tavily_keys.iter().enumerate() {
            if tk.group.is_some() {
                out.push(format!(
                    "tavily_keys[{i}].group 已弃用：池已平铺（ADR-0003），分组名不再参与调度，\
                     请删除该字段。"
                ));
            }
            if tk.rpm.is_some() {
                out.push(format!(
                    "tavily_keys[{i}].rpm 已弃用：per-key 限速从未存在（值只流向它所在的组桶），\
                     请改用 [upstream] rpm。"
                ));
            }
        }

        out
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let flat = self.flatten_lanes();
        anyhow::ensure!(
            !flat.is_empty(),
            "at least one tavily key must be configured"
        );
        anyhow::ensure!(
            !self.proxy_keys.is_empty(),
            "at least one proxy key must be configured"
        );
        for (i, (tk, from_groups)) in flat.iter().enumerate() {
            anyhow::ensure!(
                tk.key.starts_with("tvly-"),
                "tavily_keys[{i}]: key should start with 'tvly-'{}",
                if *from_groups {
                    "（来自已弃用的 [[groups]]，请移入 [[tavily_keys]]）"
                } else {
                    ""
                }
            );
        }
        for (i, pk) in self.proxy_keys.iter().enumerate() {
            if let Some(mc) = pk.max_concurrency {
                anyhow::ensure!(
                    mc > 0,
                    "proxy_keys[{i}]: max_concurrency must be greater than 0"
                );
            }
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

    /// Resolve the quota persistence state file path.
    ///
    /// 1. Configured `[storage] quota_file` wins;
    /// 2. `TAVILY_PROXY_QUOTA_FILE` environment variable overrides if present;
    /// 3. In test runner processes without explicit path, returns `None` (in-memory only);
    /// 4. Production default: `~/.local/state/tavily-proxy/quota.json` (or `./data/quota.json`).
    pub fn resolve_quota_path(&self) -> Option<std::path::PathBuf> {
        if let Some(storage) = &self.storage
            && let Some(path) = &storage.quota_file
        {
            return Some(path.clone());
        }
        if let Ok(env_path) = std::env::var("TAVILY_PROXY_QUOTA_FILE") {
            return Some(std::path::PathBuf::from(env_path));
        }
        if is_test_environment() {
            return None;
        }
        Some(crate::quota::default_quota_path())
    }

    /// Retention days for audit history. 0 means unlimited.
    pub fn retention_days(&self) -> u32 {
        self.storage
            .as_ref()
            .map(|s| s.retention_days)
            .unwrap_or(DEFAULT_RETENTION_DAYS)
    }

    /// Hard file size cap in bytes for the quota state file.
    pub fn max_file_size_bytes(&self) -> usize {
        let mb = self
            .storage
            .as_ref()
            .map(|s| s.max_file_size_mb)
            .unwrap_or(DEFAULT_MAX_FILE_SIZE_MB);
        (mb as usize) * 1024 * 1024
    }
}

pub(crate) fn is_test_environment() -> bool {
    if std::env::var("TAVILY_PROXY_FORCE_PERSIST").is_ok() {
        return false;
    }
    if std::env::var("CARGO_TARGET_TMPDIR").is_ok() {
        return true;
    }
    if let Ok(exe) = std::env::current_exe() {
        let exe_str = exe.to_string_lossy();
        if exe_str.contains("/target/")
            && (exe_str.contains("/deps/") || exe_str.contains("/debug/deps/"))
        {
            return true;
        }
    }
    false
}

/// The table a parse error was raised inside, named the way the config writes it.
///
/// Repeated tables (`[[filter.rules]]`) are numbered, because "unknown field in a
/// rule" is only actionable once you know which rule.
pub fn table_location(content: &str, byte_end: usize) -> String {
    let end = byte_end.min(content.len());
    let mut header: Option<&str> = None;
    let mut occurrence = 0usize;

    for line in content[..end].lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.len() >= 2 && trimmed.starts_with('[') && trimmed.ends_with(']') {
            occurrence = if header == Some(trimmed) {
                occurrence + 1
            } else {
                1
            };
            header = Some(trimmed);
        }
    }

    match header {
        Some(h) if h.starts_with("[[") => format!("在 {h}（第 {occurrence} 个）: "),
        Some(h) => format!("在 {h}: "),
        None => "在顶层: ".to_string(),
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
