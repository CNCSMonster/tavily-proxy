use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Days, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

pub const ROLLING_WINDOW_DAYS: usize = 30;

pub use crate::auth::QuotaSlotGuard;

#[derive(Debug, Clone, Default)]
pub struct TokenUsageBucket {
    /// 每日结算已用请求数（按 UTC 日期归档）
    pub daily: BTreeMap<NaiveDate, u64>,
    /// 当前在途未结算请求数（Reserve 阶段占用，Settle 释放）
    pub in_flight: u64,
}

impl TokenUsageBucket {
    /// 计算以 today 为基准、过去 30 天（含 today）的累计已结算用量
    pub fn settled_in_window(&self, today: NaiveDate) -> u64 {
        let cutoff = today - Days::new((ROLLING_WINDOW_DAYS - 1) as u64);
        self.daily
            .range(cutoff..=today)
            .map(|(_, &count)| count)
            .sum()
    }

    /// 清理早于保留期限的历史用量（若 retention_days = 0 则不清理）。
    /// 无论保留期设置多短，最近 30 天核心计费窗口内的数据绝对不予清理。
    pub fn prune_retention(&mut self, today: NaiveDate, retention_days: u32) {
        if retention_days > 0 {
            let window_start = today - Days::new((ROLLING_WINDOW_DAYS - 1) as u64);
            let cutoff = today - Days::new(retention_days.saturating_sub(1) as u64);
            let effective_cutoff = if cutoff > window_start {
                window_start
            } else {
                cutoff
            };
            self.daily.retain(|&date, _| date >= effective_cutoff);
        }
    }

    /// 清理 30 天之前的过期日用量（快捷方法）
    pub fn prune_expired(&mut self, today: NaiveDate) {
        self.prune_retention(today, ROLLING_WINDOW_DAYS as u32);
    }
}

/// 持久化状态文件结构（Schema v1）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaStateFile {
    pub schema_version: u32,
    pub updated_at: DateTime<Utc>,
    pub tokens: BTreeMap<String, TokenQuotaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenQuotaData {
    pub daily: BTreeMap<NaiveDate, u64>,
}

/// 默认配额持久化文件存储路径：~/.local/state/tavily-proxy/quota.json
/// 若无 HOME 或目录无法创建，则 fallback 到 ./data/quota.json
pub fn default_quota_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        let state_dir = PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("tavily-proxy");
        if std::fs::create_dir_all(&state_dir).is_ok() {
            return state_dir.join("quota.json");
        }
    }
    PathBuf::from("data").join("quota.json")
}

/// 对所有 Token 的每日分桶应用时间保留期与体积硬上限过滤并序列化：
/// 1. 若 retention_days > 0，剔除早于 (today - retention_days) 的记录；
/// 2. 若序列化后字节数超出 max_file_size_bytes，优先从最久远的超期历史日期（早于 today - 29）开始剔除；
/// 3. 硬性红线保证：无论体积如何，最近 30 天计费窗口内的数据绝对不予丢弃。
pub fn prune_and_serialize(
    buckets: &BTreeMap<String, TokenUsageBucket>,
    today: NaiveDate,
    retention_days: u32,
    max_file_size_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let window_start = today - Days::new((ROLLING_WINDOW_DAYS - 1) as u64);

    let retention_cutoff = if retention_days > 0 {
        let cutoff = today - Days::new(retention_days.saturating_sub(1) as u64);
        if cutoff > window_start {
            window_start
        } else {
            cutoff
        }
    } else {
        NaiveDate::MIN
    };

    let mut tokens_data = BTreeMap::new();
    for (k, bucket) in buckets {
        let mut daily = bucket.daily.clone();
        daily.retain(|&date, _| date >= retention_cutoff);
        tokens_data.insert(k.clone(), TokenQuotaData { daily });
    }

    let mut state = QuotaStateFile {
        schema_version: 1,
        updated_at: Utc::now(),
        tokens: tokens_data,
    };

    let mut json_bytes = serde_json::to_vec_pretty(&state)?;

    if max_file_size_bytes > 0 && json_bytes.len() > max_file_size_bytes {
        loop {
            let mut earliest_old_date: Option<NaiveDate> = None;
            for token_data in state.tokens.values() {
                for &date in token_data.daily.keys() {
                    if date < window_start {
                        match earliest_old_date {
                            None => earliest_old_date = Some(date),
                            Some(d) if date < d => earliest_old_date = Some(date),
                            _ => {}
                        }
                    }
                }
            }

            let Some(date_to_evict) = earliest_old_date else {
                break;
            };

            for token_data in state.tokens.values_mut() {
                token_data.daily.remove(&date_to_evict);
            }

            json_bytes = serde_json::to_vec_pretty(&state)?;
            if json_bytes.len() <= max_file_size_bytes {
                break;
            }
        }
    }

    Ok(json_bytes)
}

/// 将配额账本原子写入目标文件：写临时文件 -> sync_all -> rename
pub fn save_quota_atomic(
    path: &Path,
    buckets: &BTreeMap<String, TokenUsageBucket>,
    retention_days: u32,
    max_file_size_bytes: usize,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let today = Utc::now().date_naive();
    let json_bytes = prune_and_serialize(buckets, today, retention_days, max_file_size_bytes)?;

    let pid = std::process::id();
    let tmp_path = PathBuf::from(format!("{}.tmp.{}", path.display(), pid));

    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(&json_bytes)?;
        file.flush()?;
        file.sync_all()?;
    }

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// 加载配额文件；若损坏或版本不兼容，记录 warning 并备份为 .corrupt.<timestamp>，降级为空账本返回
pub fn load_quota_or_recover(
    path: &Path,
    retention_days: u32,
) -> BTreeMap<String, TokenUsageBucket> {
    if !path.exists() {
        return BTreeMap::new();
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "Failed to read quota file, initializing empty"
            );
            return BTreeMap::new();
        }
    };

    let parsed: Result<QuotaStateFile, _> = serde_json::from_str(&content);
    match parsed {
        Ok(file) if file.schema_version == 1 => {
            let today = Utc::now().date_naive();
            let mut buckets = BTreeMap::new();
            for (key, data) in file.tokens {
                let mut b = TokenUsageBucket {
                    daily: data.daily,
                    in_flight: 0,
                };
                b.prune_retention(today, retention_days);
                buckets.insert(key, b);
            }
            buckets
        }
        Ok(file) => {
            warn!(
                path = %path.display(),
                version = file.schema_version,
                "Incompatible schema_version detected at {}, backing up and reinitializing",
                path.display()
            );
            backup_corrupt_file(path);
            BTreeMap::new()
        }
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "Corrupt quota file detected at {}, backing up and reinitializing",
                path.display()
            );
            backup_corrupt_file(path);
            BTreeMap::new()
        }
    }
}

fn backup_corrupt_file(path: &Path) {
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let corrupt_path = PathBuf::from(format!("{}.corrupt.{}", path.display(), ts));
    if let Err(e) = std::fs::rename(path, &corrupt_path) {
        warn!(
            path = %path.display(),
            backup = %corrupt_path.display(),
            error = %e,
            "Failed to backup corrupt quota file"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_window_calculation() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 5).unwrap();
        let mut bucket = TokenUsageBucket::default();

        // 35 天前：2026-08-31
        bucket
            .daily
            .insert(NaiveDate::from_ymd_opt(2026, 8, 31).unwrap(), 100);
        // 30 天前：2026-09-05（恰好在 30 天窗口之外，today - 30天）
        bucket
            .daily
            .insert(NaiveDate::from_ymd_opt(2026, 9, 5).unwrap(), 50);
        // 29 天前：2026-09-06（窗口边界第一天）
        bucket
            .daily
            .insert(NaiveDate::from_ymd_opt(2026, 9, 6).unwrap(), 20);
        // 10 天前：2026-09-25
        bucket
            .daily
            .insert(NaiveDate::from_ymd_opt(2026, 9, 25).unwrap(), 30);
        // 今日：2026-10-05
        bucket.daily.insert(today, 10);

        // 窗口内应该只累加 09-06 (20) + 09-25 (30) + 10-05 (10) = 60
        assert_eq!(bucket.settled_in_window(today), 60);

        // 测试 prune_expired
        bucket.prune_expired(today);
        assert!(
            !bucket
                .daily
                .contains_key(&NaiveDate::from_ymd_opt(2026, 8, 31).unwrap())
        );
        assert!(
            !bucket
                .daily
                .contains_key(&NaiveDate::from_ymd_opt(2026, 9, 5).unwrap())
        );
        assert!(
            bucket
                .daily
                .contains_key(&NaiveDate::from_ymd_opt(2026, 9, 6).unwrap())
        );
        assert_eq!(bucket.settled_in_window(today), 60);
    }

    #[test]
    fn test_atomic_persistence_and_recovery() {
        let temp_dir = tempfile::tempdir().unwrap();
        let quota_file = temp_dir.path().join("quota.json");

        let today = Utc::now().date_naive();
        let mut buckets = BTreeMap::new();
        let mut b1 = TokenUsageBucket::default();
        b1.daily.insert(today, 42);
        buckets.insert("key-1".to_string(), b1);

        save_quota_atomic(&quota_file, &buckets, 365, 10 * 1024 * 1024).unwrap();
        assert!(quota_file.exists());

        // 加载验证
        let loaded = load_quota_or_recover(&quota_file, 365);
        assert_eq!(loaded.get("key-1").unwrap().settled_in_window(today), 42);

        // 注入损坏内容
        std::fs::write(&quota_file, "{ invalid json").unwrap();
        let recovered = load_quota_or_recover(&quota_file, 365);
        assert!(recovered.is_empty());
        // 检查原文件已被重命名备份
        assert!(!quota_file.exists());
    }

    #[test]
    fn test_incompatible_version_recovery() {
        let temp_dir = tempfile::tempdir().unwrap();
        let quota_file = temp_dir.path().join("quota.json");

        let corrupt_state = serde_json::json!({
            "schema_version": 999,
            "updated_at": "2026-10-05T00:00:00Z",
            "tokens": {}
        });
        std::fs::write(&quota_file, corrupt_state.to_string()).unwrap();

        let recovered = load_quota_or_recover(&quota_file, 365);
        assert!(recovered.is_empty());
        assert!(!quota_file.exists());
    }

    #[test]
    fn test_retention_days_audit_preservation_and_pruning() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 5).unwrap();
        let mut buckets = BTreeMap::new();
        let mut b = TokenUsageBucket::default();

        // 400 天前：应被 365 天保留期淘汰
        let day_400_ago = today - Days::new(400);
        b.daily.insert(day_400_ago, 10);
        // 100 天前：虽然超过 30 天，但在 365 天保留期内，应该被保留以供审计！
        let day_100_ago = today - Days::new(100);
        b.daily.insert(day_100_ago, 20);
        // 10 天前：30 天计费窗口内，计费与审计
        let day_10_ago = today - Days::new(10);
        b.daily.insert(day_10_ago, 30);
        // 今日
        b.daily.insert(today, 5);

        buckets.insert("tok-audit".to_string(), b);

        let serialized = prune_and_serialize(&buckets, today, 365, 10 * 1024 * 1024).unwrap();
        let state: QuotaStateFile = serde_json::from_slice(&serialized).unwrap();
        let tok_data = state.tokens.get("tok-audit").unwrap();

        assert!(!tok_data.daily.contains_key(&day_400_ago), "400 天前应淘汰");
        assert!(
            tok_data.daily.contains_key(&day_100_ago),
            "100 天前应保留以供审计"
        );
        assert!(
            tok_data.daily.contains_key(&day_10_ago),
            "10 天前在计费窗口内"
        );
        assert!(tok_data.daily.contains_key(&today), "今日在计费窗口内");

        // 30 天滑动窗口计算只累加 10 天前 (30) + 今日 (5) = 35
        let b_restored = TokenUsageBucket {
            daily: tok_data.daily.clone(),
            in_flight: 0,
        };
        assert_eq!(b_restored.settled_in_window(today), 35);
    }

    #[test]
    fn test_max_file_size_eviction_protects_30d_window() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 5).unwrap();
        let mut buckets = BTreeMap::new();
        let mut b = TokenUsageBucket::default();

        // 构造较久远的多天历史数据（早于 30 天窗口）
        let day_90_ago = today - Days::new(90);
        let day_60_ago = today - Days::new(60);
        let day_40_ago = today - Days::new(40);
        b.daily.insert(day_90_ago, 100);
        b.daily.insert(day_60_ago, 200);
        b.daily.insert(day_40_ago, 300);

        // 构造窗口内数据（10 天前与今日）
        let day_10_ago = today - Days::new(10);
        b.daily.insert(day_10_ago, 50);
        b.daily.insert(today, 10);

        buckets.insert("tok-size".to_string(), b);

        // 完整序列化大小大约 250~350 字节
        let full_bytes = prune_and_serialize(&buckets, today, 365, 0).unwrap();
        let full_len = full_bytes.len();
        assert!(full_len > 200);

        // 施加一个严苛的上限，促使其淘汰最早的历史日期
        let small_cap = full_len - 60;
        let pruned_bytes = prune_and_serialize(&buckets, today, 365, small_cap).unwrap();
        assert!(pruned_bytes.len() <= small_cap);

        let state: QuotaStateFile = serde_json::from_slice(&pruned_bytes).unwrap();
        let tok_data = state.tokens.get("tok-size").unwrap();

        // 最早的 90 天前数据应该被优先淘汰
        assert!(
            !tok_data.daily.contains_key(&day_90_ago),
            "最久远的 90 天前数据应被淘汰"
        );
        // 核心 30 天窗口内的数据绝不能丢
        assert!(
            tok_data.daily.contains_key(&day_10_ago),
            "30 天窗口内数据必须保留"
        );
        assert!(tok_data.daily.contains_key(&today), "今日数据必须保留");
    }
}
