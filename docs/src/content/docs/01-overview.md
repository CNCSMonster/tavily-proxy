# Tavily Proxy

Tavily API 中转服务 — 后端 key 池自动轮换，自有 API key 认证与额度管控。

## 功能

- **Key 池终态轮换与规范限流** — 
  - **终态错误自动换 key**：遇到额度耗尽（432/433）或凭据吊销（401）时，在同一请求内自动切换到下一把可用 key 重试，调用方无感知；
  - **429 绝不跨 key 轮换（遵循上游频控契约）**：遇到上游 429 速率限制时，绝不切换到其他 key 重试（避免跨凭证频控放大与并发风暴）。若上游指定 `Retry-After <= 5s`，在同 key 上短时等待重试；若超时或继续被限，原样透传 429 及 `Retry-After` 响应头；
  - **全池终态统一 503**：当池内所有 key 均已吊销或配额耗尽时，对外统一返回 503 Service Unavailable。
- **单池与上游预算（One Pool, One Budget）** —
  - 后端 key 是一叠**平铺的有序池**，不再分组：粘性用当前 key，只在终态错误时换下一把；
  - **一个令牌桶 = 一个 IP 预算**：上游的速率限制按**来源 IP**计数而不是按 key，所以多把 key 共用一只桶才是真实的预算——桶空时**本地**生成 429 + `Retry-After`，请求根本不外发，既不浪费 key 的配额也不产生无效网络开销；
  - 桶速取 `[upstream] rpm`（全池唯一来源），未配置时按首个 key 前缀取默认（`tvly-dev-` 90 RPM，生产 key 900 RPM），`rpm = 0` 表示不限速；
  - 上游 key 可选配置 `max_requests` 作为单实例生命周期累计请求上限（熔断保险丝），真实月度配额耗尽由上游 432/433 响应自动驱动封锁轮换；
  - 旧的 `[[groups]]` 段与 `[[tavily_keys]]` 的 `group` 标签**已被拒绝**（ADR-0003）：配置里出现即按未知字段拒绝启动，请把 key 移入 `[[tavily_keys]]`；per-key 的 `rpm` 字段仍解析但已弃用并告警，上游速率请写在 `[upstream] rpm`。
- **统一入口** — 对调用方看起来就是 Tavily 官方 API：支持 `/search`、`/extract`、`/crawl`、`/map`、`/research` 及 `GET /research/{request_id}` 等全部核心端点。成功响应是 Tavily 的原样结构，
  错误是 Tavily 的 `{"detail":{"error":"..."}}` 信封 + 原样状态码，没有任何本服务自造的字段
  （唯一例外默认关闭：`[filter] report_filtered = "field"`，见「内容安全检查」）
- **自有 Key 认证与管控** — 中转服务签发独立 API key，每个 key 可独立配置：
  - 月度请求配额（`max_requests_per_month`，基于 UTC 自然日滚动 30 天滑动窗口计算，两阶段 Reserve → Settle 准入防超卖，状态原子持久化落盘，默认支持 365 天历史审计与 10 MB 物理硬上限）；
  - 主动速率限制（`rpm` 令牌桶）；
  - 最大在途并发数控制（`max_concurrency`），超限返回 429；
  - **配额与用量查询（`GET /usage`）**：1:1 兼容 Tavily 官方协议，调用方携带 Token 即可原生读取已用量与月度上限（官方 SDK 无缝兼容）。
- **内容安全检查** — 可插的 filter 链，检查 query / urls / answer / 每条 result。
  已实装 `kind = "llm"`（调 OpenAI 兼容、Anthropic 或 Responses 协议大模型判定）
  与 `kind = "jev"`（原生 TypeSafe System One 架构判定）两类检查器；
  每条规则强制命名，**按派发的 proxy token 选审查路由**（指定组合或显式免审），
  见「按调用方 token 选审查路由」

## 实现

| 关注点 | 选择 |
|---|---|
| HTTP 服务 / 异步运行时 | `axum` + `tokio` |
| 上游 HTTP 客户端 | `reqwest` |
| 日志 | `tracing` + `tracing-subscriber`（`env-filter`） |
| 配置解析 | `toml` + `serde` |
| 错误处理 | `anyhow` |
| Unix 进程控制（`setsid` / `kill`） | `libc` |

依赖检查用 `cargo shear`：未使用依赖、放错 section 的 dev/build 依赖、没被 module 树引到的 `.rs` 文件。

