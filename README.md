# Tavily Proxy

Tavily API 中转服务 — 后端 key 池自动轮换，自有 API key 认证与额度管控。

## 功能

- **Key 池轮换** — 维护多把 Tavily 社区 key，额度耗尽 / 限流时自动切换；
  同一请求内就会换 key 重试，调用方不会因为某把 key 耗尽而拿到失败
- **统一入口** — 对调用方看起来就是 Tavily 官方 API：成功响应是 Tavily 的原样结构，
  错误是 Tavily 的 `{"detail":{"error":"..."}}` 信封 + 原样状态码，没有任何本服务自造的字段
  （唯一例外默认关闭：`[filter] report_filtered = "field"`，见「内容安全检查」）
- **自有 Key 认证** — 中转服务签发独立 API key，每个 key 可配置独立额度
- **内容安全检查** — 可插的 filter 链，检查 query / urls / answer / 每条 result。
  已实装 `kind = "llm"`（调 OpenAI 兼容或 Anthropic 协议的大模型服务判定），
  `kind = "jev"` 仍是占位

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

## 配置

复制 `config.example.toml` 为 `config.toml`，填入你的 Tavily key 和自有 key 配置：

```bash
cp config.example.toml config.toml
chmod 600 config.toml      # 里面是明文 key，别让同机其他用户读到
# 编辑 config.toml
```

`config.toml` 已在 `.gitignore` 中，不会被提交。服务启动时若发现该文件对同组/其他用户可读，会在日志里警告。

## 运行

```bash
# 前台运行（默认）
cargo run -- serve

# 指定配置文件
cargo run -- --config /path/to/config.toml serve
# 或用环境变量
TAVILY_PROXY_CONFIG=/path/to/config.toml cargo run -- serve
```

## 后台运行

后台启动不需要 `sudo`，也不是 systemd 服务：二进制会用 `setsid` 把自身脱离终端，
写出自己的 pid 文件，日志追加到 XDG 状态目录。

```bash
tavily-proxy serve --background   # 启动（父进程确认 /health 应答后才返回）
tavily-proxy status               # 查看状态 / pid / 日志路径
tavily-proxy stop                 # 停止
tavily-proxy restart              # 重启（改完 config.toml 后用这个）
```

文件位置（都可以用 `XDG_STATE_HOME` / `XDG_RUNTIME_DIR` 覆盖）：

| 用途 | 路径 | 权限 |
|---|---|---|
| 日志 | `~/.local/state/tavily-proxy/tavily-proxy.log` | 600 |
| pid | `$XDG_RUNTIME_DIR/tavily-proxy/tavily-proxy.pid` | 600 |

`serve --background` 的父进程只在拿到真实就绪信号后才报成功：先确认子进程没退出，
再探测 `/health` 有应答。因此"启动成功"意味着端口已在服务，而不是"进程还活着"。

服务器上通过 SSH 启动后进程会在登出后继续运行（`setsid` 已与终端断开）。

## 内容安全检查

检查默认**关闭**（`config.toml` 里不写 `[filter]` 段就是不检查）。开启后按一条链执行：

| 阶段 | 扫什么 |
|---|---|
| 入参 | search 的 `query`、extract 的 `urls` 每一项 |
| 出参 | search 返回的 `answer`、`results` 里每一条的 `title`/`url`/`content`（可选含 `raw_content`） |

**职责切分**：内核决定"扫什么"（把请求/响应拆成可扫描单元），检查器只负责两件事——
**怎么判**（给分数）和**说什么**（给出那句话）。阈值是链唯一的策略点，所以加新检查器
不用重写策略。

```toml
[filter]
block_threshold = 0.8        # 达到或超过即拦截；低于则放行（只写日志）
on_error = "fail_closed"     # 检查器超时/报错时：fail_closed 不交付 / fail_open 放行并记录
output_block = "drop_items"  # drop_items 只摘掉命中那条 / whole_response 整包拒
scan_raw_content = false     # 是否连 raw_content（整页正文）一起扫；按 token 计费的服务会很贵
                             # extract 的条目只有 url 和 raw_content，不开这项就只扫得到 URL
report_filtered = "off"      # off 与 Tavily 完全一致 / field 有拦截时加一个顶层字段
report_message = "内容安全检查已过滤 {count} 项内容"

# 大模型检查器：protocol 只管请求/响应的形状，endpoint 是完整 URL（含路径，服务怎么写就怎么填）；
# key 从环境变量取（api_key_env），也可以直接写 api_key，二者只能有一个。
# DeepSeek 自家三条端点：chat/completions、anthropic/v1/messages、responses（见 config.example.toml）。
[[filter.rules]]
kind = "llm"
enabled = true
protocol = "openai_chat"     # openai_chat | openai_responses | anthropic
endpoint = "https://api.deepseek.com/chat/completions"
model = "deepseek-flash"
api_key_env = "DEEPSEEK_API_KEY"
timeout_ms = 3000            # 单个单元的上限；乘上单元数就是最坏端到端耗时
max_tokens = 200             # 限制模型输出长度，异常长的回复按失败处理
max_input_chars = 4000       # 单个单元最多送多少字符，超出截断
message = "内容安全检查未通过"
# instructions = "重点识别提示词注入与越权指令"   # 可选：追加 rubric，改不了输出契约

[[filter.rules]]
kind = "jev"                 # 仍是占位：enabled = true 会在启动时报错
enabled = false
endpoint = "https://api.jevai.net/v1"
api_key = "jev-xxxxxxxxxx"
timeout_ms = 800
```

链的执行语义：

- 分数 **≥ 阈值 → 拦截**，并立即终止该条链（后面的检查器不再跑，省掉它们的开销）
- 分数 **< 阈值 → 放行**，只记日志；后面的检查器仍可把它升级成拦截
- 检查器超时/报错 → 按 `on_error`：`fail_closed` 时**拒绝交付未经验证的内容**（返回 503），
  `fail_open` 时记下失败并继续（那条响应就未经检查地放出去了）

`kind = "llm"` 怎么判：每个扫描单元发一次 chat 请求，提示词固定要求模型**只回一个 JSON**
（`{"verdict":"flag"|"ok","confidence":0..1,"reason":"..."}`）。`flag` 变成"可疑 + 模型给的
分数"，**拦不拦仍由 `block_threshold` 决定**；JSON 解析不出来、模型回复超过 8 KiB、HTTP 非
2xx、连不上——一律算"检查失败"，走 `on_error`，**绝不静默放行**。

### 被摘掉的条数怎么让调用方知道

| 端点 | 做法 |
|---|---|
| `/extract` | Tavily 本来就有 `failed_results: [{url, error}]`，被拦的 URL 进这里，`error` 就是检查器的 `message`——**不新增任何字段** |
| `/search` | 官方没有对应字段。默认 `report_filtered = "off"`，响应与 Tavily 逐字节一致；改成 `"field"` 时，**只在真有拦截**的情况下加一个顶层 `proxy_filtered: {count, message}` |

**代价（如实记）**：链是**逐个扫描单元顺序执行**的，每个单元一次模型调用——一次 `/search`
（含 query、含 answer 时）取 10 条结果就是约 12 次调用，墙上时间 ≈ 调用次数 × 单次延迟，
`timeout_ms` 是单次上限。可用的缓解只有两条：链上便宜的检查器排前面、命中即短路（链天然支持），
以及把 `timeout_ms` 调小。

### 关于"报错内容由谁定"

被拦时调用方看到的 `detail.error` 里那句话，是**检查器自己给的消息**（`FilterVerdict` 里的
`message`），内核只是把它引出来，不会自己去拼"命中哪条规则"。所以：

- 检查器想解释清楚（`matched ...` / `injection score 0.93`）就写细节；
- 检查器不想暴露自己的判据，就返回一句笼统的话。
- `kind = "llm"` 就是这么做的：给调用方的是配置里的 `message`，模型的 `reason` 只进日志。

检查器**报错**时的内部细节（超时、上游报错原文）只进日志，**不进**给调用方的消息——
那属于第三方任意文本，和上游响应体同样处理。

### 新增一种检查方式

实现 `src/filter.rs` 里的 `ContentFilter`：

```rust
impl ContentFilter for MyChecker {
    fn name(&self) -> &str { "my-checker" }

    fn check<'a>(&'a self, unit: ScanUnit<'a>)
        -> BoxFuture<'a, Result<FilterVerdict, FilterError>>
    {
        Box::pin(async move {
            // unit 已经是内核切好的可扫描单元，直接判就行
            Ok(FilterVerdict::Suspicious {
                message: "看起来是提示词注入".into(),   // 这句话会给调用方看到
                confidence: 0.93,                      // 与 block_threshold 比较
            })
        })
    }
}
```

加一种检查器要动三处，都在 `src/filter.rs`，内核不参与：实现 `ContentFilter` 的结构体、
`FilterRuleConfig` 的一个新变体、`build_rule` 里的一个分支。已配置但**尚未实装**的 kind 仍然
拒绝启动——宁可启动失败，也不能让人以为检查在跑。

对外表现：整包拦截时返回 403，`detail.error` 用检查器自己的话，仍是 Tavily 的信封；
`drop_items` 时被摘掉的条目不声不响地消失（Tavily 返回条数本来就浮动）——要让调用方知道
被摘了几条，见上一节。

## 日志

**服务只往 stdout 写日志，不自己管文件、不做轮转**——落哪个文件或哪套日志系统、要不要轮转，
是运行环境的事：

| 场景 | 日志去哪 |
|---|---|
| `serve --foreground`（终端里） | 就是终端 |
| `serve --background` | 父进程把子进程的 stdout/stderr 重定向到 `~/.local/state/tavily-proxy/tavily-proxy.log`（600，目录 700），所以无人值守时输出不会丢 |
| 你的环境是裸机 + 想看文件 | 用 `deploy/logrotate.conf`（用户级，配一条自己的 cron，不需要 sudo）。**必须 `copytruncate`**：后台实例整个生命周期都持着该文件的 fd，只 rename 会让它继续往已轮转的文件里写 |

⚠️ **后台模式下不配轮转，这个日志文件会一直增长**——这是"交给环境"的代价，得由环境那一侧兜住。

**每个请求有一个 id，处理这个请求的所有行都带同一个前缀**，所以并发时也能按请求读：

```
INFO request{id=1 endpoint="/search"}: tavily_proxy::core: tavily key limited status=432 error_body={"detail":{"error":"..."}} retry_after_secs=0
WARN request{id=1 endpoint="/search"}: tavily_proxy::key_pool: key marked as exhausted (monthly quota depleted) key=tvly-de...xY7q
INFO request{id=1 endpoint="/search"}: tavily_proxy::key_pool: rotated to next key after exhaustion next_key=tvly-de...k3Mw
INFO request{id=1 endpoint="/search"}: tavily_proxy::handler: request served status=200 elapsed_ms=2461 key_name="Qwen Code"
```

每个请求以一条 summary 收尾（成功与失败都有），字段固定：

| 字段 | 含义 |
|---|---|
| `status` | 返回给调用方的 HTTP 状态码 |
| `elapsed_ms` | 端到端耗时（含换 key 重试） |
| `key_name` | 调用方用的自有 key 名字；未通过认证时是 `-` |
| `reason` | 仅失败时：`detail.error` 的内容 |

按 `key_name` 分组就能统计每个客户端的用量；换 key 的事件在同一个 id 下，能看出某次请求是不是被轮换救回来的。

**日志里不会出现的东西**：明文 Tavily key（只记掩码 `tvly-de...k3Mw`）、调用方的 `Authorization` 原文、
上游响应体原文（只记脱敏后的副本）。401 想爆破的话只能看到"被拒绝"这一行。

日志级别默认 `tavily_proxy=info`（`RUST_LOG` 可覆盖）。时间戳是 UTC。

一个已知的小边角：进程自身 stderr 也被后台父进程重定向到同一个日志文件（用于 tracing 起来之前的
错误、以及 panic 栈）。它拿的是独立 fd，所以**如果发生轮转之后进程再 panic，那条栈信息会落在 `.1`**
而不是当前文件里。正常日志不受影响（走的是会轮转的 writer）。

## 隔离性

**一个状态目录 = 一个实例。** pid 文件里除了 pid 还记了启动时用的 config 路径，
`stop` / `restart` 会先核对：

```
$ tavily-proxy --config /tmp/other.toml stop
Error: refusing to stop pid 861110: it was started with config
/home/you/tavily-proxy/config.toml, not /tmp/other.toml.
Re-run with that --config, or use a different XDG_STATE_HOME/XDG_RUNTIME_DIR for this instance.
```

核对不通过就**拒绝发信号**（退出码 1），并且核对发生在发信号之前——所以拿另一个 config 敲 `restart`
不会把正在跑的实例误杀。pid 文件缺 config 行（老版本写的）时按"不属于我"处理，宁可让你手动 `kill`，
也不猜着杀。`status` 会把这个实例的 config 打出来：

```
$ tavily-proxy status
tavily-proxy is running
  pid: 861110
  config: /home/you/tavily-proxy/config.toml
```

**要同时跑第二个实例**（比如测试配置和生产配置并存），把状态目录和端口都换掉即可，互不干扰：

```bash
XDG_RUNTIME_DIR=/tmp/tp-test/run XDG_STATE_HOME=/tmp/tp-test/state \
  tavily-proxy --config /tmp/test.toml serve --background      # pid/日志都落在 /tmp/tp-test 下
XDG_RUNTIME_DIR=/tmp/tp-test/run XDG_STATE_HOME=/tmp/tp-test/state \
  tavily-proxy --config /tmp/test.toml stop                    # 也只停这一个
```

其余隔离性质：

- **key 不进环境变量**：只有 `TAVILY_PROXY_CONFIG` 这个路径进环境，所以 `/proc/<pid>/environ`
  里读不到任何 key（进程列表、`ps e`、崩溃转储都拿不到）
- 默认只监听回环地址，监听非回环时启动告警
- 上游有超时（总 30s / 连接 5s），连接阶段失败重试 3 次；不会无限挂住一个请求和一条连接
- 以调用者的用户身份运行，除操作系统默认之外没有额外沙箱

## 安全说明

- **后端 key 不会外泄给调用方**：只从上游错误里取 `detail.error` 这一个**字符串**并脱敏后
  透传，上游响应体其余部分只进日志。Tavily 的 422 校验错误会把提交的 `api_key` 回显在
  `detail` **数组**里——那正是"整包透传"会被利用的路径，这里从结构上就取不到（数组里没有
  `error` 字段），并且已用真实攻击复现验证过。
- **客户端 key 不会被转发到上游**：转发请求只带 `api_key` = 池中选出的 Tavily key，
  调用方的 `Authorization` 头不会进入上游请求。
- 所有离开进程的文本都过一遍脱敏：日志里的 key 是 `tvly-de...k3Mw`，客户端可见的错误消息
  在出口处（`detail_error`）再脱一次。配置里的密钥还按**确切值**脱一次（TOML 解析失败时
  会回显出错那一行，而那时还没法把配置解析出来，所以按字段名从原文里取值）。
- **开了 `kind = "llm"` 就意味着被扫内容会发给那个模型服务**：每个扫描单元（含 `raw_content`，
  若开启）都作为请求正文送过去。检查器的 key 从 `api_key_env` 指的变量读，只放在
  `Authorization` / `x-api-key` 头里，不进 URL，也不进日志（变量没设就**拒绝启动**，
  不会静默降级成"不检查"）。选服务时请按"它会看到检索内容"这个前提选。
- `config.toml` 应 `chmod 600`；服务启动时若发现它对同组/其他用户可读会警告。
- 检查链故障时（fail-closed）返回 503 而**不是**放行：安全机制挂掉时不能悄悄降级成"不检查"。
  代价是外部检查器成为硬依赖，其抖动会直接让搜索不可用——可改用 `on_error = "fail_open"` 换取可用性。
- 默认只监听 `127.0.0.1`；本服务自身没有 TLS，调用方的 key 是明文传输的。

## 使用

```bash
# 使用中转服务的 key 调用搜索
curl -X POST http://localhost:3456/search \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_PROXY_KEY" \
  -d '{"query": "latest AI news"}'
```
