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

- **429 绝不跨凭证轮换（遵循 RFC 6585 标准）**：Tavily 的 429 是针对当前来源 IP 的频控约束。若在收到 429 时将相同 query 盲目换用另一把 key 重试，不仅无法解决源 IP 限流问题，反而会造成请求风暴与异常重试。因此系统遵循标准协议，只在同一 key 原地退避等待不超过 5s，若仍未恢复则原样向客户端返回 429 及 `Retry-After`，交由客户端标准退避。
- **后端 key 不会外泄给调用方**：只从上游错误里取 `detail.error` 这一个**字符串**并脱敏后
  透传，上游响应体其余部分只进日志。Tavily 的 422 校验错误会把提交的 `api_key` 回显在
  `detail` **数组**里——那正是"整包透传"会被利用的路径，这里从结构上就取不到（数组里没有
  `error` 字段），并且已用真实攻击复现验证过。
- **客户端 key 不会被转发到上游**：转发请求只带 `api_key` = 池中选出的 Tavily key，
  调用方的 `Authorization` 头不会进入上游请求。
- 所有离开进程的文本都过一遍脱敏：日志里的 key 是 `tvly-de...k3Mw`，客户端可见的错误消息
  在出口处（`detail_error`）再脱一次。配置里的密钥还按**确切值**脱一次（TOML 解析失败时
  会回显出错那一行，而那时还没法把配置解析出来，所以按字段名从原文里取值）。
- **开了 `kind = "llm"` 就意味着被扫内容会发给那个模型服务**：被扫单元（含 `raw_content`，
  若开启）都会进入请求正文，可能按批合并发送。检查器的 key 从 `api_key_env` 指的变量读，只放在
  `Authorization` / `x-api-key` 头里，不进 URL，也不进日志（变量没设就**拒绝启动**，
  不会静默降级成"不检查"）。选服务时请按"它会看到检索内容"这个前提选。
- `config.toml` 应 `chmod 600`；服务启动时若发现它对同组/其他用户可读会警告。
- 检查链故障时（fail-closed）返回 503 而**不是**放行：安全机制挂掉时不能悄悄降级成"不检查"。
  代价是外部检查器成为硬依赖，其抖动会直接让搜索不可用——可改用 `on_error = "fail_open"` 换取可用性。
- 默认只监听 `127.0.0.1`；本服务自身没有 TLS，调用方的 key 是明文传输的。

