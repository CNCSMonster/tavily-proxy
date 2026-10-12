## 部署

本机开发用上面「运行」一节即可；服务器部署的完整路径是
**构建 → 安装 → 守护 → TLS → 验证 → 升级**，全部材料在 `deploy/`：

| 文件 | 用途 |
|---|---|
| `deploy/tavily-proxy.service` | systemd unit（复制即用，改路径后安装） |
| `deploy/Caddyfile` | Caddy 反代 + 自动 TLS（改域名即用） |
| `deploy/nginx.conf` | nginx 反代 server 块（证书自备） |
| `deploy/logrotate.conf` | **仅 setsid 后台模式**的日志轮转；systemd 下不需要 |

### 1. 构建与安装

```bash
cargo build --release
sudo install -D -m 755 target/release/tavily-proxy /usr/local/bin/tavily-proxy
# config.toml 填好生产 key 后再装（明文密钥，权限 600）
sudo install -D -m 600 config.toml /etc/tavily-proxy/config.toml
```

不装系统路径也行：把 systemd unit 里的 `ExecStart` 指到仓库里
`target/release/tavily-proxy` 的绝对路径即可。

### 2. 进程守护（systemd）

生产用 systemd，**不要**用 `serve --background`：setsid 模式脱离 systemd 管理——
崩溃不会自动拉起，开机不会自启，`systemctl` 也看不见它。

```bash
sudo install -m 644 deploy/tavily-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tavily-proxy
```

- unit 里 `ExecStart` 是**前台**模式（systemd 就是进程管理器）；
  服务已实现 SIGTERM 优雅退出，`systemctl stop` 直接可用；
- systemd 下**一律用 `systemctl status | stop | restart`**，不要用 `tavily-proxy stop`
  （那会绕过 systemd，把它晒成 inactive）；
- 日志由 journald 收：`journalctl -u tavily-proxy -f`，**不需要 logrotate**；
- 检查器的 key（`[filter]` 的 `api_key_env`）经 unit 里的
  `EnvironmentFile=-/etc/tavily-proxy/env` 注入（`KEY=value` 一行一个，`chmod 600`）。

### 3. TLS 与反向代理

本服务自身无 TLS（见「安全说明」），**跨机/公网调用必须让反代终结 TLS**，
否则 proxy key 明文裸传：

- **同机调用**（`127.0.0.1:3456`）：key 不出网卡，不需要 TLS；
- **跨机 / 公网**：推荐 Caddy（自动签发并续期证书）：

```bash
sudo apt install caddy   # 或按 Caddy 官方文档装
sudo install -m 644 deploy/Caddyfile /etc/caddy/Caddyfile   # 先把域名改成你的
sudo systemctl reload caddy
```

nginx 用户用 `deploy/nginx.conf`（证书自备，可配 certbot）。
两个模板都只反代到回环 `127.0.0.1:3456`；nginx 的 `client_max_body_size 1m`
与服务的 1 MiB 请求体上限对齐。

### 4. 验证

```bash
systemctl is-active tavily-proxy                       # active
curl -s http://127.0.0.1:3456/health                    # {"status":"ok","stats":{...}}
curl -s -X POST http://127.0.0.1:3456/search \
  -H "Authorization: Bearer tp-你的key" \
  -H "Content-Type: application/json" \
  -d '{"query":"hello"}' | head -c 300                  # Tavily 形状的响应
```

### 5. 升级

**先换二进制，再重启**——旧进程一直持着旧代码，顺序反了等于没升级：

```bash
git pull && cargo build --release
sudo install -m 755 target/release/tavily-proxy /usr/local/bin/tavily-proxy
sudo /usr/local/bin/tavily-proxy check --config /etc/tavily-proxy/config.toml || exit 1
sudo systemctl restart tavily-proxy
```

（setsid 后台模式同理：换完文件再 `tavily-proxy restart`。）

**重启前必跑 `check`**：配置现在是严格解析的，一个拼错的字段名就会让服务**拒绝启动**——
先跑预检（退出 0 才重启）比重启后翻 `journalctl` 找回一个挂掉的服务便宜得多。
`check` 是 serve 启动序里 bind **之前**的那部分：不占端口、不联网、不写 pid，
所以旧进程还在跑的时候照样能执行。

不要把 `check` 写成 unit 里的 `ExecStartPre`：`systemctl restart` 会先停旧进程再跑前置检查，
检查失败的结果是"旧实例已停 + 新实例没起"的宕机；而手动前置检查失败时旧进程还在服务。

### 6. 监控

| 什么 | 哪里 |
|---|---|
| 探活 + 计数 | `GET /health`（`stats` 含请求总数与各状态码计数） |
| 请求级指标 | `METRICS_FILE` 指向的 JSONL（unit 默认 `/var/lib/tavily-proxy/metrics.jsonl`；置空禁用），字段含 `status` `total_ms` `filter_calls` 等 |
| 错误日志 | `journalctl -u tavily-proxy -p err`；每请求一条 summary，可按 `key_name` 聚合各客户端用量 |

