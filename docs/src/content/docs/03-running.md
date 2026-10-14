## 运行

```bash
# 前台运行（默认）
cargo run -- serve

# 指定配置文件
cargo run -- --config /path/to/config.toml serve
# 或用环境变量
TAVILY_PROXY_CONFIG=/path/to/config.toml cargo run -- serve

# 配置预检（不监听端口、不联网、不写 pid）
cargo run -- check
```

## 后台运行

后台启动不需要 `sudo`，也不是 systemd 服务：二进制会用 `setsid` 把自身脱离终端，
写出自己的 pid 文件，日志追加到 XDG 状态目录。

```bash
tavily-proxy check                # 配置预检：不占端口、不联网，退出码 0/1
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

## 容器运行 (Docker)

官方提供经过轻量裁剪与权限加固的多架构 Docker 镜像（以非 root 用户 `appuser:10001` 运行）：

```bash
# 1. 从 GHCR 拉取预构建镜像
docker pull ghcr.io/cncsmonster/tavily-proxy:latest

# 2. 挂载本地配置文件启动容器（注意：config.toml 内 listen 请设为 "0.0.0.0:3456" 以便端口映射）
docker run -d \
  --name tavily-proxy \
  --restart unless-stopped \
  -p 3456:3456 \
  -v $(pwd)/config.toml:/app/config.toml:ro \
  ghcr.io/cncsmonster/tavily-proxy:latest

# 3. 检查容器健康状态
docker ps --filter name=tavily-proxy
```

本地自行构建镜像：

```bash
docker build -t tavily-proxy:latest .
```

