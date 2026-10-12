## 配置

复制 `config.example.toml` 为 `config.toml`，填入你的 Tavily key 和自有 key 配置：

```bash
cp config.example.toml config.toml
chmod 600 config.toml      # 里面是明文 key，别让同机其他用户读到
# 编辑 config.toml
```

`config.toml` 已在 `.gitignore` 中，不会被提交。服务启动时若发现该文件对同组/其他用户可读，会在日志里警告。

**配置是严格解析的**：每一段（`[server]` / `[upstream]` / `[[tavily_keys]]` / `[[proxy_keys]]` / `[filter]` /
`[[filter.rules]]`，含 `kind = "jev"` 与 `kind = "llm"` 两种形态）都拒绝未知字段——拼错的字段名会**拒绝启动**并报出
「哪张表的哪个字段」（`在 [[filter.rules]]（第 2 个）: unknown field "timeout_m"`），而不是静默生效成"没配"。
报错文本先脱敏再打印，不会把你写错的那行 key 带进日志。改完配置先跑一次预检：

```bash
tavily-proxy check --config config.toml   # 退出 0 = 能启动；非 0 = 启动会失败
```

