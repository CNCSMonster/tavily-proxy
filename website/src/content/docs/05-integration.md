## 与 tvly CLI / tavily skills 集成

tavily 系 agent skills（search / extract / crawl / map / research 等）底层统一走 `tvly` CLI（官方 SDK：`Authorization: Bearer` 认证 + `POST {base}/search`，与本代理协议完全兼容）。两个环境变量即可把全部 skills 指向代理：

```bash
export TAVILY_API_KEY=<proxy-token>               # 代理签发的客户端 token（[[proxy_keys]]）
export TAVILY_API_BASE_URL=http://127.0.0.1:3456  # 代理地址（可经 SSH 隧道转发）
tvly search "你的查询" --json
```

- `TAVILY_API_BASE_URL` 优先级高于 tvly 配置文件里的 `api_base_url`；
- 每个 token 可配独立 rpm 桶、月度上限与过滤路由（见 `[[proxy_keys]]`）；
- 已端到端实测（2026-10-11）：test token 经隧道调用 `tvly search` 返回 10 条结果、1.11s。

