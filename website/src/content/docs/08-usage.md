## 使用

```bash
# 查询当前 proxy key 的配额与用量（1:1 兼容 Tavily 官方 GET /usage 契约）
curl -X GET http://localhost:3456/usage \
  -H "Authorization: Bearer YOUR_PROXY_KEY"

# 使用中转服务的 key 调用搜索
curl -X POST http://localhost:3456/search \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_PROXY_KEY" \
  -d '{"query": "latest AI news"}'

# 提取网页内容
curl -X POST http://localhost:3456/extract \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_PROXY_KEY" \
  -d '{"urls": ["https://example.com"]}'

# 爬取整站或指定页面
curl -X POST http://localhost:3456/crawl \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_PROXY_KEY" \
  -d '{"url": "https://example.com"}'

# 网站结构探测
curl -X POST http://localhost:3456/map \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_PROXY_KEY" \
  -d '{"url": "https://example.com"}'

# 发起 Deep Research 深度调研
curl -X POST http://localhost:3456/research \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_PROXY_KEY" \
  -d '{"input": "latest advances in quantum computing"}'

# 查询 Research 进度与结果
curl -X GET http://localhost:3456/research/YOUR_REQUEST_ID \
  -H "Authorization: Bearer YOUR_PROXY_KEY"
```
