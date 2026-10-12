// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import path from 'node:path';
import fs from 'node:fs';
import { OramaSearchManager } from './src/search-engine.js';

const docsDir = path.resolve(process.cwd(), 'src/content/docs');
const searchManager = new OramaSearchManager(docsDir);

function oramaSearchPlugin() {
  return {
    name: 'starlight-orama-search-plugin',
    configureServer(server) {
      searchManager.init();

      server.watcher.on('add', (filePath) => {
        if (filePath.endsWith('.md')) {
          searchManager.upsertFile(filePath);
        }
      });

      server.watcher.on('change', (filePath) => {
        if (filePath.endsWith('.md')) {
          searchManager.upsertFile(filePath);
        }
      });

      server.watcher.on('unlink', (filePath) => {
        if (filePath.endsWith('.md')) {
          searchManager.removeFile(filePath);
        }
      });

      server.middlewares.use('/api/search', async (req, res) => {
        try {
          const url = new URL(req.url, `http://${req.headers.host}`);
          const term = url.searchParams.get('q') || '';
          const results = await searchManager.query(term);
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(results));
        } catch (err) {
          res.statusCode = 500;
          res.end(JSON.stringify({ error: err.message }));
        }
      });
    },
  };
}

const siteTitle = process.env.SITE_TITLE || 'Tavily Proxy 用户手册';

// https://astro.build/config
export default defineConfig({
  redirects: {
    '/': '/01-overview',
  },
  server: {
    port: 4400,
    host: '0.0.0.0',
  },
  vite: {
    plugins: [oramaSearchPlugin()],
  },
  integrations: [
    starlight({
      title: siteTitle,
      customCss: ['./src/styles/custom.css'],
      components: {
        Search: './src/components/Search.astro',
      },
      defaultLocale: 'root',
      locales: {
        root: {
          label: '简体中文',
          lang: 'zh-CN',
        },
      },
      sidebar: [
        { label: '功能与实现概览', link: '/01-overview' },
        { label: '配置说明', link: '/02-configuration' },
        { label: '运行方式', link: '/03-running' },
        { label: '部署指南', link: '/04-deployment' },
        { label: 'CLI 与 Skills 集成', link: '/05-integration' },
        { label: '内容安全检查', link: '/06-content-safety' },
        { label: '日志与隔离性', link: '/07-logging-and-security' },
        { label: 'API 使用与查询', link: '/08-usage' },
      ],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/CNCSMonster/tavily-proxy',
        },
      ],
    }),
  ],
});
