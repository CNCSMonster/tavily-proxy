import fs from 'node:fs';
import path from 'node:path';
import { create, insert, remove, search } from '@orama/orama';

const segmenter = new Intl.Segmenter('zh-CN', { granularity: 'word' });
const STOP_WORDS = new Set(['的', '了', '在', '是', '我', '有', '和', '就', '不', '人', '都', '一', '一个', '上', '也', '很', '到', '说', '要', '去', '你', '会', '着', '没有', '看', '好', '自己', '这']);

function tokenizeChinese(text) {
  if (!text) return [];
  const words = [];
  const segments = Array.from(segmenter.segment(text));
  for (let i = 0; i < segments.length; i++) {
    const s = segments[i];
    if (s.isWordLike) {
      const w = s.segment.toLowerCase();
      if (!STOP_WORDS.has(w) && w.length > 0) {
        words.push(w);
      }
      if (i + 1 < segments.length && segments[i + 1].isWordLike) {
        const bi = (w + segments[i + 1].segment).toLowerCase();
        words.push(bi);
      }
    }
  }
  return words;
}

export class OramaSearchManager {
  constructor(contentDir) {
    this.contentDir = path.resolve(contentDir);
    this.db = null;
    this.initialized = false;
  }

  async init() {
    if (this.initialized) return;
    const t0 = performance.now();

    this.db = await create({
      schema: {
        id: 'string',
        title: 'string',
        url: 'string',
        category: 'string',
        content: 'string',
      },
      components: {
        tokenizer: {
          language: 'zh',
          normalizationCache: new Map(),
          tokenize: tokenizeChinese,
        },
      },
    });

    const files = this.scanDir(this.contentDir);
    for (const file of files) {
      await this.upsertFile(file, false);
    }

    this.initialized = true;
    console.log(`[Orama] Indexed ${files.length} notes in ${(performance.now() - t0).toFixed(1)}ms`);
  }

  scanDir(dir) {
    const results = [];
    if (!fs.existsSync(dir)) return results;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    
    // 隐私目录与敏感配置过滤（默认屏蔽 Private/ 目录，亦支持 EXCLUDE_DIRS 追加）
    const envExcludes = (process.env.EXCLUDE_DIRS || 'Private')
      .split(',')
      .map(s => s.trim().toLowerCase())
      .filter(Boolean);

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        const isHidden = entry.name.startsWith('.');
        const isExcluded = envExcludes.includes(entry.name.toLowerCase());
        if (!isHidden && !isExcluded) {
          results.push(...this.scanDir(full));
        }
      } else if (entry.name.endsWith('.md')) {
        results.push(full);
      }
    }
    return results;
  }

  getRelInfo(rawPath) {
    let p = rawPath.replace(/\\/g, '/');
    let realBase = this.contentDir.replace(/\\/g, '/');
    try {
      realBase = fs.realpathSync(this.contentDir).replace(/\\/g, '/');
    } catch {}

    const linkBase = path.resolve(process.cwd(), 'src/content/docs').replace(/\\/g, '/');

    if (p.startsWith(linkBase)) {
      p = p.slice(linkBase.length);
    } else if (p.startsWith(realBase)) {
      p = p.slice(realBase.length);
    }

    const rel = p.replace(/^\/+/, '').replace(/\.md$/, '');
    const parts = rel.split('/');
    const category = parts.length > 1 ? parts[0] : '概览';
    const url = '/' + parts.map(s => s.toLowerCase()).join('/') + '/';
    return { id: rel, category, url };
  }

  async upsertFile(filePath, isIncremental = true) {
    try {
      if (!fs.existsSync(filePath)) return;
      const raw = fs.readFileSync(filePath, 'utf-8');
      const titleMatch = raw.match(/^#{1,2}\s+(.+)$/m);
      const title = titleMatch ? titleMatch[1].trim() : path.basename(filePath, '.md');
      const { id, category, url } = this.getRelInfo(filePath);

      if (isIncremental && this.db) {
        try {
          await remove(this.db, id);
        } catch {}
      }

      await insert(this.db, {
        id,
        title,
        url,
        category,
        content: raw.slice(0, 15000),
      });

      if (isIncremental) {
        console.log(`[Orama] Incremental indexed: ${id}`);
      }
    } catch (err) {
      console.error(`[Orama] Error indexing ${filePath}:`, err.message);
    }
  }

  async removeFile(filePath) {
    try {
      const { id } = this.getRelInfo(filePath);
      if (this.db) {
        await remove(this.db, id);
        console.log(`[Orama] Removed index: ${id}`);
      }
    } catch {}
  }

  async query(term, limit = 15) {
    if (!this.db || !term || !term.trim()) return [];
    const trimmed = term.trim();

    const res = await search(this.db, {
      term: trimmed,
      limit: limit * 2,
      boost: {
        title: 5,
        category: 2,
        content: 1,
      },
    });

    const hits = [];
    const lowerTerm = trimmed.toLowerCase();

    for (const h of res.hits) {
      const doc = h.document;
      const titleLower = doc.title.toLowerCase();
      const contentLower = doc.content.toLowerCase();

      // 如果有明显相关性（标题或正文中至少出现过关键词子串或主要词项）
      const snippet = this.extractSnippet(doc.content, trimmed);
      hits.push({
        id: doc.id,
        title: doc.title,
        url: doc.url,
        category: doc.category,
        snippet,
        score: h.score,
      });

      if (hits.length >= limit) break;
    }

    return hits;
  }

  extractSnippet(content, term) {
    if (!content) return '';
    const clean = content.replace(/[#*`~\[\]\(\)>_-]/g, ' ').replace(/\s+/g, ' ');
    const lower = clean.toLowerCase();
    const idx = lower.indexOf(term.toLowerCase());

    if (idx === -1) {
      // 找不到完整词时，尝试找第一个分词
      const words = tokenizeChinese(term);
      for (const w of words) {
        const subIdx = lower.indexOf(w);
        if (subIdx !== -1) {
          const start = Math.max(0, subIdx - 30);
          const end = Math.min(clean.length, subIdx + 50);
          const text = clean.slice(start, end);
          const regex = new RegExp(`(${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
          return (start > 0 ? '...' : '') + text.replace(regex, '<mark>$1</mark>') + (end < clean.length ? '...' : '');
        }
      }
      return clean.slice(0, 80) + '...';
    }

    const start = Math.max(0, idx - 30);
    const end = Math.min(clean.length, idx + 50);
    const text = clean.slice(start, end);
    const regex = new RegExp(`(${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    return (start > 0 ? '...' : '') + text.replace(regex, '<mark>$1</mark>') + (end < clean.length ? '...' : '');
  }
}
