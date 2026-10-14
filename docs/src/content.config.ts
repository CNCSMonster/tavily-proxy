import { defineCollection } from 'astro:content';
import { docsSchema } from '@astrojs/starlight/schema';
import { glob } from 'astro/loaders';
import fs from 'node:fs';
import path from 'node:path';

function customDocsLoader() {
  const baseLoader = glob({
    base: './src/content/docs',
    pattern: '**/[^_]*.{md,mdx,markdown}',
  });

  return {
    name: 'custom-docs-loader',
    async load(context) {
      const originalParseData = context.parseData.bind(context);
      context.parseData = async (opts) => {
        if (!opts.data) opts.data = {};
        if (!opts.data.title) {
          try {
            const content = fs.readFileSync(opts.filePath, 'utf-8');
            // 提取第一个一级或二级标题作为页面标题
            const match = content.match(/^#{1,2}\s+(.+)$/m);
            if (match) {
              opts.data.title = match[1].trim();
            } else {
              opts.data.title = path.basename(opts.filePath, path.extname(opts.filePath));
            }
          } catch {
            opts.data.title = path.basename(opts.id);
          }
        }
        return originalParseData(opts);
      };

      return baseLoader.load(context);
    },
  };
}

export const collections = {
  docs: defineCollection({
    loader: customDocsLoader(),
    schema: docsSchema(),
  }),
};
