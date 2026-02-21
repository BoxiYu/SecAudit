import { readFileSync } from 'node:fs';
import { extname, relative } from 'node:path';
import { glob } from 'glob';
import ignore from 'ignore';
import { Finding, Rule } from '../types.js';
import { allRules } from './rules/index.js';

const DEFAULT_IGNORE = [
  'node_modules/**',
  'dist/**',
  'build/**',
  '.git/**',
  '*.min.js',
  '*.min.css',
  '*.map',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
];

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2',
  '.ttf', '.eot', '.mp3', '.mp4', '.zip', '.tar', '.gz', '.pdf',
]);

export class StaticScanner {
  private rules: Rule[];
  private ig: ReturnType<typeof ignore>;
  private fileFilter?: Set<string>;

  constructor(rules?: Rule[]) {
    this.rules = rules ?? allRules;
    this.ig = ignore();
    this.ig.add(DEFAULT_IGNORE);
  }

  setFileFilter(files: string[]): void {
    this.fileFilter = new Set(files);
  }

  addIgnorePatterns(patterns: string[]): void {
    this.ig.add(patterns);
  }

  async scan(targetPath: string): Promise<{ findings: Finding[]; filesScanned: number }> {
    const files = await glob('**/*', {
      cwd: targetPath,
      nodir: true,
      dot: false,
      absolute: false,
    });

    const filtered = files.filter((f) => {
      if (BINARY_EXTENSIONS.has(extname(f).toLowerCase())) return false;
      if (this.ig.ignores(f)) return false;
      if (this.fileFilter && !this.fileFilter.has(f)) return false;
      return true;
    });

    const findings: Finding[] = [];

    for (const file of filtered) {
      const fullPath = `${targetPath}/${file}`;
      let content: string;
      try {
        content = readFileSync(fullPath, 'utf-8');
      } catch {
        continue;
      }

      const ext = extname(file).toLowerCase();
      const lines = content.split('\n');

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];

        for (const rule of this.rules) {
          if (rule.fileExtensions && !rule.fileExtensions.includes(ext)) {
            continue;
          }

          const match = rule.pattern.exec(line);
          if (match && !rule.negate) {
            // Skip if line is a comment
            const trimmed = line.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
              continue;
            }

            findings.push({
              file: relative(targetPath, fullPath),
              line: lineNum + 1,
              column: (match.index ?? 0) + 1,
              severity: rule.severity,
              category: rule.category,
              message: rule.message,
              rule: rule.id,
              snippet: line.trim().substring(0, 200),
            });
          }
        }
      }
    }

    return { findings, filesScanned: filtered.length };
  }
}
