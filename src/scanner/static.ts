import { readFileSync } from 'node:fs';
import { extname, relative } from 'node:path';
import { glob } from 'glob';
import ignore from 'ignore';
import { Finding, Rule } from '../types.js';
import { allRules } from './rules/index.js';

const SUPPRESS_REGEX = /(?:\/\/|#|\/\*)\s*secaudit-disable(?:-next)?-line\s+([\w,\s]+)/i;
const SUPPRESS_FILE_REGEX = /(?:\/\/|#|\/\*)\s*secaudit-disable-file\b/i;

const DEFAULT_IGNORE = [
  'node_modules/**',
  'dist/**',
  'build/**',
  '.git/**',
  'vendor/**',
  'third_party/**',
  'third-party/**',
  '__pycache__/**',
  '.venv/**',
  'venv/**',
  '*.min.js',
  '*.min.css',
  '*.map',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  // i18n / locale files (high false-positive rate)
  '**/i18n/**',
  '**/locales/**',
  '**/locale/**',
  '**/translations/**',
  '**/lang/**',
  // Test files (hardcoded creds are intentional)
  '**/test/**',
  '**/tests/**',
  '**/spec/**',
  '**/__tests__/**',
  '**/test-*/**',
  '**/cypress/**',
  '**/e2e/**',
  // Data / config files (not source code)
  '*.json',
  '*.yml',
  '*.yaml',
  '*.toml',
  '*.xml',
  '*.md',
  '*.txt',
  '*.csv',
  '*.svg',
  '*.html',
  '*.css',
  '*.scss',
  '*.less',
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

      // Check file-level suppression
      if (lines.some((l) => SUPPRESS_FILE_REGEX.test(l))) continue;

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];

        // Check line-level suppression (current line or previous line)
        const suppressMatch = SUPPRESS_REGEX.exec(line) ?? (lineNum > 0 ? SUPPRESS_REGEX.exec(lines[lineNum - 1]) : null);
        const suppressedRules = suppressMatch ? new Set(suppressMatch[1].split(/[,\s]+/).map((s) => s.trim())) : null;

        for (const rule of this.rules) {
          if (rule.fileExtensions && !rule.fileExtensions.includes(ext)) {
            continue;
          }

          // Skip if rule is suppressed
          if (suppressedRules && (suppressedRules.has(rule.id) || suppressedRules.has('all'))) continue;

          const match = rule.pattern.exec(line);
          if (match && !rule.negate) {
            // Skip if line is a comment (but not a suppression directive we already handled)
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
              cwe: rule.cwe,
              owasp: rule.owasp,
              fix: rule.fix,
            });
          }
        }
      }
    }

    return { findings, filesScanned: filtered.length };
  }
}
