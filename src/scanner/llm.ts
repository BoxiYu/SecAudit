import { readFileSync } from 'node:fs';
import { extname, relative } from 'node:path';
import { glob } from 'glob';
import ignore from 'ignore';
import { Finding } from '../types.js';
import { analyzeCode } from '../providers/pi-ai.js';

const DEFAULT_IGNORE = [
  'node_modules/**', 'dist/**', 'build/**', '.git/**',
  '*.min.js', '*.min.css', '*.map',
  'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock',
];

const CODE_EXTENSIONS = new Set([
  '.ts', '.js', '.jsx', '.tsx', '.py', '.rb', '.java', '.go',
  '.php', '.cs', '.rs', '.c', '.cpp', '.h', '.vue', '.svelte',
]);

const MAX_FILE_SIZE = 50_000; // 50KB per file for LLM analysis

export class LLMScanner {
  private provider: string;
  private model: string;
  private apiKey?: string;
  private fileFilter?: Set<string>;

  constructor(provider: string = 'openai', model: string = 'gpt-4o-mini', apiKey?: string) {
    this.provider = provider;
    this.model = model;
    this.apiKey = apiKey;
  }

  setFileFilter(files: string[]): void {
    this.fileFilter = new Set(files);
  }

  async scan(targetPath: string): Promise<{ findings: Finding[]; filesScanned: number }> {
    const files = await glob('**/*', {
      cwd: targetPath,
      nodir: true,
      dot: false,
      absolute: false,
    });

    const ig = ignore();
    ig.add(DEFAULT_IGNORE);

    const filtered = files.filter((f) => {
      const ext = extname(f).toLowerCase();
      if (!CODE_EXTENSIONS.has(ext)) return false;
      if (ig.ignores(f)) return false;
      if (this.fileFilter && !this.fileFilter.has(f)) return false;
      return true;
    });

    const findings: Finding[] = [];
    let scanned = 0;

    for (const file of filtered) {
      const fullPath = `${targetPath}/${file}`;
      let content: string;
      try {
        content = readFileSync(fullPath, 'utf-8');
      } catch {
        continue;
      }

      // Skip files that are too large
      if (content.length > MAX_FILE_SIZE) {
        continue;
      }

      // Skip files that are mostly auto-generated or have few lines
      const lines = content.split('\n');
      if (lines.length < 5) continue;

      const relPath = relative(targetPath, fullPath);
      const fileFindings = await analyzeCode(this.provider, this.model, content, relPath, this.apiKey);

      // Validate line numbers and enrich with snippets
      for (const finding of fileFindings) {
        if (finding.line > 0 && finding.line <= lines.length) {
          finding.snippet = lines[finding.line - 1].trim().substring(0, 200);
        } else {
          // Line out of range — try to find by snippet match
          finding.line = 1;
          finding.snippet = '';
        }
      }

      findings.push(...fileFindings);
      scanned++;
    }

    return { findings, filesScanned: scanned };
  }
}
