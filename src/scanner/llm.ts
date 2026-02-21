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
  private concurrency: number;

  constructor(provider: string = 'openai', model: string = 'gpt-4o-mini', apiKey?: string, concurrency: number = 5) {
    this.provider = provider;
    this.model = model;
    this.apiKey = apiKey;
    this.concurrency = concurrency;
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

    // Pre-read and filter files
    const fileInfos: Array<{ file: string; content: string; lines: string[] }> = [];
    for (const file of filtered) {
      const fullPath = `${targetPath}/${file}`;
      let content: string;
      try {
        content = readFileSync(fullPath, 'utf-8');
      } catch {
        continue;
      }
      if (content.length > MAX_FILE_SIZE) continue;
      const lines = content.split('\n');
      if (lines.length < 5) continue;
      fileInfos.push({ file, content, lines });
    }

    const findings: Finding[] = [];

    // Process files with concurrency limit
    const analyzeFile = async (info: typeof fileInfos[0]): Promise<Finding[]> => {
      const relPath = relative(targetPath, `${targetPath}/${info.file}`);
      const fileFindings = await analyzeCode(this.provider, this.model, info.content, relPath, this.apiKey);
      for (const finding of fileFindings) {
        if (finding.line > 0 && finding.line <= info.lines.length) {
          finding.snippet = info.lines[finding.line - 1].trim().substring(0, 200);
        } else {
          finding.line = 1;
          finding.snippet = '';
        }
      }
      return fileFindings;
    };

    // Run with concurrency pool
    for (let i = 0; i < fileInfos.length; i += this.concurrency) {
      const batch = fileInfos.slice(i, i + this.concurrency);
      const results = await Promise.all(batch.map(analyzeFile));
      for (const result of results) {
        findings.push(...result);
      }
    }

    return { findings, filesScanned: fileInfos.length };
  }
}
