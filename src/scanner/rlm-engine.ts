import { readFileSync } from 'node:fs';
import { extname, dirname, basename, join } from 'node:path';
import { glob } from 'glob';
import type { Finding, Severity } from '../types.js';

const CODE_EXTENSIONS = new Set([
  '.ts', '.js', '.jsx', '.tsx', '.py', '.go', '.java', '.c', '.cpp', '.h',
  '.hpp', '.rs', '.rb', '.php', '.cs', '.swift', '.kt', '.scala', '.vue',
]);

const MAX_CHARS_PER_CHUNK = 100_000;
const MAX_FILE_SIZE = 50_000;

export interface RLMConfig {
  provider: string;
  model: string;
  apiKey?: string;
  concurrency: number;
  maxDepth: number;
  maxIterations: number;
}

export interface RLMResult {
  findings: Finding[];
  llmCalls: number;
  chunksAnalyzed: number;
  modulesIdentified: string[];
}

interface FileInfo {
  path: string;
  content: string;
  lines: string[];
  size: number;
}

interface ModuleGroup {
  name: string;
  files: FileInfo[];
  priority: number;
}

/**
 * Recursive Language Model engine for deep security analysis.
 *
 * Implements recursive decomposition: an LLM identifies security-critical
 * areas, spawns sub-analyses on those areas, then aggregates the results.
 */
export class RLMEngine {
  private config: RLMConfig;
  private callCount = 0;

  constructor(config: Partial<RLMConfig> = {}) {
    this.config = {
      provider: config.provider ?? 'openai-codex',
      model: config.model ?? 'gpt-5.3-codex',
      apiKey: config.apiKey,
      concurrency: config.concurrency ?? 3,
      maxDepth: config.maxDepth ?? 2,
      maxIterations: config.maxIterations ?? 30,
    };
  }

  /**
   * Make a single LLM call. Returns the text response.
   */
  async llmQuery(systemPrompt: string, userPrompt: string): Promise<string> {
    if (this.callCount >= this.config.maxIterations) {
      return '';
    }
    this.callCount++;

    try {
      const { createModel } = await import('../providers/pi-ai.js');
      const { completeSimple } = await import('@mariozechner/pi-ai');
      const m = createModel(this.config.provider, this.config.model, this.config.apiKey);
      const ctx = {
        systemPrompt,
        messages: [{ role: 'user' as const, content: userPrompt, timestamp: Date.now() }],
      };
      const result = await completeSimple(
        m, ctx,
        this.config.apiKey ? { apiKey: this.config.apiKey } as any : undefined,
      );
      const textParts = result.content.filter(
        (c): c is { type: 'text'; text: string } => 'type' in c && (c as any).type === 'text',
      );
      return textParts.map((p) => p.text).join('');
    } catch (err) {
      console.error(`RLM query failed:`, (err as Error).message);
      return '';
    }
  }

  /**
   * Execute multiple LLM calls concurrently, respecting the concurrency limit.
   */
  async llmQueryBatched(
    calls: Array<{ systemPrompt: string; userPrompt: string }>,
  ): Promise<string[]> {
    const results: string[] = [];
    for (let i = 0; i < calls.length; i += this.config.concurrency) {
      const batch = calls.slice(i, i + this.config.concurrency);
      const batchResults = await Promise.all(
        batch.map((c) => this.llmQuery(c.systemPrompt, c.userPrompt)),
      );
      results.push(...batchResults);
    }
    return results;
  }

  /**
   * Read and index all code files under a target path.
   */
  async readFiles(targetPath: string): Promise<FileInfo[]> {
    const allFiles = await glob('**/*', { cwd: targetPath, nodir: true, dot: false });
    const codeFiles = allFiles.filter((f) => CODE_EXTENSIONS.has(extname(f).toLowerCase()));

    const infos: FileInfo[] = [];
    for (const file of codeFiles) {
      try {
        const content = readFileSync(join(targetPath, file), 'utf-8');
        if (content.length > MAX_FILE_SIZE) continue;
        infos.push({
          path: file,
          content,
          lines: content.split('\n'),
          size: content.length,
        });
      } catch {
        continue;
      }
    }
    return infos;
  }

  /**
   * Chunk files into groups that fit within the context limit.
   * Groups files by directory for related-file context.
   */
  chunkCode(files: FileInfo[], maxCharsPerChunk: number = MAX_CHARS_PER_CHUNK): FileInfo[][] {
    const chunks: FileInfo[][] = [];
    let currentChunk: FileInfo[] = [];
    let currentSize = 0;

    // Sort by directory so related files stay together
    const sorted = [...files].sort((a, b) => dirname(a.path).localeCompare(dirname(b.path)));

    for (const file of sorted) {
      const fileSize = file.content.length + file.path.length + 50; // overhead for headers
      if (currentSize + fileSize > maxCharsPerChunk && currentChunk.length > 0) {
        chunks.push(currentChunk);
        currentChunk = [];
        currentSize = 0;
      }
      currentChunk.push(file);
      currentSize += fileSize;
    }

    if (currentChunk.length > 0) {
      chunks.push(currentChunk);
    }

    return chunks;
  }

  /**
   * Format files into a numbered code block for LLM consumption.
   */
  formatFilesForLLM(files: FileInfo[]): string {
    return files.map((f) => {
      const numbered = f.content.split('\n').map((l, i) => `${i + 1}: ${l}`).join('\n');
      return `\n=== FILE: ${f.path} ===\n${numbered}\n`;
    }).join('');
  }

  /**
   * Build a file listing (tree) for reconnaissance.
   */
  buildFileTree(files: FileInfo[]): string {
    const dirs = new Map<string, string[]>();
    for (const f of files) {
      const dir = dirname(f.path);
      const arr = dirs.get(dir) ?? [];
      arr.push(`${basename(f.path)} (${f.lines.length} lines)`);
      dirs.set(dir, arr);
    }

    const lines: string[] = [];
    for (const [dir, fileNames] of [...dirs.entries()].sort()) {
      lines.push(`${dir}/`);
      for (const name of fileNames) {
        lines.push(`  ${name}`);
      }
    }
    return lines.join('\n');
  }

  /**
   * Parse a JSON array from LLM text output. Returns [] on failure.
   */
  parseJSONArray<T>(text: string): T[] {
    if (!text) return [];
    const match = text.match(/\[[\s\S]*\]/);
    if (!match) return [];
    try {
      return JSON.parse(match[0]) as T[];
    } catch {
      return [];
    }
  }

  /**
   * Parse raw findings from LLM output into Finding objects.
   */
  parseFindings(text: string, defaultSnippet: string = ''): Finding[] {
    const raw = this.parseJSONArray<{
      file?: string; line?: number; severity?: string;
      category?: string; message?: string; rule?: string;
    }>(text);

    return raw
      .filter((item) => item.message)
      .map((item) => ({
        file: item.file || 'unknown',
        line: item.line || 1,
        column: 1,
        severity: (item.severity as Severity) || ('medium' as Severity),
        category: item.category || 'Cross-File Vulnerability',
        message: item.message!,
        rule: item.rule || 'RLM_GENERIC',
        snippet: defaultSnippet,
      }));
  }

  /** Number of LLM calls made so far */
  get currentCallCount(): number {
    return this.callCount;
  }

  /** Whether we've hit the iteration limit */
  get isExhausted(): boolean {
    return this.callCount >= this.config.maxIterations;
  }

  /** Reset call counter (for reuse across phases) */
  resetCallCount(): void {
    this.callCount = 0;
  }
}
