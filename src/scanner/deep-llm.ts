import { readFileSync } from 'node:fs';
import { extname, relative, dirname, basename } from 'node:path';
import { glob } from 'glob';
import { Finding, Severity } from '../types.js';

const CODE_EXTENSIONS = new Set([
  '.ts', '.js', '.jsx', '.tsx', '.py', '.go', '.java', '.c', '.cpp', '.h',
  '.hpp', '.rs', '.rb', '.php', '.cs', '.swift', '.kt', '.scala', '.vue',
]);

const MAX_CONTEXT = 80000; // ~80k chars, fits in most model context windows

const DEEP_PROMPT = `You are an elite security researcher performing a DEEP code audit.
Unlike a shallow scan, you have access to MULTIPLE related files from the same project.
Your job is to find vulnerabilities that ONLY become visible when understanding cross-file interactions:

1. **Data flow**: Track user input across files (controller → service → database)
2. **Auth gaps**: Routes or APIs missing authentication/authorization checks
3. **Business logic**: Flawed assumptions in multi-step processes (payments, access control)
4. **Race conditions**: Shared state accessed from concurrent paths
5. **Incomplete validation**: Input validated in one place but used raw in another
6. **Privilege escalation**: Lower-privilege code paths reaching higher-privilege operations
7. **Cryptographic issues**: Keys/IVs reused, weak algorithms, timing attacks

For each vulnerability, respond with a JSON array:
{
  "file": "<relative path>",
  "line": <line number>,
  "severity": "critical" | "high" | "medium" | "low",
  "category": "<category>",
  "message": "<detailed description of the cross-file vulnerability>",
  "rule": "DEEP_<short_id>"
}

Return [] if nothing found. Respond ONLY with the JSON array.`;

/**
 * Group files by module/directory for related-file analysis
 */
function groupFiles(files: string[]): Map<string, string[]> {
  const groups = new Map<string, string[]>();
  for (const file of files) {
    const dir = dirname(file);
    const arr = groups.get(dir) ?? [];
    arr.push(file);
    groups.set(dir, arr);
  }
  return groups;
}

export class DeepLLMScanner {
  private provider: string;
  private model: string;
  private apiKey?: string;
  private concurrency: number;

  constructor(provider: string = 'openai', model: string = 'gpt-4o-mini', apiKey?: string, concurrency: number = 3) {
    this.provider = provider;
    this.model = model;
    this.apiKey = apiKey;
    this.concurrency = concurrency;
  }

  async scan(targetPath: string): Promise<{ findings: Finding[]; modulesScanned: number }> {
    const allFiles = await glob('**/*', { cwd: targetPath, nodir: true, dot: false });
    const codeFiles = allFiles.filter((f) => CODE_EXTENSIONS.has(extname(f).toLowerCase()));

    const groups = groupFiles(codeFiles);
    const findings: Finding[] = [];
    let modulesScanned = 0;

    const analyzeGroup = async (dir: string, files: string[]): Promise<Finding[]> => {
      // Build combined context with line numbers
      let context = '';
      const includedFiles: string[] = [];

      for (const file of files) {
        const fullPath = `${targetPath}/${file}`;
        let content: string;
        try {
          content = readFileSync(fullPath, 'utf-8');
        } catch { continue; }

        if (content.length > 30000) continue; // Skip huge files

        const numbered = content.split('\n').map((l, i) => `${i + 1}: ${l}`).join('\n');
        const block = `\n=== FILE: ${file} ===\n${numbered}\n`;

        if (context.length + block.length > MAX_CONTEXT) break;
        context += block;
        includedFiles.push(file);
      }

      if (includedFiles.length < 2) return []; // Need at least 2 files for cross-file analysis
      if (context.length < 200) return [];

      try {
        const { createModel } = await import('../providers/pi-ai.js');
        const { completeSimple } = await import('@mariozechner/pi-ai');
        const m = createModel(this.provider, this.model, this.apiKey);
        const ctx = {
          systemPrompt: DEEP_PROMPT,
          messages: [{
            role: 'user' as const,
            content: `Analyze these ${includedFiles.length} related files in module "${dir}" for cross-file security vulnerabilities:\n${context}`,
            timestamp: Date.now(),
          }],
        };
        const result = await completeSimple(m, ctx, this.apiKey ? { apiKey: this.apiKey } as any : undefined);
        const textParts = result.content.filter((c): c is { type: 'text'; text: string } => 'type' in c && (c as any).type === 'text');
        const text = textParts.map((p) => p.text).join('');

        const jsonMatch = text.match(/\[[\s\S]*\]/);
        if (!jsonMatch) return [];

        const parsed = JSON.parse(jsonMatch[0]) as Array<{
          file: string; line: number; severity: string;
          category: string; message: string; rule: string;
        }>;

        return parsed.map((item) => ({
          file: item.file || includedFiles[0],
          line: item.line || 1,
          column: 1,
          severity: (item.severity as Severity) || Severity.Medium,
          category: item.category || 'Cross-File Vulnerability',
          message: item.message,
          rule: item.rule || 'DEEP_GENERIC',
          snippet: `Module: ${dir} (${includedFiles.length} files analyzed)`,
        }));
      } catch (err) {
        console.error(`Deep analysis failed for ${dir}:`, (err as Error).message);
        return [];
      }
    };

    // Process groups with concurrency
    const entries = [...groups.entries()].filter(([, files]) => files.length >= 2);
    for (let i = 0; i < entries.length; i += this.concurrency) {
      const batch = entries.slice(i, i + this.concurrency);
      const results = await Promise.all(batch.map(([dir, files]) => analyzeGroup(dir, files)));
      for (const result of results) findings.push(...result);
      modulesScanned += batch.length;
    }

    return { findings, modulesScanned };
  }
}
