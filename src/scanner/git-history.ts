import { execFileSync } from 'node:child_process';
import { Finding, Severity } from '../types.js';
import { analyzeCode } from '../providers/pi-ai.js';

const SECURITY_KEYWORDS = [
  'fix', 'vuln', 'secur', 'cve', 'overflow', 'inject', 'xss', 'csrf',
  'sanitiz', 'escap', 'bounds', 'buffer', 'exploit', 'patch', 'heap',
  'stack', 'leak', 'permission', 'auth', 'bypass', 'crash', 'denial',
  'dos', 'rce', 'remote code', 'arbitrary', 'malicious', 'unsafe',
  'null pointer', 'use.after.free', 'double.free', 'race.condition',
  'integer.overflow', 'format.string', 'path.traversal', 'privilege',
];

const SECURITY_PATTERN = new RegExp(SECURITY_KEYWORDS.join('|'), 'i');

interface SecurityCommit {
  hash: string;
  subject: string;
  date: string;
  diff: string;
  files: string[];
}

function getSecurityCommits(repoPath: string, limit: number = 100): SecurityCommit[] {
  // Get recent commits with security-related messages
  let log: string;
  try {
    log = execFileSync('git', [
      'log', `--max-count=${limit * 3}`, '--format=%H|||%s|||%ai',
    ], { cwd: repoPath, encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 });
  } catch {
    return [];
  }

  const commits: SecurityCommit[] = [];

  for (const line of log.trim().split('\n')) {
    if (!line) continue;
    const [hash, subject, date] = line.split('|||');
    if (!SECURITY_PATTERN.test(subject)) continue;

    // Get the diff for this commit
    let diff: string;
    try {
      diff = execFileSync('git', [
        'diff', `${hash}~1..${hash}`, '--unified=5', '--stat',
      ], { cwd: repoPath, encoding: 'utf-8', maxBuffer: 5 * 1024 * 1024 });
    } catch {
      continue;
    }

    // Get changed files
    let filesStr: string;
    try {
      filesStr = execFileSync('git', [
        'diff-tree', '--no-commit-id', '-r', '--name-only', hash,
      ], { cwd: repoPath, encoding: 'utf-8' });
    } catch {
      continue;
    }

    const files = filesStr.trim().split('\n').filter(Boolean);
    commits.push({ hash: hash.substring(0, 12), subject, date, diff, files });

    if (commits.length >= limit) break;
  }

  return commits;
}

function getFullDiff(repoPath: string, hash: string): string {
  try {
    return execFileSync('git', [
      'diff', `${hash}~1..${hash}`, '--unified=10',
    ], { cwd: repoPath, encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 });
  } catch {
    return '';
  }
}

function getCurrentFileContent(repoPath: string, filePath: string): string {
  try {
    return execFileSync('git', [
      'show', `HEAD:${filePath}`,
    ], { cwd: repoPath, encoding: 'utf-8', maxBuffer: 5 * 1024 * 1024 });
  } catch {
    return '';
  }
}

const GIT_HISTORY_PROMPT = `You are a security researcher analyzing git commits for incomplete security fixes.

Given a security-related commit (diff) and the CURRENT state of related files, determine if:
1. The fix was incomplete — similar vulnerable patterns exist elsewhere in the codebase
2. The fix introduced a new vulnerability
3. Other call sites of the patched function are still vulnerable

This is exactly how real 0-days are found: a security fix in one place reveals the same bug pattern was missed elsewhere.

For each vulnerability found, respond with a JSON array:
{
  "line": <line number in current file>,
  "severity": "critical" | "high" | "medium" | "low",
  "category": "<category>",
  "message": "<what was missed and why it's vulnerable>",
  "rule": "GIT_HIST_<short_id>",
  "file": "<relative file path>"
}

If no issues found, return: []
Respond ONLY with the JSON array.`;

export class GitHistoryScanner {
  private provider: string;
  private model: string;
  private apiKey?: string;
  private maxCommits: number;

  constructor(provider: string = 'openai', model: string = 'gpt-4o-mini', apiKey?: string, maxCommits: number = 50) {
    this.provider = provider;
    this.model = model;
    this.apiKey = apiKey;
    this.maxCommits = maxCommits;
  }

  async scan(repoPath: string): Promise<{ findings: Finding[]; commitsAnalyzed: number }> {
    const commits = getSecurityCommits(repoPath, this.maxCommits);
    if (commits.length === 0) return { findings: [], commitsAnalyzed: 0 };

    const findings: Finding[] = [];

    for (const commit of commits) {
      const diff = getFullDiff(repoPath, commit.hash);
      if (!diff || diff.length > 50000) continue; // Skip huge diffs

      // Get current content of affected files
      const fileContents: string[] = [];
      for (const file of commit.files.slice(0, 5)) {
        const content = getCurrentFileContent(repoPath, file);
        if (content && content.length < 20000) {
          const numbered = content.split('\n').map((l, i) => `${i + 1}: ${l}`).join('\n');
          fileContents.push(`=== ${file} (current HEAD) ===\n${numbered}`);
        }
      }

      if (fileContents.length === 0) continue;

      // Build the prompt
      const prompt = `Security commit: ${commit.hash} — "${commit.subject}" (${commit.date})

--- COMMIT DIFF ---
${diff.substring(0, 15000)}

--- CURRENT FILE CONTENTS (check for similar unfixed patterns) ---
${fileContents.join('\n\n').substring(0, 30000)}`;

      try {
        const { createModel } = await import('../providers/pi-ai.js');
        const { completeSimple } = await import('@mariozechner/pi-ai');
        const m = createModel(this.provider, this.model, this.apiKey);
        const context = {
          systemPrompt: GIT_HISTORY_PROMPT,
          messages: [{ role: 'user' as const, content: prompt, timestamp: Date.now() }],
        };
        const result = await completeSimple(m, context, this.apiKey ? { apiKey: this.apiKey } as any : undefined);
        const textParts = result.content.filter((c): c is { type: 'text'; text: string } => 'type' in c && (c as any).type === 'text');
        const text = textParts.map((p) => p.text).join('');

        const jsonMatch = text.match(/\[[\s\S]*\]/);
        if (!jsonMatch) continue;

        const parsed = JSON.parse(jsonMatch[0]) as Array<{
          line: number; severity: string; category: string;
          message: string; rule: string; file?: string;
        }>;

        for (const item of parsed) {
          findings.push({
            file: item.file ?? commit.files[0] ?? 'unknown',
            line: item.line || 1,
            column: 1,
            severity: (item.severity as Severity) || Severity.Medium,
            category: item.category || 'Incomplete Fix',
            message: `[Git: ${commit.hash}] ${item.message}`,
            rule: item.rule || 'GIT_HIST_GENERIC',
            snippet: `Commit: "${commit.subject}"`,
            cwe: 'CWE-1068',
            owasp: 'A06:2021',
          });
        }
      } catch (err) {
        console.error(`Git history analysis failed for ${commit.hash}:`, (err as Error).message);
      }
    }

    return { findings, commitsAnalyzed: commits.length };
  }
}
