/**
 * Agent-based security scanner.
 * 
 * Unlike single-pass LLM scan, this runs an iterative agent loop:
 * 1. Agent sees file tree → chooses what to read
 * 2. Agent reads files → analyzes → decides next action
 * 3. Agent follows cross-references, tracks data flows
 * 4. Agent reports findings when confident
 * 
 * This mimics how Claude Code / Codex CLI work on EVMbench.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import { createModel } from '../providers/pi-ai.js';
import type { Finding } from '../types.js';
import { Severity } from '../types.js';
import type { Context } from '@mariozechner/pi-ai';
import { completeSimple } from '@mariozechner/pi-ai';

const CODE_EXTENSIONS = new Set([
  '.ts', '.js', '.jsx', '.tsx', '.py', '.rb', '.java', '.go',
  '.php', '.cs', '.rs', '.c', '.cpp', '.h', '.sol', '.vy',
]);

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'lib', 'forge-std',
  'openzeppelin-contracts', '.openzeppelin',
]);

const AGENT_SYSTEM_PROMPT = `You are an elite smart contract security auditor performing an iterative code audit.
You have a budget of actions. Each turn, you can take ONE action:

1. **READ <filepath>** — Read a source file to examine its code
2. **SEARCH <pattern>** — Search for a pattern across all files (returns matching lines)
3. **FINDING** — Report a confirmed vulnerability (JSON format below)
4. **DONE** — Finish the audit

IMPORTANT: Do NOT say DONE until you have:
1. Read at least 5-10 source files (or all files if fewer than 10)
2. Searched for critical patterns (transfer, msg.sender, balanceOf, etc.)
3. Traced at least one complete value flow (deposit → accounting → withdrawal)

Strategy tips:
- Start by reading README.md or the main entry point to understand the protocol
- Follow the money: trace deposit → internal accounting → withdrawal flows
- Check every external call for reentrancy, return value handling, and state consistency
- Verify access control on ALL state-changing functions
- Look for math errors: rounding direction, overflow in unchecked blocks, division before multiplication
- Check signature schemes for replay (missing chainId, nonce, domain separator)
- Verify oracle integrations can't be manipulated within one transaction
- Don't report issues in test/mock files

When reporting a FINDING, use this exact JSON format:
\`\`\`json
FINDING
{
  "file": "<relative path>",
  "line": <line number>,
  "severity": "critical" | "high",
  "category": "<category>",
  "message": "<root cause, exploit scenario, and impact>",
  "rule": "AGENT_<short_id>"
}
\`\`\`

When you want to read a file:
\`\`\`
READ path/to/file.sol
\`\`\`

When you want to search:
\`\`\`
SEARCH transfer(
\`\`\`

When done:
\`\`\`
DONE
\`\`\`

Be thorough but efficient. Focus on HIGH-SEVERITY loss-of-funds vulnerabilities only.
Do NOT report low/info/medium issues. Quality over quantity.`;

interface AgentAction {
  type: 'read' | 'search' | 'finding' | 'done' | 'unknown';
  path?: string;
  pattern?: string;
  finding?: {
    file: string;
    line: number;
    severity: string;
    category: string;
    message: string;
    rule: string;
  };
}

function buildFileTree(basePath: string, prefix = ''): string[] {
  const lines: string[] = [];
  try {
    const entries = readdirSync(basePath, { withFileTypes: true });
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry.name)) continue;
      if (entry.name.startsWith('.')) continue;
      const fullPath = join(basePath, entry.name);
      if (entry.isDirectory()) {
        lines.push(`${prefix}${entry.name}/`);
        lines.push(...buildFileTree(fullPath, prefix + '  '));
      } else {
        const ext = extname(entry.name).toLowerCase();
        if (CODE_EXTENSIONS.has(ext) || entry.name === 'README.md' || entry.name === 'AGENTS.md') {
          try {
            const stat = statSync(fullPath);
            const sizeKB = Math.round(stat.size / 1024);
            lines.push(`${prefix}${entry.name} (${sizeKB}KB)`);
          } catch {
            lines.push(`${prefix}${entry.name}`);
          }
        }
      }
    }
  } catch { /* ignore */ }
  return lines;
}

function readSourceFile(basePath: string, filePath: string): string | null {
  try {
    const full = join(basePath, filePath);
    // Safety: don't read outside basePath
    if (!full.startsWith(basePath)) return null;
    const content = readFileSync(full, 'utf-8');
    if (content.length > 100_000) return content.substring(0, 100_000) + '\n... (truncated)';
    // Add line numbers
    return content.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');
  } catch {
    return null;
  }
}

function searchFiles(basePath: string, pattern: string): string {
  const results: string[] = [];
  const searchDir = (dir: string) => {
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (IGNORE_DIRS.has(entry.name)) continue;
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          searchDir(full);
        } else {
          const ext = extname(entry.name).toLowerCase();
          if (!CODE_EXTENSIONS.has(ext)) continue;
          try {
            const content = readFileSync(full, 'utf-8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
              if (lines[i].includes(pattern)) {
                const relPath = relative(basePath, full);
                results.push(`${relPath}:${i + 1}: ${lines[i].trim()}`);
                if (results.length >= 50) return; // limit results
              }
            }
          } catch { /* skip */ }
        }
      }
    } catch { /* skip */ }
  };
  searchDir(basePath);
  return results.length > 0
    ? results.join('\n')
    : `No matches found for "${pattern}"`;
}

function parseAction(response: string): AgentAction {
  // Check for FINDING
  const findingMatch = response.match(/FINDING\s*\n?\s*(\{[\s\S]*?\})/);
  if (findingMatch) {
    try {
      const finding = JSON.parse(findingMatch[1]);
      return { type: 'finding', finding };
    } catch { /* fall through */ }
  }

  // Check for READ
  const readMatch = response.match(/READ\s+(\S+)/);
  if (readMatch) {
    return { type: 'read', path: readMatch[1] };
  }

  // Check for SEARCH
  const searchMatch = response.match(/SEARCH\s+(.+)/);
  if (searchMatch) {
    return { type: 'search', pattern: searchMatch[1].trim() };
  }

  // Check for DONE
  if (response.includes('DONE')) {
    return { type: 'done' };
  }

  return { type: 'unknown' };
}

export interface AgentConfig {
  provider: string;
  model: string;
  apiKey?: string;
  maxIterations: number;
  verbose: boolean;
}

export class AgentScanner {
  private config: AgentConfig;
  private log: (msg: string) => void;

  constructor(config: AgentConfig) {
    this.config = config;
    this.log = config.verbose
      ? (msg: string) => console.error(`  [agent] ${msg}`)
      : () => {};
  }

  async scan(targetPath: string): Promise<{ findings: Finding[]; iterations: number }> {
    const m = createModel(this.config.provider, this.config.model, this.config.apiKey);
    const findings: Finding[] = [];
    const filesRead: Map<string, string> = new Map();

    // Build file tree
    const tree = buildFileTree(targetPath).join('\n');
    
    // Detect if Solidity project
    const isSolidity = tree.includes('.sol');

    // Conversation transcript (user-side only, rebuilt each turn)
    const transcript: string[] = [];
    transcript.push(`You are auditing a ${isSolidity ? 'Solidity/DeFi' : 'web application'} project.\n\nFile tree:\n\`\`\`\n${tree}\n\`\`\`\n\nYou have ${this.config.maxIterations} actions remaining. Start your audit. What would you like to read first?`);

    let iterations = 0;

    for (let i = 0; i < this.config.maxIterations; i++) {
      iterations = i + 1;
      
      // Build context as single user message with full transcript
      const context: Context = {
        systemPrompt: AGENT_SYSTEM_PROMPT,
        messages: [
          {
            role: 'user' as const,
            content: transcript.join('\n\n---\n\n'),
            timestamp: Date.now(),
          },
        ],
      };

      // Call LLM
      let responseText: string;
      try {
        const result = await completeSimple(m, context, this.config.apiKey ? { apiKey: this.config.apiKey } as any : undefined);
        const textParts = result.content.filter((c): c is { type: 'text'; text: string } => 'type' in c && (c as any).type === 'text');
        responseText = textParts.map((p) => p.text).join('');
      } catch (err) {
        this.log(`LLM error at iteration ${i + 1}: ${(err as Error).message}`);
        break;
      }

      if (!responseText) break;

      // Add to transcript
      transcript.push(`[Your response]:\n${responseText}`);

      // Parse action
      const action = parseAction(responseText);
      this.log(`[${i + 1}/${this.config.maxIterations}] Action: ${action.type}${action.path ? ' ' + action.path : ''}${action.pattern ? ' "' + action.pattern + '"' : ''}`);

      let userResponse: string;

      switch (action.type) {
        case 'read': {
          if (!action.path) {
            userResponse = 'Error: No file path specified. Use: READ path/to/file.sol';
            break;
          }
          if (filesRead.has(action.path)) {
            userResponse = `You already read this file. Here it is again:\n\`\`\`\n${filesRead.get(action.path)}\n\`\`\``;
            break;
          }
          const content = readSourceFile(targetPath, action.path);
          if (content) {
            filesRead.set(action.path, content);
            userResponse = `File: ${action.path}\n\`\`\`\n${content}\n\`\`\`\n\nYou have ${this.config.maxIterations - i - 1} actions remaining.`;
          } else {
            userResponse = `Error: Could not read "${action.path}". Check the path against the file tree.`;
          }
          break;
        }

        case 'search': {
          if (!action.pattern) {
            userResponse = 'Error: No search pattern specified. Use: SEARCH pattern';
            break;
          }
          const results = searchFiles(targetPath, action.pattern);
          userResponse = `Search results for "${action.pattern}":\n${results}\n\nYou have ${this.config.maxIterations - i - 1} actions remaining.`;
          break;
        }

        case 'finding': {
          if (action.finding) {
            const f: Finding = {
              file: action.finding.file,
              line: action.finding.line || 1,
              column: 1,
              severity: (action.finding.severity as Severity) || Severity.High,
              category: action.finding.category || 'Agent Analysis',
              message: action.finding.message || 'Vulnerability detected',
              rule: action.finding.rule || 'AGENT_GENERIC',
              snippet: '',
            };
            // Try to get snippet
            const fileContent = filesRead.get(f.file);
            if (fileContent) {
              const lines = fileContent.split('\n');
              // Line numbers are prefixed, find the right line
              for (const line of lines) {
                const match = line.match(/^(\d+): (.*)/);
                if (match && parseInt(match[1]) === f.line) {
                  f.snippet = match[2].trim().substring(0, 200);
                  break;
                }
              }
            }
            findings.push(f);
            this.log(`  📍 Finding: ${f.severity.toUpperCase()} ${f.file}:${f.line} — ${f.message.substring(0, 80)}...`);
            userResponse = `Finding recorded. You have ${this.config.maxIterations - i - 1} actions remaining. Continue auditing or say DONE.`;
          } else {
            userResponse = 'Error: Could not parse finding. Use the exact JSON format specified.';
          }
          break;
        }

        case 'done': {
          this.log(`Agent finished after ${i + 1} iterations with ${findings.length} findings`);
          return { findings, iterations };
        }

        default: {
          // Try to extract multiple actions or findings from free-form response
          userResponse = `I couldn't parse your action. Please use one of: READ <path>, SEARCH <pattern>, FINDING {...}, or DONE.\nYou have ${this.config.maxIterations - i - 1} actions remaining.`;
          break;
        }
      }

      // Add tool result to transcript
      transcript.push(`[Result]:\n${userResponse}`);

      // Context management: if transcript gets too long, trim old entries
      const totalChars = transcript.reduce((sum, t) => sum + t.length, 0);
      if (totalChars > 120_000) {
        // Keep first entry (file tree) + summary + last 6 entries
        const first = transcript[0];
        const recent = transcript.slice(-6);
        const summary = `[Previous turns summarized: Read ${filesRead.size} files (${[...filesRead.keys()].join(', ')}). Found ${findings.length} vulnerabilities so far.]`;
        transcript.length = 0;
        transcript.push(first, summary, ...recent);
        this.log('Context trimmed due to length');
      }
    }

    this.log(`Agent hit iteration limit (${this.config.maxIterations}) with ${findings.length} findings`);
    return { findings, iterations };
  }
}
