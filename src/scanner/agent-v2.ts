/**
 * Agent V2 — Real tool-use agent via pi-ai's complete() with proper multi-turn.
 * 
 * Tools:
 * - read_file: Read a source file with line numbers
 * - search: Grep for a pattern across all files
 * - list_files: List all source files in a directory
 * - report_finding: Report a confirmed vulnerability
 * - done: Finish the audit
 */

import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, relative, extname, dirname } from 'node:path';
import { execSync } from 'node:child_process';
import { createModel } from '../providers/pi-ai.js';
import type { Finding } from '../types.js';
import { Severity } from '../types.js';
import type { Context, Tool, Message, AssistantMessage, ToolCall, ToolResultMessage } from '@mariozechner/pi-ai';
import { complete } from '@mariozechner/pi-ai';
import { Type } from '@sinclair/typebox';

const CODE_EXTENSIONS = new Set([
  '.ts', '.js', '.jsx', '.tsx', '.py', '.rb', '.java', '.go',
  '.php', '.cs', '.rs', '.c', '.cpp', '.h', '.sol', '.vy',
]);

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'lib', 'forge-std',
  'openzeppelin-contracts', '.openzeppelin', 'test', 'tests',
  'mock', 'mocks', 'script', 'scripts',
]);

// Tool definitions using TypeBox schema
const TOOLS: Tool[] = [
  {
    name: 'read_file',
    description: 'Read a source file with line numbers. Use this to examine contract code.',
    parameters: Type.Object({
      path: Type.String({ description: 'Relative file path from project root' }),
    }),
  },
  {
    name: 'search',
    description: 'Search for a text pattern across all source files. Returns matching lines with file:line prefix. Use to find function calls, variable usage, access patterns.',
    parameters: Type.Object({
      pattern: Type.String({ description: 'Text pattern to search for' }),
    }),
  },
  {
    name: 'list_files',
    description: 'List all source files in a directory (recursive). Shows file sizes.',
    parameters: Type.Object({
      directory: Type.Optional(Type.String({ description: 'Subdirectory to list (default: project root)' })),
    }),
  },
  {
    name: 'report_finding',
    description: 'Report a confirmed HIGH-SEVERITY vulnerability. Only report loss-of-funds issues you are confident about.',
    parameters: Type.Object({
      file: Type.String({ description: 'Relative file path' }),
      line: Type.Number({ description: 'Line number' }),
      severity: Type.Union([Type.Literal('critical'), Type.Literal('high')]),
      title: Type.String({ description: 'Short title (e.g., "Missing access control on withdraw")' }),
      description: Type.String({ description: 'Detailed root cause, exploit scenario, and impact' }),
    }),
  },
  {
    name: 'run_command',
    description: 'Execute a shell command in the project directory. Use for: grep/rg with regex, find, wc, forge build/test, solc, or any analysis command. Commands are sandboxed to the project dir. Timeout: 30s.',
    parameters: Type.Object({
      command: Type.String({ description: 'Shell command to execute (e.g., "rg -n transferFrom", "find . -name *.sol | wc -l")' }),
    }),
  },
  {
    name: 'write_file',
    description: 'Write content to a file. Use to create PoC test files or analysis scripts.',
    parameters: Type.Object({
      path: Type.String({ description: 'Relative file path to write' }),
      content: Type.String({ description: 'File content' }),
    }),
  },
  {
    name: 'done',
    description: 'Finish the audit. Call this when you have thoroughly examined the codebase.',
    parameters: Type.Object({}),
  },
];

const SYSTEM_PROMPT_SOLIDITY = `You are an elite smart contract security auditor performing a comprehensive code audit. You have tools to read files, search code, run shell commands, and report vulnerabilities.

RULES:
- You MUST read ALL important source files before finishing. Do NOT stop after reading 2-3 files.
- Use run_command with "rg" or "grep" for powerful regex searches across the codebase.
- Use report_finding for each confirmed vulnerability. Do NOT just describe findings in text.
- Call "done" ONLY after you have read all core contracts and thoroughly analyzed them.

AUDIT METHODOLOGY (follow this order):
1. list_files to see project structure
2. Read ALL core contracts (skip interfaces/libraries unless needed)
3. For EACH contract with state-changing functions, check:
   a. Access control: who can call each external/public function? Missing onlyOwner/onlyAdmin?
   b. Reentrancy: external calls before state updates? CEI violations?
   c. Math: unchecked blocks with user input? Division before multiplication? Rounding direction?
   d. Value flow: does deposit amount == credited amount? (fee-on-transfer, rebasing tokens)
   e. Oracle trust: can prices be manipulated in one transaction? (flash loans, donations)
   f. Signatures: missing chainId, nonce, deadline, domain separator?
   g. Accounting: can totalShares * pricePerShare != totalAssets after operations?
4. Use "rg -n 'pattern'" to trace cross-contract data flows:
   - rg -n 'transfer\(|transferFrom\(' — find all token transfers
   - rg -n 'msg.sender|tx.origin' — find auth patterns
   - rg -n 'balanceOf|totalSupply' — find balance-dependent logic
   - rg -n 'external|public' — find all entry points
5. Report each finding with report_finding tool (exact file, line, exploit scenario)
6. Only call done when you've covered all contracts

Focus on HIGH-SEVERITY LOSS-OF-FUNDS issues only. Be specific with exploit scenarios.`;

const SYSTEM_PROMPT_DEFAULT = `You are an elite security auditor. You have access to tools to read files, search code, and report vulnerabilities.

Your goal: find ALL HIGH-SEVERITY vulnerabilities.

Strategy:
1. List files to understand the project
2. Read entry points and critical modules
3. Check authentication, authorization, injection, business logic
4. Use search to trace data flows
5. Report only findings you are confident about

Be thorough.`;

function listSourceFiles(basePath: string, subdir?: string): string {
  const targetPath = subdir ? join(basePath, subdir) : basePath;
  const lines: string[] = [];
  
  const walk = (dir: string, prefix: string) => {
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (IGNORE_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          lines.push(`${prefix}${entry.name}/`);
          walk(fullPath, prefix + '  ');
        } else {
          const ext = extname(entry.name).toLowerCase();
          if (CODE_EXTENSIONS.has(ext) || entry.name === 'README.md') {
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
    } catch { /* skip */ }
  };
  
  walk(targetPath, '');
  return lines.join('\n') || 'No files found';
}

function readFile(basePath: string, filePath: string): string {
  try {
    const full = join(basePath, filePath);
    if (!full.startsWith(basePath)) return 'Error: path outside project';
    const content = readFileSync(full, 'utf-8');
    const truncated = content.length > 100_000 ? content.substring(0, 100_000) + '\n... (truncated)' : content;
    return truncated.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');
  } catch {
    return `Error: could not read "${filePath}"`;
  }
}

function searchFiles(basePath: string, pattern: string): string {
  const results: string[] = [];
  const walk = (dir: string) => {
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (IGNORE_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else {
          const ext = extname(entry.name).toLowerCase();
          if (!CODE_EXTENSIONS.has(ext)) continue;
          try {
            const content = readFileSync(full, 'utf-8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
              if (lines[i].includes(pattern)) {
                results.push(`${relative(basePath, full)}:${i + 1}: ${lines[i].trim()}`);
                if (results.length >= 100) return;
              }
            }
          } catch { /* skip */ }
        }
      }
    } catch { /* skip */ }
  };
  walk(basePath);
  return results.length > 0 ? results.join('\n') : `No matches for "${pattern}"`;
}

function handleToolCall(basePath: string, toolCall: ToolCall): { content: string; finding?: Finding } {
  const args = toolCall.arguments || {};
  
  switch (toolCall.name) {
    case 'read_file':
      return { content: readFile(basePath, args.path || '') };
    
    case 'search':
      return { content: searchFiles(basePath, args.pattern || '') };
    
    case 'list_files':
      return { content: listSourceFiles(basePath, args.directory) };
    
    case 'report_finding': {
      const finding: Finding = {
        file: args.file || '',
        line: args.line || 1,
        column: 1,
        severity: (args.severity as Severity) || Severity.High,
        category: args.title || 'Agent Finding',
        message: args.description || '',
        rule: 'AGENT_V2',
        snippet: '',
      };
      return { content: 'Finding recorded.', finding };
    }
    
    case 'run_command': {
      const cmd = args.command || '';
      // Block dangerous commands
      const blocked = ['rm -rf /', 'mkfs', 'dd if=', ':(){', 'chmod -R 777 /'];
      if (blocked.some(b => cmd.includes(b))) {
        return { content: 'Error: command blocked for safety.' };
      }
      try {
        const output = execSync(cmd, {
          cwd: basePath,
          timeout: 30_000,
          maxBuffer: 1024 * 1024,
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        const truncated = output.length > 50_000 ? output.substring(0, 50_000) + '\n... (truncated)' : output;
        return { content: truncated || '(no output)' };
      } catch (err: any) {
        const stderr = err.stderr || '';
        const stdout = err.stdout || '';
        const output = (stdout + '\n' + stderr).trim();
        return { content: output ? `Exit code ${err.status || 1}:\n${output.substring(0, 10_000)}` : `Command failed: ${err.message}` };
      }
    }

    case 'write_file': {
      const filePath = args.path || '';
      const content = args.content || '';
      try {
        const full = join(basePath, filePath);
        if (!full.startsWith(basePath)) return { content: 'Error: path outside project' };
        mkdirSync(dirname(full), { recursive: true });
        writeFileSync(full, content, 'utf-8');
        return { content: `Written ${content.length} bytes to ${filePath}` };
      } catch (err: any) {
        return { content: `Error writing file: ${err.message}` };
      }
    }
    
    case 'done':
      return { content: 'Audit complete.' };
    
    default:
      return { content: `Unknown tool: ${toolCall.name}` };
  }
}

export interface AgentV2Config {
  provider: string;
  model: string;
  apiKey?: string;
  maxIterations: number;
  verbose: boolean;
  reasoning?: string;
}

export class AgentV2Scanner {
  private config: AgentV2Config;
  private log: (msg: string) => void;

  constructor(config: AgentV2Config) {
    this.config = config;
    this.log = config.verbose
      ? (msg: string) => console.error(`  [agent-v2] ${msg}`)
      : () => {};
  }

  async scan(targetPath: string): Promise<{ findings: Finding[]; iterations: number }> {
    const m = createModel(this.config.provider, this.config.model, this.config.apiKey);
    const findings: Finding[] = [];
    const filesRead = new Set<string>();
    let searchCount = 0;
    let commandCount = 0;

    // Detect Solidity project and count source files
    const fileList = listSourceFiles(targetPath);
    const isSolidity = fileList.includes('.sol');
    const sourceFileCount = (fileList.match(/\.\w+\s+\(/g) || []).length;
    const minFilesBeforeDone = Math.min(Math.max(5, Math.floor(sourceFileCount * 0.5)), 20);

    const messages: Message[] = [
      {
        role: 'user' as const,
        content: `Audit this ${isSolidity ? 'Solidity/DeFi' : ''} project for HIGH-SEVERITY loss-of-funds vulnerabilities. Start by listing files, then read and analyze each important contract. Be thorough.`,
        timestamp: Date.now(),
      },
    ];

    const context: Context = {
      systemPrompt: isSolidity ? SYSTEM_PROMPT_SOLIDITY : SYSTEM_PROMPT_DEFAULT,
      messages,
      tools: TOOLS,
    };

    let iterations = 0;

    for (let i = 0; i < this.config.maxIterations; i++) {
      iterations = i + 1;

      // Call LLM with tools
      let response: AssistantMessage;
      try {
        const opts: any = {};
        if (this.config.apiKey) opts.apiKey = this.config.apiKey;
        if (this.config.reasoning) opts.reasoning = this.config.reasoning;
        response = await complete(m, context, Object.keys(opts).length ? opts : undefined);
      } catch (err) {
        this.log(`LLM error at iteration ${i + 1}: ${(err as Error).message}`);
        break;
      }

      // Add assistant message to conversation
      messages.push(response);

      // Check for tool calls
      const toolCalls = response.content.filter((c): c is ToolCall => c.type === 'toolCall');
      
      if (toolCalls.length === 0) {
        this.log(`[${i + 1}/${this.config.maxIterations}] Text response (no tool calls, ${filesRead.size} files read)`);
        
        // If model stopped but hasn't read enough files, nudge it to continue
        if (response.stopReason === 'stop' && filesRead.size < minFilesBeforeDone && i < this.config.maxIterations - 2) {
          this.log(`Nudging: only ${filesRead.size}/${minFilesBeforeDone} files read`);
          messages.push({
            role: 'user' as const,
            content: `You've only read ${filesRead.size} files out of ${sourceFileCount} source files. You need to read at least ${minFilesBeforeDone} files before concluding. Continue reading the remaining contracts and use run_command with "rg" to search for vulnerability patterns. Use report_finding for any issues found.`,
            timestamp: Date.now(),
          });
          continue;
        }
        
        if (response.stopReason === 'stop') {
          this.log('Model stopped naturally');
          break;
        }
        continue;
      }

      // Process each tool call
      let isDone = false;
      for (const toolCall of toolCalls) {
        this.log(`[${i + 1}/${this.config.maxIterations}] Tool: ${toolCall.name}(${JSON.stringify(toolCall.arguments).substring(0, 80)})`);
        
        // Track activity
        if (toolCall.name === 'read_file' && toolCall.arguments?.path) {
          filesRead.add(toolCall.arguments.path);
        }
        if (toolCall.name === 'search') searchCount++;
        if (toolCall.name === 'run_command') commandCount++;
        
        if (toolCall.name === 'done') {
          if (filesRead.size < minFilesBeforeDone) {
            // Block premature done
            const toolResult: ToolResultMessage = {
              role: 'toolResult' as const,
              toolCallId: toolCall.id,
              toolName: toolCall.name,
              content: [{ type: 'text' as const, text: `Cannot finish yet. You've only read ${filesRead.size}/${minFilesBeforeDone} required files. Continue reading contracts and analyzing them.` }],
              isError: true,
              timestamp: Date.now(),
            };
            messages.push(toolResult);
            continue;
          }
          isDone = true;
        }

        if (toolCall.name === 'done' && !isDone) continue; // already handled above
        const result = handleToolCall(targetPath, toolCall);
        
        if (result.finding) {
          findings.push(result.finding);
          this.log(`  📍 Finding: ${result.finding.severity.toUpperCase()} ${result.finding.file}:${result.finding.line}`);
        }

        // Add tool result to conversation
        const toolResult: ToolResultMessage = {
          role: 'toolResult' as const,
          toolCallId: toolCall.id,
          toolName: toolCall.name,
          content: [{ type: 'text' as const, text: result.content }],
          isError: result.content.startsWith('Error:'),
          timestamp: Date.now(),
        };
        messages.push(toolResult);
      }

      if (isDone) {
        this.log(`Agent finished after ${i + 1} iterations with ${findings.length} findings`);
        break;
      }

      // Context management: estimate token usage
      const totalChars = messages.reduce((sum, m) => {
        if (typeof m.content === 'string') return sum + m.content.length;
        if (Array.isArray(m.content)) {
          return sum + m.content.reduce((s, c) => {
            if ('text' in c) return s + (c as any).text.length;
            return s + 100; // rough estimate for other content types
          }, 0);
        }
        return sum;
      }, 0);

      if (totalChars > 300_000) {
        this.log(`Context too large (${Math.round(totalChars / 1000)}K chars), stopping`);
        break;
      }
    }

    this.log(`Total: ${findings.length} findings in ${iterations} iterations`);
    return { findings, iterations };
  }
}
