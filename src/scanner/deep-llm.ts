import type { Finding } from '../types.js';
import { RLMEngine, type RLMConfig, type RLMResult } from './rlm-engine.js';

// --- Prompts for each RLM phase ---

const RECON_PROMPT_DEFAULT = `You are an elite security researcher performing reconnaissance on a codebase.
Given the project file listing below, identify the security-critical modules/directories that need deep analysis.

Focus on:
- Entry points (HTTP routes, CLI handlers, API controllers)
- Authentication & authorization modules
- Database access layers (queries, ORMs, migrations)
- File handling & upload logic
- User input processing & validation
- Cryptographic operations
- Configuration & secrets management
- Inter-service communication

Respond with a JSON array of objects:
[{ "module": "<directory/path>", "reason": "<why this is security-critical>", "priority": 1-5 }]

Rank by priority (1 = highest risk). Return ONLY the JSON array.`;

const RECON_PROMPT_SOLIDITY = `You are an elite smart contract security researcher performing reconnaissance.
Given the Solidity project file listing below, identify contracts that need deep security analysis.

Focus on (highest to lowest priority):
- Core protocol logic (vaults, pools, staking, lending, AMM, bridges)
- Token contracts with custom mint/burn/transfer logic
- Access control / governance / admin functions
- Oracle integrations and price feeds
- Upgradeable proxy contracts and initializers
- Cross-contract interaction patterns (delegatecall, callbacks, flash loans)
- Reward/fee distribution and accounting logic
- Withdrawal/claim mechanisms

IGNORE: test files, mock contracts, interfaces-only files, standard OpenZeppelin imports

Respond with a JSON array of objects:
[{ "module": "<directory/path>", "reason": "<why this is security-critical>", "priority": 1-5 }]

Rank by priority (1 = highest risk). Return ONLY the JSON array.`;

function getReconPromptFromFiles(files: { path: string }[]): string {
  if (files.some(f => f.path.endsWith('.sol') || f.path.endsWith('.vy'))) {
    return RECON_PROMPT_SOLIDITY;
  }
  return RECON_PROMPT_DEFAULT;
}

const RECON_PROMPT = RECON_PROMPT_DEFAULT; // backward compat

const FOCUSED_ANALYSIS_PROMPT_DEFAULT = `You are an elite security researcher performing a DEEP code audit.
You have access to MULTIPLE related files from the same module.
Find vulnerabilities that ONLY become visible when understanding cross-file interactions:

1. **Data flow**: Track user input across files (controller → service → database)
2. **Auth gaps**: Routes or APIs missing authentication/authorization checks
3. **Business logic**: Flawed assumptions in multi-step processes (payments, access control)
4. **Race conditions**: Shared state accessed from concurrent paths
5. **Incomplete validation**: Input validated in one place but used raw in another
6. **Privilege escalation**: Lower-privilege code paths reaching higher-privilege operations
7. **Cryptographic issues**: Keys/IVs reused, weak algorithms, timing attacks

For each vulnerability, respond with a JSON array:
[{
  "file": "<relative path>",
  "line": <line number>,
  "severity": "critical" | "high" | "medium" | "low",
  "category": "<category>",
  "message": "<detailed description of the cross-file vulnerability>",
  "rule": "RLM_<short_id>"
}]

Return [] if nothing found. Respond ONLY with the JSON array.`;

const FOCUSED_ANALYSIS_PROMPT_SOLIDITY = `You are an elite smart contract auditor performing a DEEP security audit.
You have access to MULTIPLE related Solidity files. Find HIGH-SEVERITY LOSS-OF-FUNDS vulnerabilities.

CRITICAL patterns to check across files:

1. **Accounting errors**: Do deposits/withdrawals/fees/rewards calculate correctly? Check:
   - Share price manipulation (first depositor, donation/inflation attacks)
   - Fee-on-transfer token incompatibility in accounting
   - Rounding direction (should favor protocol, not user)
   - totalAssets/totalSupply/balanceOf consistency

2. **Access control across contracts**: 
   - Can external contracts call sensitive functions via callbacks/flash loans?
   - Are initializers protected? Can they be called twice?
   - Do modifiers actually revert (require vs bare expression)?

3. **State consistency across calls**:
   - CEI violations enabling reentrancy
   - State read in contract A, changed in contract B before A finishes
   - Flash loan enabling state manipulation between checks

4. **Cross-contract trust**:
   - Does contract A trust return values from contract B without validation?
   - Can an attacker deploy a malicious contract that mimics expected interface?
   - Signature replay across contracts/chains (missing domain separator, nonce)

5. **Token/value flow correctness**:
   - Can users extract more value than deposited through any sequence of operations?
   - Are there paths where tokens get stuck (no withdrawal mechanism)?
   - Do liquidation/claiming paths handle edge cases (zero amounts, dust, blacklisted addresses)?

Be EXTREMELY SPECIFIC: name the exact function, line, mechanism, and a concrete exploit scenario.

For each vulnerability:
[{
  "file": "<relative path>",
  "line": <line number>,
  "severity": "critical" | "high" | "medium" | "low",
  "category": "<category>",
  "message": "<root cause + exploit scenario + impact>",
  "rule": "RLM_<short_id>"
}]

Return [] if nothing found. Respond ONLY with the JSON array.`;

const FOCUSED_ANALYSIS_PROMPT = FOCUSED_ANALYSIS_PROMPT_DEFAULT;

const CROSS_MODULE_PROMPT = `You are an elite security researcher performing cross-module vulnerability analysis.
You are given findings from individual module analyses. Your job is to identify CROSS-MODULE vulnerabilities
that only become visible when considering how different parts of the application interact.

Look for:
1. **Auth bypass chains**: Auth checked in module A but skipped when called from module B
2. **Data flow across boundaries**: User input sanitized in one module but used raw in another
3. **Privilege escalation paths**: Combining lower-privilege operations across modules
4. **TOCTOU / race conditions**: State checked in one module, used in another without re-check
5. **Trust boundary violations**: Internal APIs called with external data without validation
6. **Inconsistent security policies**: Different validation rules for the same data in different modules

For each cross-module vulnerability, respond with a JSON array:
[{
  "file": "<primary file where fix should go>",
  "line": <line number>,
  "severity": "critical" | "high" | "medium" | "low",
  "category": "Cross-Module Vulnerability",
  "message": "<describe the cross-module interaction and vulnerability>",
  "rule": "RLM_CROSS_<short_id>"
}]

Return [] if nothing found. Respond ONLY with the JSON array.`;

const AGGREGATION_PROMPT = `You are a security findings deduplication and ranking engine.
Given the following list of security findings (as JSON), deduplicate and rank them.

Rules:
- Remove exact duplicates (same file + line + same vulnerability type)
- Merge findings that describe the same root cause (keep the most detailed description)
- Ensure severity ratings are consistent (if same vuln is rated differently, use the higher severity)
- Keep cross-module findings that add context beyond what individual findings say

Respond with the deduplicated JSON array in the same format. Respond ONLY with the JSON array.`;

/**
 * Deep LLM scanner using the RLM (Recursive Language Model) paradigm.
 *
 * 4-phase analysis:
 *   1. Reconnaissance - identify security-critical modules
 *   2. Focused analysis - deep-dive into each critical module
 *   3. Cross-module analysis - find inter-module vulnerabilities
 *   4. Aggregation - deduplicate and rank findings
 */
export class DeepLLMScanner {
  private engine: RLMEngine;
  private quiet: boolean;
  private useRepl: boolean;

  constructor(
    provider: string = 'openai-codex',
    model: string = 'gpt-5.3-codex',
    apiKey?: string,
    concurrency: number = 3,
    maxDepth: number = 2,
    maxIterations: number = 30,
    useRepl: boolean = false,
  ) {
    this.engine = new RLMEngine({ provider, model, apiKey, concurrency, maxDepth, maxIterations });
    this.quiet = false;
    this.useRepl = useRepl;
  }

  setQuiet(quiet: boolean): void {
    this.quiet = quiet;
  }

  private log(msg: string): void {
    if (!this.quiet) console.log(msg);
  }

  async scan(targetPath: string): Promise<{ findings: Finding[]; modulesScanned: number }> {
    const result = await this.analyze(targetPath);
    return { findings: result.findings, modulesScanned: result.modulesIdentified.length };
  }

  async analyze(targetPath: string): Promise<RLMResult> {
    const files = await this.engine.readFiles(targetPath);
    if (files.length === 0) {
      return { findings: [], llmCalls: 0, chunksAnalyzed: 0, modulesIdentified: [] };
    }

    // Phase 1: Reconnaissance
    this.log('   Phase 1/4: Reconnaissance — identifying critical modules...');
    const modules = await this.phaseRecon(files);
    this.log(`   Found ${modules.length} security-critical modules`);

    if (modules.length === 0 || this.engine.isExhausted) {
      return { findings: [], llmCalls: this.engine.currentCallCount, chunksAnalyzed: 0, modulesIdentified: [] };
    }

    // Phase 2: Focused analysis per module (REPL-enhanced if available)
    let moduleFindings: Finding[];
    if (this.useRepl) {
      this.log('   Phase 2/4: REPL-enhanced focused analysis — deep-diving with code execution...');
      moduleFindings = await this.phaseFocusedAnalysisREPL(targetPath, modules);
    } else {
      this.log('   Phase 2/4: Focused analysis — deep-diving into modules...');
      moduleFindings = await this.phaseFocusedAnalysis(files, modules);
    }
    this.log(`   Phase 2 found ${moduleFindings.length} findings across ${modules.length} modules`);

    // Phase 3: Cross-module analysis
    let crossFindings: Finding[] = [];
    if (moduleFindings.length > 0 && modules.length > 1 && !this.engine.isExhausted) {
      this.log('   Phase 3/4: Cross-module analysis — finding inter-module vulnerabilities...');
      crossFindings = await this.phaseCrossModule(files, modules, moduleFindings);
      this.log(`   Phase 3 found ${crossFindings.length} cross-module findings`);
    } else {
      this.log('   Phase 3/4: Cross-module analysis — skipped (insufficient data)');
    }

    // Phase 4: Aggregation
    const allFindings = [...moduleFindings, ...crossFindings];
    this.log('   Phase 4/4: Aggregation — deduplicating and ranking...');
    const finalFindings = await this.phaseAggregation(allFindings);
    this.log(`   Final: ${finalFindings.length} unique findings (${this.engine.currentCallCount} LLM calls)`);

    return {
      findings: finalFindings,
      llmCalls: this.engine.currentCallCount,
      chunksAnalyzed: modules.length,
      modulesIdentified: modules.map((m) => m.module),
    };
  }

  /**
   * Phase 1: Send the file tree to LLM and get back prioritized modules.
   */
  private async phaseRecon(
    files: Array<{ path: string; content: string; lines: string[]; size: number }>,
  ): Promise<Array<{ module: string; reason: string; priority: number }>> {
    const tree = this.engine.buildFileTree(files);
    const reconPrompt = getReconPromptFromFiles(files);
    const text = await this.engine.llmQuery(
      reconPrompt,
      `Here is the project structure:\n\n${tree}`,
    );

    const modules = this.engine.parseJSONArray<{ module: string; reason: string; priority: number }>(text);

    // Sort by priority (1 = highest) and take top modules
    return modules
      .filter((m) => m.module && m.priority)
      .sort((a, b) => a.priority - b.priority);
  }

  /**
   * Phase 2: For each critical module, gather its files and analyze in chunks.
   */
  private async phaseFocusedAnalysis(
    allFiles: Array<{ path: string; content: string; lines: string[]; size: number }>,
    modules: Array<{ module: string; reason: string; priority: number }>,
  ): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Build batched calls — one per module chunk
    const calls: Array<{ systemPrompt: string; userPrompt: string; moduleName: string }> = [];

    for (const mod of modules) {
      if (this.engine.isExhausted) break;

      // Match files belonging to this module (prefix match on directory)
      const moduleFiles = allFiles.filter((f) =>
        f.path.startsWith(mod.module) || f.path.startsWith(mod.module + '/'),
      );

      if (moduleFiles.length === 0) {
        // Try fuzzy match — module name as substring
        const fuzzyFiles = allFiles.filter((f) =>
          f.path.toLowerCase().includes(mod.module.toLowerCase()),
        );
        if (fuzzyFiles.length === 0) continue;
        moduleFiles.push(...fuzzyFiles);
      }

      // Chunk the module's files if they exceed context limits
      const chunks = this.engine.chunkCode(moduleFiles);

      for (const chunk of chunks) {
        const context = this.engine.formatFilesForLLM(chunk);
        const fileList = chunk.map((f) => f.path).join(', ');
        calls.push({
          systemPrompt: chunk.some(f => f.path.endsWith('.sol')) ? FOCUSED_ANALYSIS_PROMPT_SOLIDITY : FOCUSED_ANALYSIS_PROMPT_DEFAULT,
          userPrompt: `Analyze these ${chunk.length} files in module "${mod.module}" (${mod.reason}) for security vulnerabilities:\n${context}`,
          moduleName: mod.module,
        });
      }
    }

    // Execute batched
    const results = await this.engine.llmQueryBatched(
      calls.map((c) => ({ systemPrompt: c.systemPrompt, userPrompt: c.userPrompt })),
    );

    for (let i = 0; i < results.length; i++) {
      const parsed = this.engine.parseFindings(results[i], `Module: ${calls[i].moduleName}`);
      findings.push(...parsed);
    }

    return findings;
  }

  /**
   * Phase 3: Take findings from Phase 2, group related ones, and look for cross-module issues.
   */
  private async phaseCrossModule(
    allFiles: Array<{ path: string; content: string; lines: string[]; size: number }>,
    modules: Array<{ module: string; reason: string; priority: number }>,
    existingFindings: Finding[],
  ): Promise<Finding[]> {
    // Summarize existing findings per module
    const findingsByModule = new Map<string, Finding[]>();
    for (const f of existingFindings) {
      for (const mod of modules) {
        if (f.file.startsWith(mod.module) || f.file.includes(mod.module)) {
          const arr = findingsByModule.get(mod.module) ?? [];
          arr.push(f);
          findingsByModule.set(mod.module, arr);
          break;
        }
      }
    }

    const findingsSummary = existingFindings.map((f) =>
      `[${f.severity}] ${f.file}:${f.line} — ${f.message} (${f.rule})`
    ).join('\n');

    // Also include a brief code snippet from the most critical files
    const criticalFiles = existingFindings
      .filter((f) => f.severity === 'critical' || f.severity === 'high')
      .map((f) => f.file);
    const uniqueCritFiles = [...new Set(criticalFiles)].slice(0, 5);
    const critFileContents = allFiles
      .filter((f) => uniqueCritFiles.includes(f.path))
      .slice(0, 5);

    let codeContext = '';
    if (critFileContents.length > 0) {
      codeContext = '\n\nKey files for context:\n' + this.engine.formatFilesForLLM(critFileContents);
    }

    const text = await this.engine.llmQuery(
      CROSS_MODULE_PROMPT,
      `Modules analyzed: ${modules.map((m) => m.module).join(', ')}\n\nFindings from individual module analysis:\n${findingsSummary}${codeContext}`,
    );

    return this.engine.parseFindings(text, 'Cross-module analysis');
  }

  /**
   * Phase 4: Deduplicate and rank all findings.
   * Uses LLM for intelligent dedup if we have budget, otherwise falls back to simple dedup.
   */
  private async phaseAggregation(findings: Finding[]): Promise<Finding[]> {
    if (findings.length === 0) return [];

    // If few findings or no LLM budget, do simple dedup
    if (findings.length <= 5 || this.engine.isExhausted) {
      return this.simpleDeduplicate(findings);
    }

    // LLM-assisted deduplication
    const findingsJSON = JSON.stringify(
      findings.map((f) => ({
        file: f.file,
        line: f.line,
        severity: f.severity,
        category: f.category,
        message: f.message,
        rule: f.rule,
      })),
      null,
      2,
    );

    const text = await this.engine.llmQuery(
      AGGREGATION_PROMPT,
      `Deduplicate and rank these ${findings.length} security findings:\n${findingsJSON}`,
    );

    const deduped = this.engine.parseFindings(text);
    if (deduped.length === 0) {
      // Fallback if LLM failed to return valid JSON
      return this.simpleDeduplicate(findings);
    }

    // Restore snippet field from original findings where possible
    for (const f of deduped) {
      const original = findings.find((o) => o.file === f.file && o.line === f.line);
      if (original?.snippet) {
        f.snippet = original.snippet;
      }
    }

    return deduped;
  }

  /**
   * Phase 2 (REPL variant): Use the REPL sandbox for focused analysis.
   * The LLM can write and execute Python code to programmatically analyze the codebase.
   */
  private async phaseFocusedAnalysisREPL(
    targetPath: string,
    modules: Array<{ module: string; reason: string; priority: number }>,
  ): Promise<Finding[]> {
    const moduleSummary = modules
      .map((m) => `- ${m.module} (priority ${m.priority}): ${m.reason}`)
      .join('\n');

    const query = `Focus on these security-critical modules:\n${moduleSummary}`;

    const { findings, iterations } = await this.engine.analyzeWithREPL(targetPath, query);
    this.log(`   REPL analysis completed in ${iterations} iterations`);
    return findings;
  }

  /**
   * Simple deduplication by file + line + rule.
   */
  private simpleDeduplicate(findings: Finding[]): Finding[] {
    // Group by file:line (within ±3 lines) and keep the highest severity / best description
    const groups = new Map<string, Finding[]>();
    for (const f of findings) {
      // Normalize file path
      const normFile = f.file.replace(/^\.\//, '');
      let matched = false;
      for (const [key, group] of groups) {
        const [gFile, gLineStr] = key.split(':');
        const gLine = parseInt(gLineStr, 10);
        if (gFile === normFile && Math.abs(f.line - gLine) <= 3) {
          group.push(f);
          matched = true;
          break;
        }
      }
      if (!matched) {
        groups.set(`${normFile}:${f.line}`, [f]);
      }
    }

    const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    const result: Finding[] = [];
    for (const group of groups.values()) {
      // Pick the finding with highest severity, then longest message (most detail)
      group.sort((a, b) => {
        const sevDiff = (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0);
        if (sevDiff !== 0) return sevDiff;
        return (b.message?.length ?? 0) - (a.message?.length ?? 0);
      });
      result.push(group[0]);
    }
    return result;
  }
}
