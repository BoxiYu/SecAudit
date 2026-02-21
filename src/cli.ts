#!/usr/bin/env node

import { resolve } from 'node:path';
import { writeFileSync } from 'node:fs';
import { Command } from 'commander';
import { StaticScanner } from './scanner/static.js';
import { LLMScanner } from './scanner/llm.js';
import { reportTerminal } from './reporter/terminal.js';
import { reportJSON } from './reporter/json.js';
import { reportSARIF } from './reporter/sarif.js';
import { login, checkAuth, getApiKey } from './auth/oauth.js';
import { Severity, SEVERITY_ORDER } from './types.js';
import { loadConfig, loadBaseline, isInBaseline } from './config.js';
import type { Finding, ScanResult } from './types.js';

const program = new Command();

program
  .name('secaudit')
  .description('AI-powered security review tool — static rules + LLM deep analysis')
  .version('0.2.0');

program
  .command('scan', { isDefault: true })
  .description('Scan a directory or file for security vulnerabilities')
  .argument('[path]', 'Path to scan', '.')
  .option('-p, --provider <provider>', 'LLM provider (openai, anthropic, google, etc.)')
  .option('-m, --model <model>', 'LLM model to use')
  .option('-f, --format <format>', 'Output format (terminal, json, sarif)')
  .option('-s, --severity <severity>', 'Minimum severity to report (critical, high, medium, low, info)')
  .option('--no-llm', 'Skip LLM analysis (static rules only)')
  .option('--no-static', 'Skip static analysis (LLM only)')
  .option('--diff <ref>', 'Scan only files changed since git ref')
  .option('--baseline', 'Filter out baseline findings')
  .option('-q, --quiet', 'Quiet mode — only exit code')
  .option('-v, --verbose', 'Show detailed rule information')
  .option('--deep', 'Deep LLM mode — cross-file analysis')
  .option('--git-history', 'Analyze git history for incomplete security fixes')
  .option('--verify', 'Verify C/C++ findings in Docker sandbox (requires Docker)')
  .action(async (targetPath: string, options) => {
    const absPath = resolve(targetPath);
    const config = loadConfig(absPath);
    const startTime = Date.now();
    const allFindings: Finding[] = [];
    let filesScanned = 0;
    let staticCount = 0;
    let llmCount = 0;

    // Merge config with CLI options (CLI takes precedence)
    const provider = options.provider ?? config.provider ?? 'openai-codex';
    const model = options.model ?? config.model ?? 'gpt-5.1-codex-mini';
    const format = options.format ?? config.format ?? 'terminal';
    const severity = options.severity ?? config.severity ?? 'low';

    // Get files to scan (diff mode or full directory)
    let diffFiles: string[] | undefined;
    if (options.diff) {
      const { execFileSync } = await import('node:child_process');
      try {
        const diffOutput = execFileSync('git', ['diff', '--name-only', options.diff], { cwd: absPath, encoding: 'utf-8' });
        diffFiles = diffOutput.trim().split('\n').filter(Boolean);
        if (diffFiles.length === 0) {
          if (!options.quiet) console.log('\n✅ No changed files to scan.\n');
          return;
        }
      } catch {
        console.error(`\n⚠️  Failed to get git diff for "${options.diff}". Make sure you're in a git repo.\n`);
        return;
      }
    }

    // Static scan
    if (options.static !== false) {
      const scanner = new StaticScanner();
      if (diffFiles) scanner.setFileFilter(diffFiles);

      // Apply config ignore patterns
      if (config.ignore?.length) {
        scanner.addIgnorePatterns(config.ignore);
      }

      const result = await scanner.scan(absPath);
      allFindings.push(...result.findings);
      filesScanned = Math.max(filesScanned, result.filesScanned);
      staticCount = result.findings.length;
    }

    // LLM scan
    if (options.llm !== false) {
      // For OAuth providers, set API key and fix model
      if (provider === 'openai-codex' || provider === 'chatgpt') {
        const key = await getApiKey(provider);
        if (key) {
          process.env.OPENAI_API_KEY = key;
        }
      }

      const resolvedKey = await getApiKey(provider);
      if (!checkAuth(provider) && !resolvedKey) {
        if (!options.quiet) {
          console.error(`\n⚠️  No API key found for ${provider}. Run: secaudit login\n`);
        }
      } else {
        const actualModel = (provider === 'openai-codex' && model === 'gpt-4o-mini') ? 'gpt-5.1-codex-mini' : model;
        const llmScanner = new LLMScanner(provider, actualModel, resolvedKey ?? undefined);
        if (diffFiles) llmScanner.setFileFilter(diffFiles);
        const result = await llmScanner.scan(absPath);
        allFindings.push(...result.findings);
        filesScanned = Math.max(filesScanned, result.filesScanned);
        llmCount = result.findings.length;
      }
    }

    // Git history analysis
    if (options.gitHistory) {
      const { GitHistoryScanner } = await import('./scanner/git-history.js');
      const resolvedKey2 = await getApiKey(provider);
      const actualModel2 = (provider === 'openai-codex' && model === 'gpt-4o-mini') ? 'gpt-5.1-codex-mini' : model;
      const gitScanner = new GitHistoryScanner(provider, actualModel2, resolvedKey2 ?? undefined);
      if (!options.quiet) console.log('\n🔍 Analyzing git history for incomplete security fixes...');
      const gitResult = await gitScanner.scan(absPath);
      allFindings.push(...gitResult.findings);
      if (!options.quiet) console.log(`   Found ${gitResult.findings.length} issues from ${gitResult.commitsAnalyzed} security commits`);
    }

    // Deep LLM analysis (cross-file)
    if (options.deep) {
      const { DeepLLMScanner } = await import('./scanner/deep-llm.js');
      const resolvedKey3 = await getApiKey(provider);
      const actualModel3 = (provider === 'openai-codex' && model === 'gpt-4o-mini') ? 'gpt-5.1-codex-mini' : model;
      const deepScanner = new DeepLLMScanner(provider, actualModel3, resolvedKey3 ?? undefined);
      if (!options.quiet) console.log('\n🧠 Deep cross-file analysis...');
      const deepResult = await deepScanner.scan(absPath);
      allFindings.push(...deepResult.findings);
      if (!options.quiet) console.log(`   Found ${deepResult.findings.length} cross-file issues from ${deepResult.modulesScanned} modules`);
    }

    // Filter by severity
    const minSeverity = severity as Severity;
    const minOrder = SEVERITY_ORDER[minSeverity] ?? SEVERITY_ORDER[Severity.Low];
    let filtered = allFindings.filter((f) => SEVERITY_ORDER[f.severity] <= minOrder);

    // Filter disabled rules from config
    if (config.rules?.disable?.length) {
      const disabled = new Set(config.rules.disable);
      filtered = filtered.filter((f) => !disabled.has(f.rule));
    }
    if (config.rules?.enable?.length) {
      const enabled = new Set(config.rules.enable);
      filtered = filtered.filter((f) => enabled.has(f.category.toLowerCase().replace(/\s+/g, '-')) || enabled.has(f.rule));
    }

    // Deduplicate (same file + line + rule)
    const seen = new Set<string>();
    const deduped = filtered.filter((f) => {
      const key = `${f.file}:${f.line}:${f.rule}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Filter baseline
    let final = deduped;
    if (options.baseline) {
      const baseline = loadBaseline(absPath, config.baseline);
      if (baseline.length > 0) {
        final = deduped.filter((f) => !isInBaseline(baseline, f.file, f.line, f.rule));
      }
    }

    const scanResult: ScanResult = {
      findings: final,
      filesScanned,
      duration: Date.now() - startTime,
      staticFindings: staticCount,
      llmFindings: llmCount,
    };

    // Report
    if (!options.quiet) {
      switch (format) {
        case 'json':
          reportJSON(scanResult);
          break;
        case 'sarif':
          reportSARIF(scanResult);
          break;
        default:
          reportTerminal(scanResult);
      }
    }

    // Exit with error code if critical/high findings
    if (final.some((f) => f.severity === Severity.Critical || f.severity === Severity.High)) {
      process.exit(1);
    }
  });

program
  .command('login')
  .description('Authenticate with an LLM provider')
  .option('-p, --provider <provider>', 'Provider to authenticate with', 'openai-codex')
  .action(async (options) => {
    await login(options.provider);
  });

program
  .command('init')
  .description('Create a .secaudit.yml configuration file')
  .action(async () => {
    const config = `# secaudit configuration
severity: low          # Minimum severity: critical, high, medium, low, info
provider: openai       # LLM provider
model: gpt-4o-mini     # LLM model
format: terminal       # Output: terminal, json, sarif

# Ignore patterns (glob)
ignore:
  - "test/**"
  - "**/*.test.ts"
  - "**/*.spec.ts"
  - "vendor/**"
  - "node_modules/**"

# Rule configuration
rules:
  # enable: [sql-injection, xss, secrets]   # Only these categories
  disable: []                                # Disable specific rule IDs

# Baseline file for suppressing known issues
# baseline: .secaudit-baseline.json

# LLM concurrency (parallel file analysis)
# concurrency: 5
`;
    writeFileSync('.secaudit.yml', config);
    console.log('✅ Created .secaudit.yml');
  });

program
  .command('baseline')
  .description('Save current findings as baseline (suppress known issues)')
  .argument('[path]', 'Path to scan', '.')
  .option('--no-llm', 'Skip LLM analysis')
  .action(async (targetPath: string, options) => {
    const absPath = resolve(targetPath);
    const scanner = new StaticScanner();
    const result = await scanner.scan(absPath);

    const entries = result.findings.map((f) => ({
      file: f.file,
      line: f.line,
      rule: f.rule,
    }));

    const outPath = resolve(absPath, '.secaudit-baseline.json');
    writeFileSync(outPath, JSON.stringify(entries, null, 2));
    console.log(`✅ Saved ${entries.length} findings to .secaudit-baseline.json`);
    console.log('   Future scans with --baseline will only report new issues.');
  });

program
  .command('deps')
  .description('Scan dependencies for known vulnerabilities (SCA via OSV)')
  .argument('[path]', 'Path to scan', '.')
  .option('-f, --format <format>', 'Output format (terminal, json, sarif)', 'terminal')
  .option('-s, --severity <severity>', 'Minimum severity', 'low')
  .action(async (targetPath: string, options) => {
    const absPath = resolve(targetPath);
    const { SCAScanner } = await import('./scanner/sca.js');
    const scanner = new SCAScanner();

    console.log('\n🔎 Scanning dependencies for known vulnerabilities...\n');
    const result = await scanner.scan(absPath);

    const minOrder = SEVERITY_ORDER[options.severity as Severity] ?? SEVERITY_ORDER[Severity.Low];
    const filtered = result.findings.filter((f) => SEVERITY_ORDER[f.severity] <= minOrder);

    const scanResult: ScanResult = {
      findings: filtered,
      filesScanned: 0,
      duration: 0,
      staticFindings: 0,
      llmFindings: 0,
      scaFindings: filtered.length,
      depsScanned: result.depsScanned,
    };

    switch (options.format) {
      case 'json': reportJSON(scanResult); break;
      case 'sarif': reportSARIF(scanResult); break;
      default: reportTerminal(scanResult); break;
    }

    if (filtered.some((f) => f.severity === Severity.Critical || f.severity === Severity.High)) {
      process.exit(1);
    }
  });

program
  .command('verify')
  .description('Verify C/C++ findings in Docker sandbox with AddressSanitizer')
  .argument('[path]', 'Path to scan', '.')
  .option('-p, --provider <provider>', 'LLM provider for PoC generation', 'openai')
  .option('-m, --model <model>', 'LLM model', 'gpt-4o-mini')
  .option('-n, --max <n>', 'Max findings to verify', '10')
  .action(async (targetPath: string, options) => {
    const absPath = resolve(targetPath);
    const { ensureSandboxImage, verifyFinding } = await import('./scanner/sandbox.js');
    const { readFileSync } = await import('node:fs');

    console.log('\n🐳 Checking Docker sandbox...');
    if (!ensureSandboxImage()) {
      console.error('❌ Docker not available. Install Docker or start Colima.');
      return;
    }
    console.log('✅ Sandbox ready\n');

    // First run static scan to find C/C++ issues
    const scanner = new StaticScanner();
    const result = await scanner.scan(absPath);
    const cFindings = result.findings.filter((f) =>
      f.file.match(/\.[ch](pp)?$/) &&
      (f.severity === Severity.Critical || f.severity === Severity.High)
    ).slice(0, parseInt(options.max));

    if (cFindings.length === 0) {
      console.log('No C/C++ critical/high findings to verify.');
      return;
    }

    console.log(`🔬 Verifying ${cFindings.length} findings in Docker sandbox...\n`);

    const apiKey = await getApiKey(options.provider);
    let verified = 0;
    let failed = 0;

    for (const finding of cFindings) {
      const fullPath = `${absPath}/${finding.file}`;
      let source: string;
      try { source = readFileSync(fullPath, 'utf-8'); } catch { continue; }

      process.stdout.write(`  ${finding.rule} @ ${finding.file}:${finding.line} ... `);
      const result = await verifyFinding(finding, source, options.provider, options.model, apiKey ?? undefined);

      if (result.verified) {
        console.log('✅ VERIFIED');
        verified++;
        if (result.asanReport) {
          console.log(`     ASan: ${result.asanReport.substring(0, 200)}`);
        }
      } else {
        console.log('❌ Not reproduced');
        failed++;
      }
    }

    console.log(`\n📊 Results: ${verified} verified, ${failed} not reproduced out of ${cFindings.length}`);
  });

program
  .command('rules')
  .description('List all available rules')
  .option('-c, --category <cat>', 'Filter by category')
  .action(async (options) => {
    const { allRules } = await import('./scanner/rules/index.js');
    const chalk = (await import('chalk')).default;

    let rules = allRules;
    if (options.category) {
      rules = rules.filter((r) => r.category.toLowerCase().includes(options.category.toLowerCase()));
    }

    console.log(chalk.bold(`\n📋 SecAudit Rules (${rules.length} total)\n`));

    const byCategory = new Map<string, typeof rules>();
    for (const r of rules) {
      const arr = byCategory.get(r.category) ?? [];
      arr.push(r);
      byCategory.set(r.category, arr);
    }

    for (const [cat, catRules] of byCategory) {
      console.log(chalk.bold.underline(`  ${cat} (${catRules.length})`));
      for (const r of catRules) {
        const sev = r.severity === 'critical' ? chalk.red('CRIT') :
          r.severity === 'high' ? chalk.red('HIGH') :
            r.severity === 'medium' ? chalk.yellow('MED ') :
              r.severity === 'low' ? chalk.blue('LOW ') : chalk.gray('INFO');
        const cwe = r.cwe ? chalk.cyan(r.cwe) : '';
        console.log(`    ${sev}  ${r.id}  ${cwe}`);
        console.log(chalk.gray(`          ${r.message}`));
      }
      console.log();
    }
  });

program.parse();
