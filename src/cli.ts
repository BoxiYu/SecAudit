#!/usr/bin/env node

import { resolve } from 'node:path';
import { Command } from 'commander';
import { StaticScanner } from './scanner/static.js';
import { LLMScanner } from './scanner/llm.js';
import { reportTerminal } from './reporter/terminal.js';
import { reportJSON } from './reporter/json.js';
import { reportSARIF } from './reporter/sarif.js';
import { login, checkAuth, getApiKey } from './auth/oauth.js';
import { Severity, SEVERITY_ORDER } from './types.js';
import type { Finding, ScanResult } from './types.js';

const program = new Command();

program
  .name('secaudit')
  .description('AI-powered security review tool')
  .version('0.1.0');

program
  .command('scan', { isDefault: true })
  .description('Scan a directory or file for security vulnerabilities')
  .argument('[path]', 'Path to scan', '.')
  .option('-p, --provider <provider>', 'LLM provider (openai, anthropic, google, etc.)', 'openai')
  .option('-m, --model <model>', 'LLM model to use', 'gpt-4o-mini')
  .option('-f, --format <format>', 'Output format (terminal, json, sarif)', 'terminal')
  .option('-s, --severity <severity>', 'Minimum severity to report (critical, high, medium, low, info)', 'low')
  .option('--no-llm', 'Skip LLM analysis (static rules only)')
  .option('--no-static', 'Skip static analysis (LLM only)')
  .option('--diff <ref>', 'Scan only files changed since git ref')
  .action(async (targetPath: string, options) => {
    const absPath = resolve(targetPath);
    const startTime = Date.now();
    const allFindings: Finding[] = [];
    let filesScanned = 0;
    let staticCount = 0;
    let llmCount = 0;

    // Static scan
    if (options.static !== false) {
      const scanner = new StaticScanner();
      const result = await scanner.scan(absPath);
      allFindings.push(...result.findings);
      filesScanned = Math.max(filesScanned, result.filesScanned);
      staticCount = result.findings.length;
    }

    // LLM scan
    if (options.llm !== false) {
      // For OAuth providers, set API key from stored credentials
      if (options.provider === 'openai-codex' || options.provider === 'chatgpt') {
        const key = await getApiKey(options.provider);
        if (key) {
          process.env.OPENAI_API_KEY = key;
        }
      }

      if (!checkAuth(options.provider)) {
        console.error(`\n⚠️  No API key found for ${options.provider}. Run: secaudit login\n`);
      } else {
        const llmScanner = new LLMScanner(options.provider, options.model);
        const result = await llmScanner.scan(absPath);
        allFindings.push(...result.findings);
        filesScanned = Math.max(filesScanned, result.filesScanned);
        llmCount = result.findings.length;
      }
    }

    // Filter by severity
    const minSeverity = options.severity as Severity;
    const minOrder = SEVERITY_ORDER[minSeverity] ?? SEVERITY_ORDER[Severity.Low];
    const filtered = allFindings.filter((f) => SEVERITY_ORDER[f.severity] <= minOrder);

    // Deduplicate (same file + line + rule)
    const seen = new Set<string>();
    const deduped = filtered.filter((f) => {
      const key = `${f.file}:${f.line}:${f.rule}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    const scanResult: ScanResult = {
      findings: deduped,
      filesScanned,
      duration: Date.now() - startTime,
      staticFindings: staticCount,
      llmFindings: llmCount,
    };

    // Report
    switch (options.format) {
      case 'json':
        reportJSON(scanResult);
        break;
      case 'sarif':
        reportSARIF(scanResult);
        break;
      default:
        reportTerminal(scanResult);
    }

    // Exit with error code if critical/high findings
    if (deduped.some((f) => f.severity === Severity.Critical || f.severity === Severity.High)) {
      process.exit(1);
    }
  });

program
  .command('login')
  .description('Authenticate with an LLM provider')
  .option('-p, --provider <provider>', 'Provider to authenticate with', 'openai')
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
skip_llm: false        # Skip LLM analysis
ignore:
  - "test/**"
  - "**/*.test.ts"
  - "**/*.spec.ts"
`;
    const fs = await import('node:fs');
    fs.writeFileSync('.secaudit.yml', config);
    console.log('Created .secaudit.yml');
  });

program.parse();
