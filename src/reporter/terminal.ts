import chalk from 'chalk';
import { Finding, Severity, ScanResult, SEVERITY_ORDER } from '../types.js';

const SEVERITY_ICON: Record<Severity, string> = {
  [Severity.Critical]: chalk.bgRed.white(' CRIT '),
  [Severity.High]: chalk.red('  HIGH'),
  [Severity.Medium]: chalk.yellow('  MED '),
  [Severity.Low]: chalk.blue('  LOW '),
  [Severity.Info]: chalk.gray(' INFO '),
};

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  [Severity.Critical]: chalk.red,
  [Severity.High]: chalk.red,
  [Severity.Medium]: chalk.yellow,
  [Severity.Low]: chalk.blue,
  [Severity.Info]: chalk.gray,
};

export function reportTerminal(result: ScanResult): void {
  const { findings, filesScanned, duration } = result;

  console.log();
  console.log(chalk.bold('🔍 SecAudit Security Review'));
  console.log(chalk.gray('─'.repeat(60)));
  console.log();

  if (findings.length === 0) {
    console.log(chalk.green('  ✅ No security issues found!'));
    console.log();
    printSummary(result);
    return;
  }

  // Group by file
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = byFile.get(f.file) ?? [];
    arr.push(f);
    byFile.set(f.file, arr);
  }

  // Sort findings within each file by severity
  for (const [file, fileFindings] of byFile) {
    fileFindings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

    console.log(chalk.bold.underline(`  ${file}`));
    console.log();

    for (const f of fileFindings) {
      const icon = SEVERITY_ICON[f.severity];
      const color = SEVERITY_COLOR[f.severity];
      console.log(`    ${icon}  ${color(f.message)}`);

      // Meta line: line, category, rule, CWE, OWASP
      const meta = [`Line ${f.line}`, f.category, f.rule];
      if (f.cwe) meta.push(chalk.cyan(f.cwe));
      if (f.owasp) meta.push(chalk.magenta(f.owasp));
      console.log(chalk.gray(`           ${meta.join(' · ')}`));

      if (f.snippet) {
        console.log(chalk.gray(`           ${f.snippet}`));
      }

      // Fix suggestion
      if (f.fix) {
        console.log(chalk.green(`           💡 Fix: ${f.fix.description}`));
      }

      console.log();
    }
  }

  printSummary(result);
}

function printSummary(result: ScanResult): void {
  const { findings, filesScanned, duration, staticFindings, llmFindings } = result;

  const counts: Record<Severity, number> = {
    [Severity.Critical]: 0,
    [Severity.High]: 0,
    [Severity.Medium]: 0,
    [Severity.Low]: 0,
    [Severity.Info]: 0,
  };

  for (const f of findings) {
    counts[f.severity]++;
  }

  // Collect unique CWEs and OWASP categories
  const cwes = new Set<string>();
  const owasps = new Set<string>();
  for (const f of findings) {
    if (f.cwe) cwes.add(f.cwe);
    if (f.owasp) owasps.add(f.owasp);
  }

  console.log(chalk.gray('─'.repeat(60)));
  console.log(chalk.bold('  Summary'));
  console.log();
  console.log(`    Files scanned:  ${filesScanned}`);
  console.log(`    Issues found:   ${findings.length}`);

  if (staticFindings > 0) console.log(`    Static rules:   ${staticFindings}`);
  if (llmFindings > 0) console.log(`    LLM analysis:   ${llmFindings}`);

  console.log(`    Duration:       ${(duration / 1000).toFixed(1)}s`);

  if (cwes.size > 0) {
    console.log(`    CWE coverage:   ${cwes.size} unique weaknesses`);
  }
  if (owasps.size > 0) {
    console.log(`    OWASP Top 10:   ${[...owasps].sort().join(', ')}`);
  }

  console.log();

  if (counts[Severity.Critical] > 0) console.log(chalk.red(`    🔴 Critical: ${counts[Severity.Critical]}`));
  if (counts[Severity.High] > 0) console.log(chalk.red(`    🟠 High:     ${counts[Severity.High]}`));
  if (counts[Severity.Medium] > 0) console.log(chalk.yellow(`    🟡 Medium:   ${counts[Severity.Medium]}`));
  if (counts[Severity.Low] > 0) console.log(chalk.blue(`    🔵 Low:      ${counts[Severity.Low]}`));
  if (counts[Severity.Info] > 0) console.log(chalk.gray(`    ⚪ Info:     ${counts[Severity.Info]}`));
  console.log();
}
