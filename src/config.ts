import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';

export interface SecAuditConfig {
  severity?: string;
  provider?: string;
  model?: string;
  format?: string;
  ignore?: string[];
  rules?: {
    enable?: string[];
    disable?: string[];
  };
  baseline?: string;
  concurrency?: number;
}

const CONFIG_FILES = ['.secaudit.yml', '.secaudit.yaml', '.secauditrc.yml'];

export function loadConfig(dir: string): SecAuditConfig {
  for (const name of CONFIG_FILES) {
    const p = join(dir, name);
    if (existsSync(p)) {
      try {
        const raw = readFileSync(p, 'utf-8');
        return parseYaml(raw) ?? {};
      } catch {
        return {};
      }
    }
  }
  return {};
}

export interface BaselineEntry {
  file: string;
  line: number;
  rule: string;
}

export function loadBaseline(dir: string, baselinePath?: string): BaselineEntry[] {
  const p = join(dir, baselinePath ?? '.secaudit-baseline.json');
  if (!existsSync(p)) return [];
  try {
    return JSON.parse(readFileSync(p, 'utf-8'));
  } catch {
    return [];
  }
}

export function isInBaseline(baseline: BaselineEntry[], file: string, line: number, rule: string): boolean {
  return baseline.some((b) => b.file === file && b.rule === rule && Math.abs(b.line - line) <= 3);
}
