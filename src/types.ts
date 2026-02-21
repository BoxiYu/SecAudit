export enum Severity {
  Critical = 'critical',
  High = 'high',
  Medium = 'medium',
  Low = 'low',
  Info = 'info',
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  [Severity.Critical]: 0,
  [Severity.High]: 1,
  [Severity.Medium]: 2,
  [Severity.Low]: 3,
  [Severity.Info]: 4,
};

export interface FixSuggestion {
  description: string;
  replacement?: string;
}

export interface Finding {
  file: string;
  line: number;
  column: number;
  severity: Severity;
  category: string;
  message: string;
  rule: string;
  snippet: string;
  cwe?: string;
  owasp?: string;
  fix?: FixSuggestion;
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  duration: number;
  staticFindings: number;
  llmFindings: number;
  scaFindings?: number;
  depsScanned?: number;
}

export interface Rule {
  id: string;
  category: string;
  severity: Severity;
  message: string;
  pattern: RegExp;
  fileExtensions?: string[];
  /** If true, finding this pattern means it's safe (negates match) */
  negate?: boolean;
  cwe?: string;
  owasp?: string;
  fix?: FixSuggestion;
}

export interface ScanOptions {
  path: string;
  diff?: string;
  provider?: string;
  model?: string;
  format?: 'terminal' | 'json' | 'sarif';
  severity?: Severity;
  skipLlm?: boolean;
  skipStatic?: boolean;
}
