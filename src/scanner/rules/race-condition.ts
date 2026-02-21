import { Rule, Severity } from '../../types.js';

export const raceConditionRules: Rule[] = [
  {
    id: 'RACE_TOCTOU_FS',
    category: 'Race Condition',
    severity: Severity.Medium,
    message: 'TOCTOU: checking file existence before access — use atomic operations',
    pattern: /(?:existsSync|access|stat)\s*\([^)]+\)[\s\S]{0,50}(?:readFile|writeFile|unlink|rename)/,
    cwe: 'CWE-367',
    owasp: 'A04:2021',
    fix: { description: 'Use atomic operations: try/catch the read/write directly instead of check-then-act' },
  },
  {
    id: 'RACE_BALANCE_CHECK',
    category: 'Race Condition',
    severity: Severity.High,
    message: 'Read-then-update pattern without locking — potential double-spend',
    pattern: /(?:balance|amount|quantity|stock|count|credits)\s*=.*await.*find.*\n.*(?:save|update)/i,
    cwe: 'CWE-362',
    owasp: 'A04:2021',
    fix: { description: 'Use database transactions with row-level locking or optimistic concurrency' },
  },
  {
    id: 'RACE_NO_MUTEX',
    category: 'Race Condition',
    severity: Severity.Medium,
    message: 'Shared mutable state without synchronization — use mutex/lock',
    pattern: /(?:global|shared|static)\s+(?:mut\s+)?(?:counter|balance|state|data)\b/i,
    fileExtensions: ['.rs', '.go', '.java'],
    cwe: 'CWE-362',
    owasp: 'A04:2021',
  },
];
