import { Rule, Severity } from '../../types.js';

export const redosRules: Rule[] = [
  {
    id: 'REDOS_NESTED_QUANTIFIER',
    category: 'Regex DoS',
    severity: Severity.Medium,
    message: 'Nested quantifiers in regex — may cause catastrophic backtracking',
    pattern: /(?:RegExp|\/)\s*.*(?:\+\+|\*\*|\+\*|\*\+|\{\d+,\}\+|\{\d+,\}\*)/,
    fileExtensions: ['.ts', '.js', '.py', '.rb', '.java', '.go'],
    cwe: 'CWE-1333',
    owasp: 'A06:2021',
    fix: { description: 'Simplify regex: avoid nested quantifiers like (a+)+. Use atomic groups or possessive quantifiers.' },
  },
  {
    id: 'REDOS_OVERLAPPING_ALT',
    category: 'Regex DoS',
    severity: Severity.Low,
    message: 'Regex with repeated group and alternation — potential ReDoS',
    pattern: /\(\?:[^)]*\|[^)]*\)\s*[+*]/,
    cwe: 'CWE-1333',
    owasp: 'A06:2021',
  },
  {
    id: 'REDOS_USER_INPUT',
    category: 'Regex DoS',
    severity: Severity.High,
    message: 'User input used as regex — attacker can cause ReDoS',
    pattern: /new\s+RegExp\s*\(\s*(?:req\.|params\.|body\.|query\.|input|user)/i,
    fileExtensions: ['.ts', '.js'],
    cwe: 'CWE-1333',
    owasp: 'A06:2021',
    fix: { description: 'Escape user input or use a safe regex library like re2' },
  },
];
