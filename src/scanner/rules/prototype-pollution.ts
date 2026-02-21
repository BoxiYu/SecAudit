import { Rule, Severity } from '../../types.js';

export const prototypePollutionRules: Rule[] = [
  {
    id: 'PROTO_MERGE',
    category: 'Prototype Pollution',
    severity: Severity.High,
    message: 'Deep merge/extend without prototype check — may allow __proto__ pollution',
    pattern: /(?:deepMerge|deepExtend|merge|extend|assign)\s*\([^)]*(?:req\.|params\.|body\.)/i,
    fileExtensions: ['.ts', '.js'],
    cwe: 'CWE-1321',
    owasp: 'A03:2021',
    fix: { description: 'Use Object.create(null) as target, or filter __proto__/__constructor__ keys' },
  },
  {
    id: 'PROTO_BRACKET_ASSIGN',
    category: 'Prototype Pollution',
    severity: Severity.Medium,
    message: 'Dynamic property assignment with user input — may pollute prototype',
    pattern: /\w+\s*\[\s*(?:req\.|params\.|body\.|key|prop|name|field)\b[^\]]*\]\s*=/i,
    fileExtensions: ['.ts', '.js'],
    cwe: 'CWE-1321',
    owasp: 'A03:2021',
  },
  {
    id: 'PROTO_CONSTRUCTOR',
    category: 'Prototype Pollution',
    severity: Severity.High,
    message: 'Access to __proto__ or constructor.prototype — prototype pollution vector',
    pattern: /(?:__proto__|constructor\s*\[\s*["']prototype["']\s*\])/,
    fileExtensions: ['.ts', '.js'],
    cwe: 'CWE-1321',
    owasp: 'A03:2021',
  },
];
