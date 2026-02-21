import { Rule, Severity } from '../../types.js';

export const sqlInjectionRules: Rule[] = [
  {
    id: 'SQL_CONCAT',
    category: 'SQL Injection',
    severity: Severity.Critical,
    message: 'String concatenation in SQL query — use parameterized queries instead',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*?\+\s*(?:req\.|params\.|query\.|body\.|input|user)/i,
    fileExtensions: ['.ts', '.js', '.py', '.rb', '.java', '.go', '.php'],
  },
  {
    id: 'SQL_TEMPLATE_LITERAL',
    category: 'SQL Injection',
    severity: Severity.Critical,
    message: 'Template literal in SQL query — use parameterized queries instead',
    pattern: /(?:query|execute|exec|raw|prepare)\s*\(\s*`[^`]*\$\{/i,
    fileExtensions: ['.ts', '.js'],
  },
  {
    id: 'SQL_FSTRING',
    category: 'SQL Injection',
    severity: Severity.Critical,
    message: 'f-string in SQL query — use parameterized queries instead',
    pattern: /(?:execute|cursor\.execute|\.query)\s*\(\s*f["'][^"']*\{/i,
    fileExtensions: ['.py'],
  },
  {
    id: 'SQL_FORMAT',
    category: 'SQL Injection',
    severity: Severity.High,
    message: 'String format in SQL query — use parameterized queries instead',
    pattern: /(?:execute|query)\s*\(\s*["'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?["']\s*[%\.]\s*format/i,
    fileExtensions: ['.py'],
  },
  {
    id: 'SQL_RAW_QUERY',
    category: 'SQL Injection',
    severity: Severity.Medium,
    message: 'Raw SQL query detected — ensure inputs are sanitized',
    pattern: /\.(?:rawQuery|raw|unsafe|unsafeRaw)\s*\(/i,
  },
];
