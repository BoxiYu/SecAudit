import { Rule, Severity } from '../../types.js';

export const redirectRules: Rule[] = [
  {
    id: 'REDIRECT_OPEN',
    category: 'Open Redirect',
    severity: Severity.Medium,
    message: 'Redirect with user-controlled URL — validate against allowlist',
    pattern: /(?:redirect|res\.redirect|Response\.Redirect|header\s*\(\s*["']Location)\s*\(\s*(?:req\.|params\.|query\.|body\.|input|user|url)/i,
    cwe: 'CWE-601',
    owasp: 'A01:2021',
    fix: { description: 'Validate redirect URLs against a whitelist of allowed domains' },
  },
  {
    id: 'REDIRECT_META',
    category: 'Open Redirect',
    severity: Severity.Medium,
    message: 'Meta refresh with dynamic URL — potential open redirect',
    pattern: /meta.*?http-equiv\s*=\s*["']refresh["'].*?url\s*=\s*(?:<%|{{|\$)/i,
    fileExtensions: ['.html', '.erb', '.ejs', '.php', '.jsp'],
    cwe: 'CWE-601',
    owasp: 'A01:2021',
  },
  {
    id: 'REDIRECT_PYTHON',
    category: 'Open Redirect',
    severity: Severity.Medium,
    message: 'Django/Flask redirect with user input — validate URL',
    pattern: /(?:redirect|HttpResponseRedirect)\s*\(\s*(?:request\.|data\[)/i,
    fileExtensions: ['.py'],
    cwe: 'CWE-601',
    owasp: 'A01:2021',
  },
];
