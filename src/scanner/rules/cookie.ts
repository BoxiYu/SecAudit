import { Rule, Severity } from '../../types.js';

export const cookieRules: Rule[] = [
  {
    id: 'COOKIE_NO_HTTPONLY',
    category: 'Insecure Cookie',
    severity: Severity.Medium,
    message: 'Cookie without HttpOnly — accessible to JavaScript (XSS risk)',
    pattern: /(?:Set-Cookie|cookie)\s*[:=].*(?!.*[Hh]ttp[Oo]nly).*(?:session|token|auth|jwt)/i,
    cwe: 'CWE-1004',
    owasp: 'A05:2021',
    fix: { description: 'Add HttpOnly flag to prevent JavaScript access to sensitive cookies' },
  },
  {
    id: 'COOKIE_NO_SECURE',
    category: 'Insecure Cookie',
    severity: Severity.Medium,
    message: 'Cookie without Secure flag — may be sent over HTTP',
    pattern: /(?:secure)\s*[:=]\s*false/i,
    cwe: 'CWE-614',
    owasp: 'A05:2021',
    fix: { description: 'Set secure: true to ensure cookies are only sent over HTTPS' },
  },
  {
    id: 'COOKIE_DOCUMENT_COOKIE',
    category: 'Insecure Cookie',
    severity: Severity.Medium,
    message: 'document.cookie access — prefer HttpOnly server-side cookies',
    pattern: /document\.cookie\s*[=+]/,
    fileExtensions: ['.ts', '.js', '.jsx', '.tsx'],
    cwe: 'CWE-1004',
    owasp: 'A05:2021',
  },
];
