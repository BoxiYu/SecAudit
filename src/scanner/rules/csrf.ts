import { Rule, Severity } from '../../types.js';

export const csrfRules: Rule[] = [
  {
    id: 'CSRF_DISABLED',
    category: 'CSRF',
    severity: Severity.High,
    message: 'CSRF protection disabled — re-enable for state-changing requests',
    pattern: /(?:csrf|csrfProtection|_csrf)\s*[:=]\s*(?:false|disabled|off)/i,
    cwe: 'CWE-352',
    owasp: 'A01:2021',
  },
  {
    id: 'CSRF_EXEMPT',
    category: 'CSRF',
    severity: Severity.Medium,
    message: 'CSRF exemption — ensure this endpoint does not modify state',
    pattern: /(?:@csrf_exempt|csrf_exempt|@IgnoreCSRF|skipCSRF)/i,
    cwe: 'CWE-352',
    owasp: 'A01:2021',
  },
  {
    id: 'CSRF_SAMESITE_NONE',
    category: 'CSRF',
    severity: Severity.Medium,
    message: 'Cookie SameSite=None — vulnerable to cross-site requests',
    pattern: /[Ss]ame[Ss]ite\s*[:=]\s*["']?[Nn]one/i,
    cwe: 'CWE-1275',
    owasp: 'A01:2021',
    fix: { description: 'Set SameSite=Lax or SameSite=Strict' },
  },
];
