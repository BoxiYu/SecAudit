import { Rule, Severity } from '../../types.js';

export const authRules: Rule[] = [
  {
    id: 'AUTH_HARDCODED_PASSWORD',
    category: 'Authentication',
    severity: Severity.Critical,
    message: 'Hardcoded password detected',
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{3,}["']/i,
  },
  {
    id: 'AUTH_JWT_NONE',
    category: 'Authentication',
    severity: Severity.Critical,
    message: 'JWT with "none" algorithm — tokens can be forged',
    pattern: /algorithm[s"':\s]*["']none["']/i,
  },
  {
    id: 'AUTH_JWT_WEAK_SECRET',
    category: 'Authentication',
    severity: Severity.High,
    message: 'JWT signed with a short/weak secret',
    pattern: /(?:jwt|jsonwebtoken)\.sign\s*\([^,]+,\s*["'][^"']{1,15}["']/i,
  },
  {
    id: 'AUTH_NO_VERIFY',
    category: 'Authentication',
    severity: Severity.High,
    message: 'SSL/TLS verification disabled — vulnerable to MITM',
    pattern: /(?:rejectUnauthorized|verify_ssl|VERIFY_SSL|verify_certs)\s*[:=]\s*(?:false|False|0)/i,
  },
  {
    id: 'AUTH_CORS_WILDCARD',
    category: 'Authentication',
    severity: Severity.Medium,
    message: 'CORS allows all origins — restrict to specific domains',
    pattern: /(?:Access-Control-Allow-Origin|cors\s*\()\s*["'*]/i,
  },
  {
    id: 'AUTH_BCRYPT_LOW_ROUNDS',
    category: 'Authentication',
    severity: Severity.Medium,
    message: 'bcrypt with low salt rounds — use at least 10',
    pattern: /(?:genSalt|bcrypt\.hash)\s*\(\s*(?:[1-9])\s*[),]/,
  },
  {
    id: 'AUTH_SESSION_NO_SECURE',
    category: 'Authentication',
    severity: Severity.Medium,
    message: 'Cookie without secure/httpOnly flag',
    pattern: /(?:secure|httpOnly)\s*:\s*false/i,
  },
];
