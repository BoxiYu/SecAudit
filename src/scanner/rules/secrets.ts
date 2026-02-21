import { Rule, Severity } from '../../types.js';

export const secretRules: Rule[] = [
  {
    id: 'SECRET_AWS_KEY',
    category: 'Secrets',
    severity: Severity.Critical,
    message: 'AWS Access Key ID detected',
    pattern: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/,
  },
  {
    id: 'SECRET_AWS_SECRET',
    category: 'Secrets',
    severity: Severity.Critical,
    message: 'Possible AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/i,
  },
  {
    id: 'SECRET_GITHUB_TOKEN',
    category: 'Secrets',
    severity: Severity.Critical,
    message: 'GitHub token detected',
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/,
  },
  {
    id: 'SECRET_STRIPE_KEY',
    category: 'Secrets',
    severity: Severity.Critical,
    message: 'Stripe API key detected',
    pattern: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}/,
  },
  {
    id: 'SECRET_OPENAI_KEY',
    category: 'Secrets',
    severity: Severity.Critical,
    message: 'OpenAI API key detected',
    pattern: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/,
  },
  {
    id: 'SECRET_PRIVATE_KEY',
    category: 'Secrets',
    severity: Severity.Critical,
    message: 'Private key detected',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    id: 'SECRET_GENERIC_TOKEN',
    category: 'Secrets',
    severity: Severity.High,
    message: 'Possible hardcoded secret/token',
    pattern: /(?:api_key|apikey|api_secret|secret_key|access_token|auth_token)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']/i,
  },
  {
    id: 'SECRET_SLACK_WEBHOOK',
    category: 'Secrets',
    severity: Severity.High,
    message: 'Slack webhook URL detected',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
  },
  {
    id: 'SECRET_GCP_KEY',
    category: 'Secrets',
    severity: Severity.Critical,
    message: 'Google Cloud API key detected',
    pattern: /AIza[0-9A-Za-z_-]{35}/,
  },
];
