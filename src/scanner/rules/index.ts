import { Rule } from '../../types.js';
import { sqlInjectionRules } from './sql-injection.js';
import { xssRules } from './xss.js';
import { authRules } from './auth.js';
import { secretRules } from './secrets.js';
import { dependencyRules } from './dependencies.js';

export const allRules: Rule[] = [
  ...sqlInjectionRules,
  ...xssRules,
  ...authRules,
  ...secretRules,
  ...dependencyRules,
];

export { sqlInjectionRules, xssRules, authRules, secretRules, dependencyRules };
