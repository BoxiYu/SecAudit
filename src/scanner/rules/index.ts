import { Rule } from '../../types.js';
import { sqlInjectionRules } from './sql-injection.js';
import { xssRules } from './xss.js';
import { authRules } from './auth.js';
import { secretRules } from './secrets.js';
import { dependencyRules } from './dependencies.js';
import { ssrfRules } from './ssrf.js';
import { cryptoRules } from './crypto.js';
import { injectionRules } from './injection.js';
import { prototypePollutionRules } from './prototype-pollution.js';
import { redirectRules } from './redirect.js';
import { xxeRules } from './xxe.js';
import { csrfRules } from './csrf.js';
import { infoDisclosureRules } from './info-disclosure.js';
import { cookieRules } from './cookie.js';
import { fileUploadRules } from './file-upload.js';
import { massAssignmentRules } from './mass-assignment.js';
import { redosRules } from './redos.js';
import { raceConditionRules } from './race-condition.js';
import { goRules } from './go-rules.js';
import { rustRules } from './rust-rules.js';
import { phpRules } from './php-rules.js';
import { javaRules } from './java-rules.js';
import { pythonRules } from './python-rules.js';

export const allRules: Rule[] = [
  ...sqlInjectionRules,
  ...xssRules,
  ...authRules,
  ...secretRules,
  ...dependencyRules,
  ...ssrfRules,
  ...cryptoRules,
  ...injectionRules,
  ...prototypePollutionRules,
  ...redirectRules,
  ...xxeRules,
  ...csrfRules,
  ...infoDisclosureRules,
  ...cookieRules,
  ...fileUploadRules,
  ...massAssignmentRules,
  ...redosRules,
  ...raceConditionRules,
  ...goRules,
  ...rustRules,
  ...phpRules,
  ...javaRules,
  ...pythonRules,
];

export {
  sqlInjectionRules, xssRules, authRules, secretRules, dependencyRules,
  ssrfRules, cryptoRules, injectionRules, prototypePollutionRules,
  redirectRules, xxeRules, csrfRules, infoDisclosureRules, cookieRules,
  fileUploadRules, massAssignmentRules, redosRules, raceConditionRules,
  goRules, rustRules, phpRules, javaRules, pythonRules,
};
