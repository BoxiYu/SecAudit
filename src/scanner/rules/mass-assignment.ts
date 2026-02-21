import { Rule, Severity } from '../../types.js';

export const massAssignmentRules: Rule[] = [
  {
    id: 'MASS_ASSIGN_SPREAD',
    category: 'Mass Assignment',
    severity: Severity.High,
    message: 'Spread operator with request body in DB operation — whitelist fields',
    pattern: /(?:create|update|insert|save|findOneAndUpdate)\s*\(\s*(?:\.\.\.\s*(?:req\.body|body|data)|req\.body)/i,
    fileExtensions: ['.ts', '.js'],
    cwe: 'CWE-915',
    owasp: 'A04:2021',
    fix: { description: 'Destructure only expected fields: const { name, email } = req.body' },
  },
  {
    id: 'MASS_ASSIGN_DJANGO',
    category: 'Mass Assignment',
    severity: Severity.High,
    message: 'Django model created from request data — use serializer with fields',
    pattern: /\.objects\.create\s*\(\s*\*\*(?:request\.(?:POST|data|GET))/i,
    fileExtensions: ['.py'],
    cwe: 'CWE-915',
    owasp: 'A04:2021',
  },
  {
    id: 'MASS_ASSIGN_RAILS',
    category: 'Mass Assignment',
    severity: Severity.High,
    message: 'Rails mass assignment — use strong parameters (permit)',
    pattern: /\.(?:new|create|update)\s*\(\s*params\b(?!.*permit)/i,
    fileExtensions: ['.rb'],
    cwe: 'CWE-915',
    owasp: 'A04:2021',
    fix: { description: 'Use strong parameters: params.require(:model).permit(:field1, :field2)' },
  },
];
