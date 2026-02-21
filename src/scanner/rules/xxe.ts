import { Rule, Severity } from '../../types.js';

export const xxeRules: Rule[] = [
  {
    id: 'XXE_PARSER',
    category: 'XML External Entity',
    severity: Severity.High,
    message: 'XML parser without disabling external entities — vulnerable to XXE',
    pattern: /(?:parseXML|xml2js|DOMParser|SAXParser|XMLReader|DocumentBuilder|etree\.parse|lxml\.etree)/i,
    cwe: 'CWE-611',
    owasp: 'A05:2021',
    fix: { description: 'Disable external entities: set FEATURE_EXTERNAL_GENERAL_ENTITIES to false' },
  },
  {
    id: 'XXE_DOCTYPE',
    category: 'XML External Entity',
    severity: Severity.High,
    message: 'DOCTYPE with ENTITY declaration — potential XXE attack vector',
    pattern: /<!DOCTYPE\s+.*?<!ENTITY/i,
    cwe: 'CWE-611',
    owasp: 'A05:2021',
  },
  {
    id: 'XXE_JAVA_FACTORY',
    category: 'XML External Entity',
    severity: Severity.High,
    message: 'Java XML factory without secure processing — configure XXE protections',
    pattern: /(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(/,
    fileExtensions: ['.java'],
    cwe: 'CWE-611',
    owasp: 'A05:2021',
    fix: { description: 'Set factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)' },
  },
  {
    id: 'XXE_XSLT',
    category: 'XML External Entity',
    severity: Severity.High,
    message: 'XSLT processing may allow XXE — disable external entities',
    pattern: /(?:TransformerFactory|XSLTProcessor|xslt\.transform)/i,
    cwe: 'CWE-611',
    owasp: 'A05:2021',
  },
];
