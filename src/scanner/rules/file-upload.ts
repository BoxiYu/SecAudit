import { Rule, Severity } from '../../types.js';

export const fileUploadRules: Rule[] = [
  {
    id: 'UPLOAD_NO_VALIDATION',
    category: 'Insecure File Upload',
    severity: Severity.High,
    message: 'File upload without type validation — check MIME type and extension',
    pattern: /(?:multer|upload|formidable|busboy)\s*\(/i,
    fileExtensions: ['.ts', '.js'],
    cwe: 'CWE-434',
    owasp: 'A04:2021',
    fix: { description: 'Validate file extension, MIME type, and file size. Use allowlist of accepted types.' },
  },
  {
    id: 'UPLOAD_MOVE',
    category: 'Insecure File Upload',
    severity: Severity.Medium,
    message: 'File move without sanitizing filename — path traversal risk',
    pattern: /(?:move_uploaded_file|\.mv\(|saveAs|writeTo)\s*\([^)]*(?:req\.|body\.|file\.(?:name|originalname))/i,
    cwe: 'CWE-434',
    owasp: 'A04:2021',
    fix: { description: 'Sanitize filename: strip path separators, use UUID, validate extension' },
  },
  {
    id: 'UPLOAD_EXEC_EXT',
    category: 'Insecure File Upload',
    severity: Severity.Critical,
    message: 'Executable file extension allowed in upload — restrict to safe types',
    pattern: /(?:\.php|\.jsp|\.asp|\.exe|\.sh|\.bat|\.cmd|\.py|\.rb|\.pl)\s*(?:\]|["'])/i,
    cwe: 'CWE-434',
    owasp: 'A04:2021',
  },
];
