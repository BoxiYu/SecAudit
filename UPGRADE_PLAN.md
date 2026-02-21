# SecAudit Phase 2 — Major Upgrade Plan

## Goal
Make secaudit the best open-source AI-powered security scanner. Beat Semgrep CE + Bearer in key areas.

## Phase 2A: Core Engine (THIS SPRINT)

### 1. AST-Based Analysis (tree-sitter)
- Install `tree-sitter` and language grammars for JS/TS/Python/Go/Java/PHP/Ruby/Rust/C
- Replace pure-regex static scanner with AST-aware analysis
- Track variable assignments to detect taint propagation within a function
- Detect patterns like: `const x = req.body.foo; ... query(x)` (multi-line taint)
- Keep regex rules as fast pre-filter, use AST for confirmation to reduce false positives

### 2. CWE + OWASP Mapping
- Add `cwe` and `owasp` fields to Finding type
- Map every rule to CWE IDs (e.g., SQL_CONCAT → CWE-89, XSS_INNERHTML → CWE-79)
- Map to OWASP Top 10 2021 categories (A01-A10)
- Show in terminal output and SARIF

### 3. Expand Rules to 150+
New rule categories:
- **SSRF** (Server-Side Request Forgery) — CWE-918
- **Open Redirect** — CWE-601
- **XXE** (XML External Entity) — CWE-611
- **LDAP Injection** — CWE-90
- **Log Injection** — CWE-117
- **Prototype Pollution** — CWE-1321
- **Regex DoS** (ReDoS) — CWE-1333
- **Race Conditions** (TOCTOU) — CWE-367
- **Insecure File Upload** — CWE-434
- **Mass Assignment** — CWE-915
- **Hardcoded IPs/URLs** — CWE-798
- **Missing CSRF Protection** — CWE-352
- **Information Disclosure** (stack traces, debug mode) — CWE-209
- **Insecure Cookie** (missing SameSite, Secure, HttpOnly) — CWE-614
- Go-specific: goroutine leaks, unsafe pointer, missing error checks
- Rust-specific: unsafe blocks, unwrap in production
- PHP-specific: include with variable, $_GET/$_POST direct use
- Java-specific: Runtime.exec, XXE in DocumentBuilder, weak crypto
- Python-specific: os.system, subprocess shell=True, pickle, yaml.load

### 4. Fix Suggestions with Code Patches
- Add `fix` field to Finding: { description: string, replacement?: string }
- For common patterns, provide auto-fix code
- `secaudit scan --fix` to apply fixes automatically
- `secaudit scan --fix --dry-run` to preview fixes

### 5. .secaudit.yml Config File (full implementation)
```yaml
severity: medium
provider: openai
model: gpt-4o-mini
ignore:
  - "test/**"
  - "vendor/**"
rules:
  enable: [sql-injection, xss, secrets]
  disable: [DEP_INSECURE_RANDOM]
custom-rules:
  - id: MY_RULE
    pattern: "dangerousFunction("
    severity: high
    message: "Don't use dangerousFunction"
baseline: .secaudit-baseline.json
```

### 6. Baseline / Suppression System
- `secaudit baseline` — snapshot current findings as known issues
- Future scans only report NEW findings not in baseline
- Inline suppression: `// secaudit-disable-next-line SQL_CONCAT`
- File-level suppression: `// secaudit-disable-file`

### 7. Parallel Scanning
- Use worker_threads for static analysis (chunk files across workers)
- Concurrent LLM requests (configurable concurrency, default 5)
- Progress bar with `ora` or custom spinner showing files/sec

### 8. Dependency Vulnerability Scanning (SCA)
- Parse package.json / requirements.txt / go.mod / Cargo.toml / pom.xml
- Check against OSV (Open Source Vulnerabilities) API — free, no key needed
- Report known CVEs in dependencies
- `secaudit deps` subcommand

### 9. Rich Terminal Output
- Progress spinner during scan
- Grouped by severity with counts
- Clickable file:line links (iTerm2/VSCode terminal)
- `--quiet` mode for CI (just exit code)
- `--verbose` mode showing rule match details
- Color-coded severity with better layout

### 10. Watch Mode
- `secaudit watch` — watch for file changes, re-scan affected files
- Use `chokidar` or `fs.watch`
- Only re-run rules on changed files (incremental)

## Implementation Notes
- tree-sitter-wasms package for WASM grammars (no native compilation needed)
- OSV API: https://api.osv.dev/v1/query (POST, free, no auth)
- Keep backward compat: all existing CLI flags must still work
- Tests: add test-samples for each new language
- Every rule must have at least one test case in test-samples/
