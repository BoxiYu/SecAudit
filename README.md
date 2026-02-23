# SecAudit 🛡️

AI-powered security scanner that finds vulnerabilities static tools can't — business logic flaws, auth bypasses, cross-file attack chains, and more.

## Why SecAudit?

Traditional static analysis tools (Semgrep, Bearer) match patterns. SecAudit **understands your code** using LLMs to find vulnerabilities that require semantic reasoning:

| Vulnerability Type | Semgrep CE | SecAudit |
|---|:-:|:-:|
| SQL Injection (basic) | ✅ | ✅ |
| IDOR (missing ownership checks) | ❌ | ✅ |
| Auth bypass (conditional logic flaws) | ❌ | ✅ |
| Cross-module attack chains | ❌ | ✅ |
| Race conditions (TOCTOU) | ❌ | ✅ |
| Business logic flaws | ❌ | ✅ |
| JWT algorithm confusion | ❌ | ✅ |
| CAPTCHA/verification bypass | ❌ | ✅ |

## Verified Results

We ran both tools on the same codebases and **verified findings with real HTTP exploits** against live applications:

| Test | Semgrep CE | SecAudit | Verified |
|---|:-:|:-:|:-:|
| jsonwebtoken (CVE-2022-23529) | 0 findings | 11 findings | ✅ Forged unsigned JWT accepted |
| vulnerable-express (SQLi) | 0 SQL findings | SQLi + IDOR + hardcoded creds | ✅ UNION injection confirmed |
| Juice Shop (62 route files) | 15 findings | 114 findings | ✅ 5 exploits demonstrated |

### Live exploit examples (Juice Shop):

```bash
# SQL Injection → leaked 20+ user password hashes
curl "/rest/products/search?q=test'))UNION+SELECT+id,email,password,'','','','','',''FROM+Users--"

# Auth bypass → changed admin password without knowing old one
curl -X PUT "/rest/user/change-password?new=hacked&repeat=hacked" -H "Authorization: Bearer $TOKEN"

# IDOR → accessed other users' baskets
curl "/rest/basket/1" -H "Authorization: Bearer $JIM_TOKEN"  # Jim sees admin's basket

# CAPTCHA bypass → answer leaked in API response
curl "/rest/captcha"  # Returns {"answer":"60"} 🤦
```

## How It Works

SecAudit has four analysis modes, from fast to deep:

```
┌─────────────────────────────────────────────────────┐
│  Static Rules (172 rules, instant, free)            │
│  └─ Regex patterns for common vulns                 │
├─────────────────────────────────────────────────────┤
│  LLM Analysis (per-file, ~$0.001/file)              │
│  └─ AI reads each file, finds semantic issues       │
├─────────────────────────────────────────────────────┤
│  Deep RLM (recursive cross-file analysis)           │
│  └─ 4-phase: recon → focused → cross-module → dedup│
├─────────────────────────────────────────────────────┤
│  REPL Mode (LLM writes & executes analysis code)    │
│  └─ AI runs Python/ripgrep/tree-sitter in Docker    │
└─────────────────────────────────────────────────────┘
```

## Quick Start

```bash
npm install -g secaudit

# Login with ChatGPT (free, uses your subscription)
secaudit login

# Basic scan (static + LLM)
secaudit scan ./my-project

# Deep cross-file analysis
secaudit scan ./my-project --deep

# Full power: LLM executes code in Docker sandbox
secaudit scan ./my-project --deep --repl

# Static only (instant, no API calls)
secaudit scan ./my-project --no-llm

# Dependency vulnerabilities (SCA via OSV)
secaudit deps ./my-project
```

## Installation

```bash
# Requires Node.js 18+
npm install -g secaudit

# For REPL mode, also need Docker (Colima works)
brew install colima docker
colima start
```

## CLI Reference

```
secaudit scan <path>          Scan for vulnerabilities
  --no-llm                    Static rules only (no API calls)
  --deep                      Enable cross-file RLM analysis
  --repl                      Enable Docker REPL sandbox (requires Docker)
  --max-depth <n>             RLM recursion depth (default: 2)
  --max-iterations <n>        Max LLM calls (default: 30)
  --severity <level>          Minimum severity: critical|high|medium|low
  --format <fmt>              Output: terminal|json|sarif
  --baseline                  Compare against baseline
  -q, --quiet                 Suppress output
  -v, --verbose               Verbose output

secaudit deps <path>          SCA dependency scan (OSV API)
secaudit rules                List all static rules
secaudit baseline <path>      Generate baseline file
secaudit login                Authenticate with ChatGPT
secaudit verify <path>        Verify C/C++ findings with Docker + ASan
```

## Analysis Modes

### Static Rules (172 rules)

Instant regex-based scanning across 8+ languages:

- **JavaScript/TypeScript** — SQLi, XSS, eval, prototype pollution, SSRF, open redirect
- **Python** — Command injection, deserialization, path traversal
- **Go** — SQL injection, weak crypto, race conditions
- **Java** — XXE, LDAP injection, insecure deserialization
- **PHP** — SQLi, file inclusion, command execution
- **Rust** — Unsafe blocks, unwrap on user input
- **C/C++** — Buffer overflow, format string, use-after-free, TOCTOU

Every rule includes CWE ID and OWASP Top 10 2021 mapping.

### LLM Analysis

AI reviews each file for issues regex can't catch:
- Business logic flaws
- Missing input validation
- Insecure API design
- Authentication/authorization gaps

Default model: `gpt-5.3-codex` via ChatGPT subscription (free).

### Deep RLM (Recursive Language Model)

Inspired by [RLM](https://github.com/alexzhang13/rlm), the deep mode performs multi-phase recursive analysis:

1. **Reconnaissance** — LLM maps project structure, identifies security-critical modules
2. **Focused Analysis** — Batched deep-dive into each critical module with cross-file context
3. **Cross-Module** — Finds attack chains spanning multiple files (e.g., SQLi → auth bypass → account takeover)
4. **Aggregation** — LLM-assisted deduplication and severity ranking

### REPL Mode

The LLM gets a Docker sandbox with analysis tools and **writes code to audit your codebase**:

```python
# The LLM actually runs code like this in Docker:
import subprocess
result = subprocess.run(["rg", "-n", "req.body.UserId", "/code"], capture_output=True, text=True)
# Finds that UserId comes from user input → traces to DB queries → confirms IDOR
```

Available in sandbox: Python 3.12, ripgrep, tree-sitter, networkx, jedi.

## Configuration

Create `.secaudit.yml` in your project root:

```yaml
severity: medium          # Minimum severity to report
format: terminal          # Output format

rules:
  disable:                # Rules to skip
    - AUTH_HARDCODED_PASSWORD
  enable: []              # Only run these rules

ignore:                   # Paths to exclude
  - "test/**"
  - "vendor/**"

llm:
  provider: openai-codex  # LLM provider
  model: gpt-5.3-codex    # Model
  concurrency: 5          # Parallel file analysis
```

## Inline Suppression

```javascript
// secaudit-disable-next-line SQL_TEMPLATE_LITERAL
const query = `SELECT * FROM users WHERE id = ${id}`;

// secaudit-disable-file
// (disables all rules for this file)
```

## Output Formats

### Terminal (default)
```
  login.ts
     CRIT   User-controlled input directly concatenated into SQL query
           Line 34 · SQL Injection · SQL_TEMPLATE_LITERAL · CWE-89 · A03:2021
```

### JSON
```bash
secaudit scan . --format json
```

### SARIF (for GitHub Code Scanning)
```bash
secaudit scan . --format sarif > results.sarif
```

## GitHub Action

```yaml
- uses: BoxiYu/SecAudit@main
  with:
    path: ./src
    severity: high
    format: sarif
```

## SCA (Software Composition Analysis)

Scans dependencies for known vulnerabilities via the [OSV](https://osv.dev) API:

```bash
secaudit deps .
```

Supports: package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, Pipfile.lock, go.sum, Cargo.lock, Gemfile.lock, composer.lock, pom.xml.

## How It Compares

| Feature | SecAudit | Semgrep CE | Bearer | CodeQL |
|---|:-:|:-:|:-:|:-:|
| Static rules | 172 | 20,000+ | 1,000+ | 2,000+ |
| Business logic detection | ✅ | ❌ | ❌ | ❌ |
| Cross-file analysis | ✅ | ❌ | Partial | ✅ |
| IDOR / auth gap detection | ✅ | ❌ | ❌ | ❌ |
| Race condition detection | ✅ | ❌ | ❌ | ❌ |
| Attack chain discovery | ✅ | ❌ | ❌ | ❌ |
| LLM-powered analysis | ✅ | Paid only | ❌ | ❌ |
| Code execution sandbox | ✅ | ❌ | ❌ | ❌ |
| SCA | ✅ (OSV) | Paid | ❌ | ❌ |
| Speed | Minutes | Seconds | Seconds | Minutes |
| Cost | Free* | Free | Free | Free |
| Languages | 8+ | 30+ | 12+ | 10+ |

\* Uses your ChatGPT subscription for LLM features. Static rules are always free.

## Architecture

```
src/
├── cli.ts                 # CLI entry point (commander)
├── types.ts               # Finding, Severity, ScanResult types
├── config.ts              # .secaudit.yml config loader
├── providers/
│   └── pi-ai.ts           # LLM provider abstraction (@mariozechner/pi-ai)
├── scanner/
│   ├── static.ts          # Static rule engine
│   ├── llm.ts             # Per-file LLM analysis
│   ├── deep-llm.ts        # 4-phase RLM deep analysis
│   ├── rlm-engine.ts      # Recursive LLM engine core
│   ├── rlm-repl.ts        # Docker REPL container management
│   ├── rlm-docker.ts      # Docker image builder
│   ├── sca.ts             # OSV dependency scanner
│   ├── git-history.ts     # Git commit analysis
│   ├── sandbox.ts         # C/C++ verification sandbox
│   └── rules/             # 172 static rules (23 categories)
├── reporters/
│   ├── terminal.ts        # Terminal output with colors
│   ├── json.ts            # JSON reporter
│   └── sarif.ts           # SARIF reporter
└── index.ts               # Public API exports
```

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome. This project is in active development.

## Credits

- LLM provider abstraction: [@mariozechner/pi-ai](https://github.com/mariozechner/pi-ai)
- Recursive analysis inspired by: [RLM](https://github.com/alexzhang13/rlm)
- SCA data: [OSV.dev](https://osv.dev)
- Benchmark target: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
