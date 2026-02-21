---
name: secaudit
description: "Run AI-powered security reviews on codebases. Detects SQL injection, XSS, hardcoded secrets, auth flaws, command injection, and more using static rules + LLM deep analysis. Use when asked to review code security, audit a project, or scan for vulnerabilities."
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡️",
        "requires": { "bins": ["secaudit"] },
        "install":
          [
            {
              "id": "node",
              "kind": "node",
              "package": "secaudit",
              "bins": ["secaudit"],
              "label": "Install SecAudit CLI (npm)",
            },
          ],
      },
  }
---

# SecAudit - AI Security Review Tool

AI-powered security scanner combining static pattern matching with LLM deep analysis.

## Usage

```bash
# Scan a directory (static + LLM)
secaudit ./src

# Static rules only (fast, free, no API key needed)
secaudit ./src --no-llm

# With specific LLM provider
secaudit ./src --provider anthropic --model claude-sonnet-4-20250514

# JSON output
secaudit ./src --format json

# SARIF output (GitHub integration)
secaudit ./src --format sarif > results.sarif

# Filter by severity
secaudit ./src --severity high
```

## What It Detects

### Static Rules (instant, 30+ patterns)
- SQL injection (string concat, template literals, f-strings)
- XSS (innerHTML, document.write, dangerouslySetInnerHTML, v-html)
- Hardcoded secrets (AWS, GitHub, Stripe, OpenAI keys, private keys)
- Authentication flaws (weak JWT, CORS wildcard, no TLS verify)
- Code injection (eval, Function constructor, dynamic require)
- Command injection (exec/spawn with user input)
- Path traversal, insecure HTTP, weak crypto

### LLM Analysis (deep, contextual)
- Business logic flaws
- Authentication/authorization gaps
- Race conditions, IDOR
- Complex data flow vulnerabilities
- Context-aware detection

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --provider` | LLM provider | openai |
| `-m, --model` | LLM model | gpt-4o-mini |
| `-f, --format` | Output format (terminal/json/sarif) | terminal |
| `-s, --severity` | Minimum severity | low |
| `--no-llm` | Skip LLM analysis | false |
| `--no-static` | Skip static analysis | false |

## Integration Tips

- For quick scans, use `--no-llm` (runs in <1s)
- For thorough audits, use with a strong model like `gpt-4o` or `claude-sonnet-4-20250514`
- SARIF output integrates directly with GitHub Code Scanning
- Exit code 1 if critical/high findings detected (useful for CI)
