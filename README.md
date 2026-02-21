# 🛡️ SecAudit

AI-powered security review tool. Combines 30+ static rules with LLM deep analysis to catch vulnerabilities in your code.

## Install

```bash
npm install -g secaudit
```

## Quick Start

```bash
# Scan a directory (static + LLM)
secaudit ./src

# Static rules only (fast, free)
secaudit ./src --no-llm

# Use a specific LLM
secaudit ./src --provider anthropic --model claude-sonnet-4-20250514

# JSON / SARIF output
secaudit ./src --format json
secaudit ./src --format sarif > results.sarif
```

## What It Detects

### Static Rules (instant, 30+ patterns)
- **SQL Injection** — string concatenation, template literals, f-strings in queries
- **XSS** — innerHTML, document.write, dangerouslySetInnerHTML, v-html
- **Hardcoded Secrets** — AWS, GitHub, Stripe, OpenAI keys, private keys
- **Authentication** — weak JWT, CORS wildcard, disabled TLS verification
- **Code Injection** — eval(), Function constructor, dynamic require/import
- **Command Injection** — exec/spawn with user input
- **Path Traversal** — file operations with user input
- **Insecure Transport** — HTTP URLs in code
- **Weak Cryptography** — Math.random() for security

### LLM Analysis (deep, contextual)
- Business logic flaws
- Auth/authz gaps
- Race conditions & IDOR
- Complex data flow vulnerabilities

## GitHub Action

```yaml
- uses: your-org/secaudit@v1
  with:
    path: './src'
    provider: 'openai'
    model: 'gpt-4o-mini'
    api-key: ${{ secrets.OPENAI_API_KEY }}
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --provider` | LLM provider | openai |
| `-m, --model` | LLM model | gpt-4o-mini |
| `-f, --format` | Output (terminal/json/sarif) | terminal |
| `-s, --severity` | Min severity | low |
| `--no-llm` | Static rules only | false |
| `--no-static` | LLM only | false |

## As an OpenClaw Skill

Copy `skill/SKILL.md` to your OpenClaw skills directory. Then use `/security-review` in chat.

## Built With

- [pi-ai](https://github.com/badlogic/pi-mono) — Unified multi-provider LLM API
- TypeScript

## License

MIT
