# SecAudit - AI Security Review Tool

## Overview
CLI tool for automated security review of codebases, powered by LLMs.
Built with pi-mono's `pi-ai` for unified LLM access and designed as an OpenClaw skill.

## Features
1. **CLI** (`secaudit`) - Run security reviews from terminal
2. **GitHub Action** - Auto-review PRs
3. **OpenClaw Skill** - Integrate as `/security-review`

## Architecture

```
secaudit/
├── src/
│   ├── cli.ts              # CLI entry point (commander)
│   ├── index.ts             # Library exports
│   ├── scanner/
│   │   ├── static.ts        # Static rule-based scanning (fast, free)
│   │   ├── llm.ts           # LLM-powered deep analysis
│   │   └── rules/           # Static rule definitions
│   │       ├── sql-injection.ts
│   │       ├── xss.ts
│   │       ├── auth.ts
│   │       ├── secrets.ts
│   │       └── dependencies.ts
│   ├── providers/
│   │   └── pi-ai.ts         # pi-ai LLM integration
│   ├── auth/
│   │   └── oauth.ts         # ChatGPT/OpenAI OAuth flow
│   ├── reporter/
│   │   ├── terminal.ts      # CLI output (colored, grouped)
│   │   ├── json.ts          # JSON output
│   │   ├── sarif.ts         # SARIF format (GitHub integration)
│   │   └── github-pr.ts     # GitHub PR inline comments
│   └── types.ts             # Shared types
├── skill/
│   └── SKILL.md             # OpenClaw skill definition
├── action/
│   ├── action.yml           # GitHub Action definition
│   └── entrypoint.ts        # Action entry
├── package.json
├── tsconfig.json
└── README.md
```

## Tech Stack
- **Language:** TypeScript
- **LLM API:** `@mariozechner/pi-ai` (unified multi-provider)
- **CLI:** `commander`
- **Auth:** OpenAI OAuth (ChatGPT login) via pi-ai's OAuth support
- **Output:** Terminal (chalk), JSON, SARIF

## Flow
1. User runs `secaudit ./src` or `secaudit --diff HEAD~1`
2. Static rules run first (instant, catches obvious patterns)
3. LLM analysis on flagged files + complex logic
4. Results merged, deduplicated, severity-ranked
5. Output in chosen format

## Auth Options
- `OPENAI_API_KEY` env var (direct)
- `secaudit login` → ChatGPT OAuth flow (like pi's OAuth)
- Any pi-ai supported provider key

## Security Checks
### Static Rules (fast)
- SQL injection patterns
- XSS sinks (innerHTML, document.write, dangerouslySetInnerHTML)
- Hardcoded secrets/API keys
- Insecure crypto usage
- Path traversal
- Command injection (exec, spawn with user input)
- Insecure HTTP usage
- Eval/Function constructor

### LLM Analysis (deep)
- Business logic flaws
- Authentication/authorization gaps
- Race conditions
- IDOR vulnerabilities
- Insecure deserialization
- Complex data flow analysis
- Context-aware vulnerability detection

## CLI Usage
```bash
# Scan directory
secaudit ./src

# Scan git diff
secaudit --diff HEAD~1

# Scan with specific provider
secaudit --provider anthropic --model claude-sonnet-4-20250514 ./src

# Output formats
secaudit --format json ./src
secaudit --format sarif ./src > results.sarif

# Auth
secaudit login            # ChatGPT OAuth
secaudit login --provider anthropic  # Other providers

# Config
secaudit init             # Create .secaudit.yml config
```

## OpenClaw Skill Integration
```yaml
name: secaudit
description: Run AI-powered security reviews on code
requires:
  bins: [secaudit]
```

Invoke via: `/security-review ./src` in OpenClaw
