import { getModel, completeSimple, type Context, type KnownProvider, type Model, type Api } from '@mariozechner/pi-ai';
import { Finding, Severity } from '../types.js';

const SYSTEM_PROMPT_DEFAULT = `You are a security auditor. Analyze the provided code for security vulnerabilities.

For each vulnerability found, respond with a JSON array of objects:
{
  "line": <line number>,
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "category": "<category>",
  "message": "<description of the vulnerability and how to fix it>",
  "rule": "LLM_<short_id>"
}

Focus on:
- Business logic flaws
- Authentication/authorization gaps
- Race conditions
- IDOR vulnerabilities
- Insecure deserialization
- Complex data flow issues
- Missing input validation
- Error handling that leaks information

If no vulnerabilities are found, return an empty array: []
Respond ONLY with the JSON array, no other text.`;

const SYSTEM_PROMPT_SOLIDITY = `You are an elite smart contract security auditor specializing in EVM/Solidity. You have deep expertise in DeFi protocols, token economics, and on-chain attack vectors.

Analyze the provided Solidity code for HIGH-SEVERITY vulnerabilities that could lead to LOSS OF FUNDS.

For each vulnerability found, respond with a JSON array of objects:
{
  "line": <line number>,
  "severity": "critical" | "high" | "medium" | "low",
  "category": "<category>",
  "message": "<precise root cause, impact, and exploit scenario>",
  "rule": "LLM_<short_id>"
}

Focus ONLY on exploitable vulnerabilities in these categories:

**Reentrancy & State:**
- Cross-function and cross-contract reentrancy
- Read-only reentrancy (view functions returning stale state during callback)
- State changes after external calls (CEI violations)
- Storage collision in proxy/upgradeable patterns

**Access Control:**
- Missing/incorrect modifiers on sensitive functions (mint, burn, withdraw, upgrade, pause)
- Unprotected initializers in upgradeable contracts
- tx.origin vs msg.sender confusion
- Delegatecall to untrusted targets

**Math & Accounting:**
- Integer overflow/underflow in unchecked blocks
- Rounding errors in share/token calculations (first depositor attack, vault inflation)
- Price manipulation via flash loans or donation attacks
- Incorrect fee/reward/interest calculations
- Division before multiplication precision loss

**DeFi-Specific:**
- Flash loan attack vectors (price oracle manipulation, liquidity manipulation)
- Sandwich attack opportunities (missing slippage protection, no deadline)
- TWAP manipulation (short window, low liquidity)
- Vault share inflation/deflation attacks
- Incorrect LP token accounting
- Missing checks on external protocol return values

**Token & Transfer:**
- ERC20 approve race condition
- Fee-on-transfer / rebasing token incompatibility
- Missing return value checks on transfer/transferFrom
- Blacklist/pausable token DoS vectors
- ERC721/1155 callback reentrancy

**Cross-Contract:**
- Incorrect trust assumptions between contracts
- Missing validation of external contract addresses
- Signature replay across chains or contracts (missing chain ID, nonce, domain separator)
- Frontrunning/backrunning opportunities

**Logic Flaws:**
- Invariant violations (can a user end up with more value than deposited?)
- Incorrect conditional logic (&&/|| confusion, off-by-one, boundary conditions)
- State machine violations (can functions be called in wrong order?)
- Missing deadline/expiry checks

**Accounting Invariant Checks (CRITICAL - 30% of real-world high-severity bugs):**
- Can totalShares * pricePerShare != totalAssets after a sequence of deposits/withdrawals?
- Does the first depositor get fair shares? Can deposit(1 wei) + donate() inflate share price?
- Are rewards/fees calculated on stale balances vs current balances?
- Do intermediate rounding errors accumulate across operations?
- Does contract use address(this).balance or balanceOf(address(this)) that can be manipulated by direct transfer/selfdestruct?

**Replay & Frontrun (20% of real-world bugs):**
- Can the same signature be replayed on another chain, after a state change, or by a different caller?
- Is nonce/deadline/chainId/domainSeparator included in ALL signature schemes?
- Can admin functions be frontrun to change parameters before user tx executes?
- Can an order/bid be replayed after partial state changes?

**Protocol Integration (25% of real-world bugs):**
- Does code handle fee-on-transfer tokens correctly (actual received vs parameter amount)?
- Are return values from external calls (transfer, swap, oracle) validated?
- Can oracle prices be manipulated within a single transaction (flash loan)?
- Does TWAP window resist manipulation (need >30 min window with sufficient liquidity)?
- Are external protocol assumptions still valid (e.g., Uniswap V3 tick spacing, Aave health factor)?

Be SPECIFIC: identify the exact function, the exact line, the exact mechanism of exploitation, and the exact impact (e.g., "attacker drains X tokens by..."). Generic observations like "consider adding reentrancy guard" are NOT useful.

If no vulnerabilities are found, return an empty array: []
Respond ONLY with the JSON array, no other text.`;

function getSystemPrompt(filename: string): string {
  const ext = filename.toLowerCase();
  if (ext.endsWith('.sol') || ext.endsWith('.vy')) {
    return SYSTEM_PROMPT_SOLIDITY;
  }
  return SYSTEM_PROMPT_DEFAULT;
}

// Keep backward compat
const SYSTEM_PROMPT = SYSTEM_PROMPT_DEFAULT;

function addLineNumbers(code: string): string {
  return code.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');
}

export function createModel(provider: string, model: string, apiKey?: string): Model<Api> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const m = (getModel as any)(provider, model) as Model<Api>;

  // For OAuth providers, inject the token as Authorization header
  if (apiKey && (provider === 'openai-codex' || provider === 'chatgpt')) {
    m.headers = { ...m.headers, Authorization: `Bearer ${apiKey}` };
  }

  return m;
}

export async function analyzeCode(
  provider: string,
  model: string,
  code: string,
  filename: string,
  apiKey?: string,
  reasoning?: string,
): Promise<Finding[]> {
  const m = createModel(provider, model, apiKey);

  const context: Context = {
    systemPrompt: getSystemPrompt(filename),
    messages: [
      {
        role: 'user' as const,
        content: `Analyze this file for security vulnerabilities:\n\nFilename: ${filename}\n\n\`\`\`\n${addLineNumbers(code)}\n\`\`\``,
        timestamp: Date.now(),
      },
    ],
  };

  try {
    const opts: any = {};
    if (apiKey) opts.apiKey = apiKey;
    if (reasoning) opts.reasoning = reasoning;
    const result = await completeSimple(m, context, Object.keys(opts).length ? opts : undefined);
    // completeSimple returns AssistantMessage with content array
    const textParts = result.content.filter((c): c is { type: 'text'; text: string } => 'type' in c && (c as any).type === 'text');
    const text = textParts.map((p) => p.text).join('');

    if (!text) return [];

    // Extract JSON from possible markdown code blocks
    const jsonMatch = text.match(/\[[\s\S]*\]/);
    if (!jsonMatch) return [];

    const parsed = JSON.parse(jsonMatch[0]) as Array<{
      line: number;
      severity: string;
      category: string;
      message: string;
      rule: string;
    }>;

    return parsed.map((item) => ({
      file: filename,
      line: item.line || 1,
      column: 1,
      severity: (item.severity as Severity) || Severity.Medium,
      category: item.category || 'LLM Analysis',
      message: item.message || 'Potential vulnerability detected',
      rule: item.rule || 'LLM_GENERIC',
      snippet: '',
    }));
  } catch (err) {
    console.error(`LLM analysis failed for ${filename}:`, (err as Error).message);
    return [];
  }
}

const VERIFY_PROMPT = `You are a senior smart contract security auditor performing a VERIFICATION pass.
You are given a candidate vulnerability report and the relevant source code.
Your job is to determine if this is a REAL exploitable vulnerability or a FALSE POSITIVE.

For each candidate, respond with a JSON array:
[{
  "id": <index>,
  "verdict": "CONFIRMED" | "FALSE_POSITIVE",
  "confidence": 0.0-1.0,
  "reason": "<why this is real or false positive, with specific code references>"
}]

A finding is FALSE_POSITIVE if:
- The described attack is prevented by a modifier, require, or check the auditor missed
- The function is internal/private and only called safely
- The contract is a mock/test/example not meant for production
- The described scenario is economically infeasible (costs more than gain)
- The code path is unreachable or guarded by protocol-level controls

A finding is CONFIRMED if:
- You can trace a concrete exploit path from entry point to impact
- The described root cause is correct and the code lacks adequate protection
- The impact (loss of funds, DoS, privilege escalation) is real

Be strict. When in doubt, mark FALSE_POSITIVE. We prefer missing real vulns over reporting false ones.
Respond ONLY with the JSON array.`;

export async function verifyFindings(
  provider: string,
  model: string,
  code: string,
  filename: string,
  findings: Finding[],
  apiKey?: string,
): Promise<Finding[]> {
  if (findings.length === 0) return [];

  const m = createModel(provider, model, apiKey);

  const candidateList = findings.map((f, i) =>
    `[${i}] ${f.severity.toUpperCase()} L${f.line}: ${f.message}`
  ).join('\n');

  const context: Context = {
    systemPrompt: VERIFY_PROMPT,
    messages: [
      {
        role: 'user' as const,
        content: `Verify these candidate vulnerabilities:\n\n${candidateList}\n\nSource code (${filename}):\n\`\`\`\n${addLineNumbers(code)}\n\`\`\``,
        timestamp: Date.now(),
      },
    ],
  };

  try {
    const result = await completeSimple(m, context, apiKey ? { apiKey } as any : undefined);
    const textParts = result.content.filter((c): c is { type: 'text'; text: string } => 'type' in c && (c as any).type === 'text');
    const text = textParts.map((p) => p.text).join('');
    if (!text) return findings; // fallback: keep all

    const jsonMatch = text.match(/\[[\s\S]*\]/);
    if (!jsonMatch) return findings;

    const verdicts = JSON.parse(jsonMatch[0]) as Array<{
      id: number;
      verdict: string;
      confidence: number;
    }>;

    // Keep only CONFIRMED findings with confidence >= 0.6
    const confirmedIds = new Set(
      verdicts
        .filter((v) => v.verdict === 'CONFIRMED' && (v.confidence ?? 1) >= 0.6)
        .map((v) => v.id)
    );

    return findings.filter((_, i) => confirmedIds.has(i));
  } catch (err) {
    console.error(`Verification failed for ${filename}:`, (err as Error).message);
    return findings; // fallback: keep all on error
  }
}
