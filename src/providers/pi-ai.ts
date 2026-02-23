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
    const result = await completeSimple(m, context, apiKey ? { apiKey } as any : undefined);
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
