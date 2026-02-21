import { getModel, completeSimple, type Context, type KnownProvider } from '@mariozechner/pi-ai';
import { Finding, Severity } from '../types.js';

const SYSTEM_PROMPT = `You are a security auditor. Analyze the provided code for security vulnerabilities.

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

export function createModel(provider: string, model: string) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (getModel as any)(provider, model);
}

export async function analyzeCode(
  provider: string,
  model: string,
  code: string,
  filename: string,
): Promise<Finding[]> {
  const m = createModel(provider, model);

  const context: Context = {
    systemPrompt: SYSTEM_PROMPT,
    messages: [
      {
        role: 'user' as const,
        content: `Analyze this file for security vulnerabilities:\n\nFilename: ${filename}\n\n\`\`\`\n${code}\n\`\`\``,
        timestamp: Date.now(),
      },
    ],
  };

  try {
    const result = await completeSimple(m, context);
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
