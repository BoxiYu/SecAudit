import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';
import * as readline from 'node:readline';

// Dynamic import for pi-ai OAuth modules (no exports map)
const require = createRequire(import.meta.url);

interface OAuthCredentials {
  refresh: string;
  access: string;
  expires: number;
  [key: string]: unknown;
}

const CONFIG_DIR = join(homedir(), '.secaudit');
const CREDENTIALS_FILE = join(CONFIG_DIR, 'credentials.json');

interface StoredCredentials {
  provider: string;
  credentials: OAuthCredentials;
}

function loadCredentials(): StoredCredentials | null {
  try {
    if (existsSync(CREDENTIALS_FILE)) {
      return JSON.parse(readFileSync(CREDENTIALS_FILE, 'utf-8'));
    }
  } catch { /* ignore */ }
  return null;
}

function saveCredentials(provider: string, credentials: OAuthCredentials): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CREDENTIALS_FILE, JSON.stringify({ provider, credentials }, null, 2), { mode: 0o600 });
}

function prompt(message: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(message, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

export async function login(provider: string = 'openai-codex'): Promise<void> {
  if (provider === 'openai-codex' || provider === 'chatgpt') {
    console.log('\n🔐 Logging in with ChatGPT (OpenAI Codex OAuth)...\n');

    const { loginOpenAICodex } = await import('@mariozechner/pi-ai/dist/utils/oauth/openai-codex.js') as any;
    const credentials = await loginOpenAICodex({
      onAuth: (info: any) => {
        console.log('Open this URL in your browser to log in:\n');
        console.log(`  ${info.url}\n`);
        if (info.instructions) {
          console.log(info.instructions);
        }
      },
      onPrompt: async (p: any) => {
        return await prompt(p.message + ' ');
      },
      onProgress: (msg: string) => {
        console.log(`  ${msg}`);
      },
      originator: 'secaudit',
    });

    saveCredentials('openai-codex', credentials);
    console.log('\n✅ Login successful! Credentials saved to ~/.secaudit/credentials.json');
    console.log('You can now run secaudit with --provider openai-codex\n');
    return;
  }

  // Fallback: show env var instructions
  const envVarMap: Record<string, string> = {
    openai: 'OPENAI_API_KEY',
    anthropic: 'ANTHROPIC_API_KEY',
    google: 'GOOGLE_API_KEY',
    mistral: 'MISTRAL_API_KEY',
    groq: 'GROQ_API_KEY',
    xai: 'XAI_API_KEY',
  };

  const envVar = envVarMap[provider] || `${provider.toUpperCase()}_API_KEY`;
  console.log(`\nTo use secaudit with ${provider}, set:\n`);
  console.log(`  export ${envVar}="your-key-here"\n`);
}

export function checkAuth(provider: string): boolean {
  // Check OAuth credentials first
  if (provider === 'openai-codex' || provider === 'chatgpt') {
    const stored = loadCredentials();
    if (stored?.provider === 'openai-codex' && stored.credentials?.access) {
      return true;
    }
    return false;
  }

  const envVarMap: Record<string, string> = {
    openai: 'OPENAI_API_KEY',
    anthropic: 'ANTHROPIC_API_KEY',
    google: 'GOOGLE_API_KEY',
    mistral: 'MISTRAL_API_KEY',
    groq: 'GROQ_API_KEY',
    xai: 'XAI_API_KEY',
  };

  const envVar = envVarMap[provider] || `${provider.toUpperCase()}_API_KEY`;
  return !!process.env[envVar];
}

/**
 * Get API key for provider — from env var or OAuth credentials
 */
export async function getApiKey(provider: string): Promise<string | null> {
  if (provider === 'openai-codex' || provider === 'chatgpt') {
    const stored = loadCredentials();
    if (!stored?.credentials) return null;

    // Check if token expired, refresh if needed
    if (stored.credentials.expires && Date.now() > stored.credentials.expires) {
      try {
        const { refreshOpenAICodexToken } = await import('@mariozechner/pi-ai/dist/utils/oauth/openai-codex.js') as any;
        const refreshed = await refreshOpenAICodexToken(stored.credentials.refresh);
        saveCredentials('openai-codex', refreshed);
        return refreshed.access;
      } catch {
        console.error('Token refresh failed. Run: secaudit login');
        return null;
      }
    }

    return stored.credentials.access;
  }

  const envVarMap: Record<string, string> = {
    openai: 'OPENAI_API_KEY',
    anthropic: 'ANTHROPIC_API_KEY',
    google: 'GOOGLE_API_KEY',
  };

  const envVar = envVarMap[provider] || `${provider.toUpperCase()}_API_KEY`;
  return process.env[envVar] || null;
}
