import { getProviders } from '@mariozechner/pi-ai';

export async function login(provider: string = 'openai'): Promise<void> {
  const providers = getProviders();

  if (!providers.includes(provider as any)) {
    console.error(`Unknown provider: ${provider}`);
    console.error(`Available providers: ${providers.join(', ')}`);
    process.exit(1);
  }

  console.log(`\nTo use secaudit with ${provider}, set the appropriate environment variable:\n`);

  const envVarMap: Record<string, string> = {
    openai: 'OPENAI_API_KEY',
    anthropic: 'ANTHROPIC_API_KEY',
    google: 'GOOGLE_API_KEY',
    mistral: 'MISTRAL_API_KEY',
    groq: 'GROQ_API_KEY',
    xai: 'XAI_API_KEY',
  };

  const envVar = envVarMap[provider] || `${provider.toUpperCase()}_API_KEY`;
  console.log(`  export ${envVar}="your-key-here"\n`);
}

export function checkAuth(provider: string): boolean {
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
