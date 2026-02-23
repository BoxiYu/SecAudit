import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';

const RLM_IMAGE = 'secaudit-rlm';

const DOCKERFILE = `FROM python:3.12-slim
RUN pip install --no-cache-dir tree-sitter tree-sitter-languages networkx jedi rope || true
RUN apt-get update && apt-get install -y --no-install-recommends ripgrep jq && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /code /workspace
WORKDIR /workspace
`;

/**
 * Find the docker binary, preferring newer Homebrew version over system.
 */
function findDockerBin(): string {
  const candidates = [
    join(homedir(), '.homebrew', 'bin', 'docker'),
    '/opt/homebrew/bin/docker',
    '/usr/local/bin/docker',
    'docker',
  ];
  for (const bin of candidates) {
    try {
      execFileSync(bin, ['--version'], { stdio: 'ignore', timeout: 5000 });
      return bin;
    } catch { /* try next */ }
  }
  return 'docker';
}

let _dockerBin: string | undefined;
export function getDockerBin(): string {
  if (!_dockerBin) _dockerBin = findDockerBin();
  return _dockerBin;
}

/**
 * Get Docker environment, preferring Colima socket if available.
 */
export function getDockerEnv(): Record<string, string> {
  const env: Record<string, string> = { ...process.env as Record<string, string> };
  // Prefer colima default profile socket, then fallback
  const colimaDefault = join(homedir(), '.colima', 'default', 'docker.sock');
  const colimaLegacy = join(homedir(), '.colima', 'docker.sock');
  if (existsSync(colimaDefault)) {
    env.DOCKER_HOST = `unix://${colimaDefault}`;
  } else if (existsSync(colimaLegacy)) {
    env.DOCKER_HOST = `unix://${colimaLegacy}`;
  }
  // Disable BuildKit to avoid buildx API version mismatch with Colima
  env.DOCKER_BUILDKIT = '0';
  return env;
}

/**
 * Check if Docker is available and responsive.
 */
export function isDockerAvailable(): boolean {
  try {
    execFileSync(getDockerBin(), ['info'], { stdio: 'ignore', env: getDockerEnv(), timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Ensure the secaudit-rlm Docker image exists, building it if necessary.
 */
export function ensureRLMImage(): boolean {
  const env = getDockerEnv();
  try {
    execFileSync(getDockerBin(), ['image', 'inspect', RLM_IMAGE], { stdio: 'ignore', env });
    return true;
  } catch {
    const tmpDir = join(tmpdir(), 'secaudit-rlm-build');
    try {
      mkdirSync(tmpDir, { recursive: true });
      writeFileSync(join(tmpDir, 'Dockerfile'), DOCKERFILE);
      execFileSync(getDockerBin(), ['build', '-t', RLM_IMAGE, tmpDir], {
        stdio: 'inherit',
        timeout: 180000,
        env,
      });
      rmSync(tmpDir, { recursive: true, force: true });
      return true;
    } catch (err) {
      console.error('Failed to build RLM image:', (err as Error).message);
      rmSync(tmpDir, { recursive: true, force: true });
      return false;
    }
  }
}

export { RLM_IMAGE };
