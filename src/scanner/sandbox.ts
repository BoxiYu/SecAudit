import { execFileSync, execSync } from 'node:child_process';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Finding, Severity } from '../types.js';
import { getDockerBin, getDockerEnv } from './rlm-docker.js';

const DOCKER_IMAGE = 'secaudit-sandbox';
const TIMEOUT_SECONDS = 30;

// Dockerfile for C/C++ verification with AddressSanitizer
const DOCKERFILE = `FROM gcc:14
RUN apt-get update && apt-get install -y python3 python3-pip valgrind gdb && rm -rf /var/lib/apt/lists/*
WORKDIR /audit
`;

/**
 * Ensure the sandbox Docker image exists
 */
export function ensureSandboxImage(): boolean {
  try {
    execFileSync(getDockerBin(), ['image', 'inspect', DOCKER_IMAGE], { stdio: 'ignore' });
    return true;
  } catch {
    // Build the image
    const tmpDir = join(tmpdir(), 'secaudit-sandbox-build');
    try {
      mkdirSync(tmpDir, { recursive: true });
      writeFileSync(join(tmpDir, 'Dockerfile'), DOCKERFILE);
      execFileSync(getDockerBin(), ['build', '-t', DOCKER_IMAGE, tmpDir], {
        stdio: 'inherit',
        timeout: 120000,
      });
      rmSync(tmpDir, { recursive: true, force: true });
      return true;
    } catch (err) {
      console.error('Failed to build sandbox image:', (err as Error).message);
      rmSync(tmpDir, { recursive: true, force: true });
      return false;
    }
  }
}

interface VerificationResult {
  verified: boolean;
  output: string;
  exitCode: number;
  asanReport?: string;
}

/**
 * Verify a C/C++ vulnerability by compiling with ASan and running a PoC
 */
export function verifyCVuln(
  sourceFile: string,
  pocCode: string,
  compileFlags: string[] = [],
): VerificationResult {
  const tmpDir = join(tmpdir(), `secaudit-verify-${Date.now()}`);
  mkdirSync(tmpDir, { recursive: true });

  try {
    // Write source and PoC
    writeFileSync(join(tmpDir, 'target.c'), sourceFile);
    writeFileSync(join(tmpDir, 'poc.c'), pocCode);
    writeFileSync(join(tmpDir, 'run.sh'), `#!/bin/bash
set -e
# Compile with AddressSanitizer
gcc -fsanitize=address -fno-omit-frame-pointer -g -o target target.c ${compileFlags.join(' ')} 2>&1 || exit 1
# Compile and run PoC
gcc -fsanitize=address -fno-omit-frame-pointer -g -o poc poc.c ${compileFlags.join(' ')} 2>&1 || exit 1
# Run with timeout
timeout ${TIMEOUT_SECONDS} ./poc 2>&1
echo "EXIT_CODE=$?"
`);

    // Run in Docker
    const output = execSync(
      `docker run --rm --network=none --memory=256m --cpus=1 ` +
      `--read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m ` +
      `-v "${tmpDir}:/audit:ro" ` +
      `-w /tmp ` +
      `${DOCKER_IMAGE} bash -c "cp /audit/* . && chmod +x run.sh && ./run.sh"`,
      {
        encoding: 'utf-8',
        timeout: (TIMEOUT_SECONDS + 10) * 1000,
        maxBuffer: 1024 * 1024,
      }
    );

    const hasAsan = output.includes('AddressSanitizer') || output.includes('ERROR: asan');
    const hasCrash = output.includes('SEGV') || output.includes('Segmentation fault') || output.includes('Aborted');
    const exitMatch = output.match(/EXIT_CODE=(\d+)/);
    const exitCode = exitMatch ? parseInt(exitMatch[1]) : 0;

    return {
      verified: hasAsan || hasCrash || exitCode !== 0,
      output: output.substring(0, 2000),
      exitCode,
      asanReport: hasAsan ? output : undefined,
    };
  } catch (err) {
    const errMsg = (err as Error).message || '';
    const hasAsan = errMsg.includes('AddressSanitizer');
    return {
      verified: hasAsan,
      output: errMsg.substring(0, 2000),
      exitCode: 1,
      asanReport: hasAsan ? errMsg : undefined,
    };
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

/**
 * Ask LLM to generate a PoC for a finding and verify it in sandbox
 */
export async function verifyFinding(
  finding: Finding,
  sourceCode: string,
  provider: string,
  model: string,
  apiKey?: string,
): Promise<{ verified: boolean; poc?: string; asanReport?: string }> {
  const { createModel } = await import('../providers/pi-ai.js');
  const { completeSimple } = await import('@mariozechner/pi-ai');

  const m = createModel(provider, model, apiKey);
  const context = {
    systemPrompt: `You are a security researcher. Given a vulnerability finding and source code, write a minimal C program (poc.c) that triggers the vulnerability.
The PoC will be compiled with: gcc -fsanitize=address -g -o poc poc.c
It should trigger a crash, AddressSanitizer error, or observable bad behavior.
Respond ONLY with the C code, no markdown fences, no explanation.`,
    messages: [{
      role: 'user' as const,
      content: `Vulnerability: ${finding.message}
File: ${finding.file}, Line: ${finding.line}
Rule: ${finding.rule}

Source code:
${sourceCode.substring(0, 10000)}

Write a PoC (poc.c) that triggers this vulnerability:`,
      timestamp: Date.now(),
    }],
  };

  try {
    const result = await completeSimple(m, context, apiKey ? { apiKey } as any : undefined);
    const textParts = result.content.filter((c): c is { type: 'text'; text: string } => 'type' in c && (c as any).type === 'text');
    let poc = textParts.map((p) => p.text).join('');

    // Strip markdown fences if present
    poc = poc.replace(/^```c?\n?/m, '').replace(/\n?```$/m, '').trim();

    if (!poc.includes('main') && !poc.includes('int ')) {
      return { verified: false };
    }

    const verResult = verifyCVuln(sourceCode, poc);
    return {
      verified: verResult.verified,
      poc,
      asanReport: verResult.asanReport,
    };
  } catch (err) {
    console.error(`PoC generation failed:`, (err as Error).message);
    return { verified: false };
  }
}
