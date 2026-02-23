import { execFileSync, execSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { RLM_IMAGE, getDockerEnv, getDockerBin, ensureRLMImage } from './rlm-docker.js';

export interface REPLExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

const EXEC_TIMEOUT_MS = 30_000;
const MAX_OUTPUT_CHARS = 50_000;

/**
 * Python helper code pre-loaded into the container for llm_query support.
 * Writes a request JSON, then polls for the response file.
 */
const LLM_HELPER = `
import json, time, os

def llm_query(prompt: str) -> str:
    """Send a prompt to the parent LLM and return the response."""
    req = {"type": "single", "prompt": prompt}
    with open("/workspace/.llm_request.json", "w") as f:
        json.dump(req, f)
    # Wait for response (parent process handles the LLM call)
    for _ in range(300):  # 30s max wait
        if os.path.exists("/workspace/.llm_response.json"):
            with open("/workspace/.llm_response.json") as f:
                resp = json.load(f)
            os.remove("/workspace/.llm_response.json")
            return resp.get("result", "")
        time.sleep(0.1)
    return "[ERROR: LLM query timed out]"

def llm_query_batched(prompts: list[str]) -> list[str]:
    """Send multiple prompts to the parent LLM and return responses."""
    req = {"type": "batched", "prompts": prompts}
    with open("/workspace/.llm_request.json", "w") as f:
        json.dump(req, f)
    for _ in range(600):  # 60s max wait for batched
        if os.path.exists("/workspace/.llm_response.json"):
            with open("/workspace/.llm_response.json") as f:
                resp = json.load(f)
            os.remove("/workspace/.llm_response.json")
            return resp.get("results", [])
        time.sleep(0.1)
    return ["[ERROR: LLM batch query timed out]"] * len(prompts)
`;

/**
 * REPL sandbox environment for RLM engine.
 * Manages a Docker container where the LLM can execute Python code
 * to programmatically analyze the target codebase.
 */
export class RLMRepl {
  private containerId: string | null = null;
  private dockerEnv: Record<string, string>;

  constructor() {
    this.dockerEnv = getDockerEnv();
  }

  /**
   * Start the REPL container with the target codebase mounted read-only.
   */
  async start(targetPath: string): Promise<void> {
    if (!ensureRLMImage()) {
      throw new Error('Failed to ensure RLM Docker image. Is Docker running?');
    }

    const absTarget = resolve(targetPath);
    const containerName = `secaudit-rlm-${randomBytes(4).toString('hex')}`;

    try {
      // Start a detached container that sleeps forever (we exec into it)
      const id = execFileSync(getDockerBin(), [
        'run', '-d',
        '--name', containerName,
        '--network=none',
        '--memory=512m',
        '--cpus=1',
        '-v', `${absTarget}:/code:ro`,
        '--tmpfs', '/workspace:rw,size=128m',
        RLM_IMAGE,
        'sleep', '3600',
      ], {
        encoding: 'utf-8',
        env: this.dockerEnv,
        timeout: 30000,
      }).trim();

      this.containerId = id;

      // Pre-load the LLM helper into the container
      this.execInContainer(`cat > /workspace/_llm_helper.py << 'PYEOF'\n${LLM_HELPER}\nPYEOF`);
    } catch (err) {
      throw new Error(`Failed to start REPL container: ${(err as Error).message}`);
    }
  }

  /**
   * Execute Python code in the running container.
   */
  async execute(code: string): Promise<REPLExecResult> {
    if (!this.containerId) {
      throw new Error('REPL container not started');
    }

    // Write code to a temp file in the container, then execute it
    const escapedCode = code.replace(/'/g, "'\\''");
    const wrappedCode = `from _llm_helper import llm_query, llm_query_batched\n${code}`;

    try {
      // Write the code file
      this.execInContainer(`cat > /workspace/_exec.py << 'PYEOF'\n${wrappedCode}\nPYEOF`);

      // Execute it with timeout
      const result = execSync(
        `${getDockerBin()} exec ${this.containerId} timeout ${EXEC_TIMEOUT_MS / 1000} python3 /workspace/_exec.py 2>&1; echo "___EXIT_CODE=$?"`,
        {
          encoding: 'utf-8',
          env: this.dockerEnv,
          timeout: EXEC_TIMEOUT_MS + 5000,
          maxBuffer: 1024 * 1024 * 5,
        },
      );

      // Parse exit code from output
      const exitMatch = result.match(/___EXIT_CODE=(\d+)\s*$/);
      const exitCode = exitMatch ? parseInt(exitMatch[1], 10) : 0;
      const output = result.replace(/___EXIT_CODE=\d+\s*$/, '').trim();

      // Truncate if too large
      const truncated = output.length > MAX_OUTPUT_CHARS
        ? output.substring(0, MAX_OUTPUT_CHARS) + '\n... [output truncated]'
        : output;

      return { stdout: truncated, stderr: '', exitCode };
    } catch (err) {
      const errMsg = (err as any).stderr || (err as Error).message || '';
      const stdout = (err as any).stdout || '';
      return {
        stdout: stdout.substring(0, MAX_OUTPUT_CHARS),
        stderr: errMsg.substring(0, MAX_OUTPUT_CHARS),
        exitCode: 1,
      };
    }
  }

  /**
   * Check if there's a pending llm_query request from the container.
   * Returns the request JSON if found, null otherwise.
   */
  checkForLLMRequest(): { type: string; prompt?: string; prompts?: string[] } | null {
    if (!this.containerId) return null;
    try {
      const result = execSync(
        `${getDockerBin()} exec ${this.containerId} cat /workspace/.llm_request.json 2>/dev/null`,
        { encoding: 'utf-8', env: this.dockerEnv, timeout: 5000 },
      ).trim();
      if (!result) return null;
      // Remove the request file
      execSync(
        `${getDockerBin()} exec ${this.containerId} rm -f /workspace/.llm_request.json`,
        { encoding: 'utf-8', env: this.dockerEnv, timeout: 5000 },
      );
      return JSON.parse(result);
    } catch {
      return null;
    }
  }

  /**
   * Write an LLM response back to the container for the Python code to read.
   */
  writeLLMResponse(response: { result?: string; results?: string[] }): void {
    if (!this.containerId) return;
    const json = JSON.stringify(response);
    const escaped = json.replace(/'/g, "'\\''");
    try {
      execSync(
        `${getDockerBin()} exec ${this.containerId} sh -c 'echo '"'"'${escaped}'"'"' > /workspace/.llm_response.json'`,
        { encoding: 'utf-8', env: this.dockerEnv, timeout: 5000 },
      );
    } catch {
      // Best effort
    }
  }

  /**
   * Stop and remove the container.
   */
  async stop(): Promise<void> {
    if (!this.containerId) return;
    try {
      execFileSync(getDockerBin(), ['rm', '-f', this.containerId], {
        stdio: 'ignore',
        env: this.dockerEnv,
        timeout: 15000,
      });
    } catch {
      // Best effort cleanup
    }
    this.containerId = null;
  }

  /**
   * Whether the container is running.
   */
  get isRunning(): boolean {
    return this.containerId !== null;
  }

  private execInContainer(cmd: string): string {
    if (!this.containerId) throw new Error('Container not started');
    return execSync(
      `${getDockerBin()} exec ${this.containerId} sh -c '${cmd.replace(/'/g, "'\\''")}'`,
      { encoding: 'utf-8', env: this.dockerEnv, timeout: 15000 },
    );
  }
}
