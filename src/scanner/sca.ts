import { readFileSync, existsSync } from 'node:fs';
import { join, basename } from 'node:path';
import { glob } from 'glob';
import { Finding, Severity } from '../types.js';

interface OSVVulnerability {
  id: string;
  summary: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  aliases?: string[];
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{ events: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

interface OSVResponse {
  vulns?: OSVVulnerability[];
}

const LOCKFILE_PARSERS: Record<string, (content: string) => Array<{ name: string; version: string; ecosystem: string }>> = {
  'package-lock.json': parseNpmLock,
  'yarn.lock': parseYarnLock,
  'requirements.txt': parsePipRequirements,
  'Pipfile.lock': parsePipfileLock,
  'go.sum': parseGoSum,
  'Cargo.lock': parseCargoLock,
  'Gemfile.lock': parseGemfileLock,
  'pom.xml': parsePomXml,
  'composer.lock': parseComposerLock,
};

function parseNpmLock(content: string): Array<{ name: string; version: string; ecosystem: string }> {
  try {
    const lock = JSON.parse(content);
    const deps: Array<{ name: string; version: string; ecosystem: string }> = [];
    const packages = lock.packages ?? {};
    for (const [path, info] of Object.entries(packages)) {
      if (path === '') continue;
      const name = path.replace(/^node_modules\//, '');
      const version = (info as { version?: string }).version;
      if (name && version) deps.push({ name, version, ecosystem: 'npm' });
    }
    // Fallback for v1 lockfile
    if (deps.length === 0 && lock.dependencies) {
      for (const [name, info] of Object.entries(lock.dependencies)) {
        const version = (info as { version?: string }).version;
        if (version) deps.push({ name, version, ecosystem: 'npm' });
      }
    }
    return deps;
  } catch { return []; }
}

function parseYarnLock(content: string): Array<{ name: string; version: string; ecosystem: string }> {
  const deps: Array<{ name: string; version: string; ecosystem: string }> = [];
  const regex = /^"?(@?[^@\s"]+)@[^:]+":?\s*\n\s+version\s+"?([^"\s]+)"?/gm;
  let match;
  while ((match = regex.exec(content))) {
    deps.push({ name: match[1], version: match[2], ecosystem: 'npm' });
  }
  return deps;
}

function parsePipRequirements(content: string): Array<{ name: string; version: string; ecosystem: string }> {
  return content.split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#') && !l.startsWith('-'))
    .map((l) => {
      const m = l.match(/^([a-zA-Z0-9._-]+)==([^\s;]+)/);
      return m ? { name: m[1], version: m[2], ecosystem: 'PyPI' } : null;
    })
    .filter((x): x is NonNullable<typeof x> => !!x);
}

function parsePipfileLock(content: string): Array<{ name: string; version: string; ecosystem: string }> {
  try {
    const lock = JSON.parse(content);
    const deps: Array<{ name: string; version: string; ecosystem: string }> = [];
    for (const section of ['default', 'develop']) {
      const pkgs = lock[section] ?? {};
      for (const [name, info] of Object.entries(pkgs)) {
        const version = ((info as { version?: string }).version ?? '').replace(/^==/, '');
        if (version) deps.push({ name, version, ecosystem: 'PyPI' });
      }
    }
    return deps;
  } catch { return []; }
}

function parseGoSum(content: string): Array<{ name: string; version: string; ecosystem: string }> {
  const seen = new Set<string>();
  return content.split('\n')
    .map((l) => {
      const m = l.match(/^(\S+)\s+v([^\s/]+)/);
      if (!m) return null;
      const key = `${m[1]}@${m[2]}`;
      if (seen.has(key)) return null;
      seen.add(key);
      return { name: m[1], version: m[2], ecosystem: 'Go' };
    })
    .filter((x): x is NonNullable<typeof x> => !!x);
}

function parseCargoLock(content: string): Array<{ name: string; version: string; ecosystem: string }> {
  const deps: Array<{ name: string; version: string; ecosystem: string }> = [];
  const regex = /\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g;
  let match;
  while ((match = regex.exec(content))) {
    deps.push({ name: match[1], version: match[2], ecosystem: 'crates.io' });
  }
  return deps;
}

function parseGemfileLock(content: string): Array<{ name: string; version: string; ecosystem: string }> {
  const deps: Array<{ name: string; version: string; ecosystem: string }> = [];
  const regex = /^\s{4}(\S+)\s+\(([^)]+)\)/gm;
  let match;
  while ((match = regex.exec(content))) {
    deps.push({ name: match[1], version: match[2], ecosystem: 'RubyGems' });
  }
  return deps;
}

function parsePomXml(content: string): Array<{ name: string; version: string; ecosystem: string }> {
  const deps: Array<{ name: string; version: string; ecosystem: string }> = [];
  const regex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<$]+)<\/version>/g;
  let match;
  while ((match = regex.exec(content))) {
    deps.push({ name: `${match[1]}:${match[2]}`, version: match[3], ecosystem: 'Maven' });
  }
  return deps;
}

function parseComposerLock(content: string): Array<{ name: string; version: string; ecosystem: string }> {
  try {
    const lock = JSON.parse(content);
    return (lock.packages ?? []).map((p: { name: string; version: string }) => ({
      name: p.name,
      version: p.version.replace(/^v/, ''),
      ecosystem: 'Packagist',
    }));
  } catch { return []; }
}

async function queryOSV(ecosystem: string, name: string, version: string): Promise<OSVVulnerability[]> {
  try {
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: { name, ecosystem },
        version,
      }),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as OSVResponse;
    return data.vulns ?? [];
  } catch { return []; }
}

function osvSeverityToSeverity(vuln: OSVVulnerability): Severity {
  const score = vuln.severity?.[0]?.score;
  if (!score) return Severity.Medium;
  const n = parseFloat(score);
  if (n >= 9.0) return Severity.Critical;
  if (n >= 7.0) return Severity.High;
  if (n >= 4.0) return Severity.Medium;
  return Severity.Low;
}

export class SCAScanner {
  async scan(targetPath: string): Promise<{ findings: Finding[]; depsScanned: number }> {
    const findings: Finding[] = [];
    let depsScanned = 0;

    // Find all lockfiles
    const files = await glob('**/*', { cwd: targetPath, nodir: true, dot: false });

    for (const file of files) {
      const name = basename(file);
      const parser = LOCKFILE_PARSERS[name];
      if (!parser) continue;

      const fullPath = join(targetPath, file);
      if (!existsSync(fullPath)) continue;

      let content: string;
      try {
        content = readFileSync(fullPath, 'utf-8');
      } catch { continue; }

      const deps = parser(content);
      depsScanned += deps.length;

      // Batch query OSV (up to 10 concurrent)
      const batchSize = 10;
      for (let i = 0; i < deps.length; i += batchSize) {
        const batch = deps.slice(i, i + batchSize);
        const results = await Promise.all(
          batch.map((d) => queryOSV(d.ecosystem, d.name, d.version))
        );

        for (let j = 0; j < batch.length; j++) {
          const dep = batch[j];
          const vulns = results[j];
          for (const vuln of vulns) {
            const cve = vuln.aliases?.find((a) => a.startsWith('CVE-')) ?? vuln.id;
            findings.push({
              file,
              line: 1,
              column: 1,
              severity: osvSeverityToSeverity(vuln),
              category: 'Vulnerable Dependency',
              message: `${dep.name}@${dep.version}: ${vuln.summary ?? cve}`,
              rule: `SCA_${vuln.id}`,
              snippet: `${dep.ecosystem}/${dep.name}@${dep.version}`,
              cwe: 'CWE-1395',
              owasp: 'A06:2021',
              fix: vuln.affected?.[0]?.ranges?.[0]?.events?.find((e) => e.fixed)
                ? { description: `Upgrade to ${vuln.affected[0].ranges![0].events.find((e) => e.fixed)!.fixed}` }
                : undefined,
            });
          }
        }
      }
    }

    return { findings, depsScanned };
  }
}
