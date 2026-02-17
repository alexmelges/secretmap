import { readdir, readFile, stat, access } from 'node:fs/promises';
import { join, basename, relative } from 'node:path';
import { homedir } from 'node:os';
import type {
  CredentialEntry, ScanResult, ScanOptions, Exposure,
  CredentialType, SourceType,
} from './types.js';
import {
  KEY_PATTERNS, VALUE_PATTERNS, SKIP_DIRS,
  KNOWN_LOCATIONS,
} from './patterns.js';

const ENV_FILE_RE = /^\.env(\..+)?$/;
const JSON_CONFIG_RE = /\.(json|jsonc)$/;
const ENC_FILE_RE = /\.enc\.(json|yaml|yml|toml)$/;

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const start = Date.now();
  const credentials: CredentialEntry[] = [];
  const exposures: Exposure[] = [];
  const home = homedir();

  // 1. Scan known home locations
  if (opts.includeHome) {
    for (const loc of KNOWN_LOCATIONS) {
      if (!loc.isHome) continue;
      const fullPath = join(home, loc.path);
      try {
        await access(fullPath);
        const entries = await scanFile(fullPath, loc.source, opts);
        credentials.push(...entries);
        // Check permissions
        const st = await stat(fullPath);
        const mode = st.mode & 0o777;
        if (mode & 0o044 && loc.source === 'ssh-directory') {
          exposures.push({
            type: 'world-readable',
            location: fullPath,
            description: `SSH key is world-readable (mode: ${mode.toString(8)})`,
            severity: 'critical',
          });
        }
      } catch {
        // File doesn't exist, skip
      }
    }
  }

  // 2. Walk project directory for env files and configs
  await walkDir(opts.rootDir, 0, opts.maxDepth, credentials, exposures, opts);

  // 3. Check for git-tracked secrets
  await checkGitTracked(opts.rootDir, credentials, exposures);

  const result: ScanResult = {
    scanTime: new Date().toISOString(),
    scanDurationMs: Date.now() - start,
    rootDir: opts.rootDir,
    totalFound: credentials.length,
    highRisk: credentials.filter(c => c.risk >= 7).length,
    credentials: credentials.sort((a, b) => b.risk - a.risk),
    exposures: exposures.sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity)),
  };

  return result;
}

function severityOrder(s: string): number {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return order[s] ?? 4;
}

async function walkDir(
  dir: string, depth: number, maxDepth: number,
  credentials: CredentialEntry[], exposures: Exposure[],
  opts: ScanOptions,
): Promise<void> {
  if (depth > maxDepth) return;

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.git')) continue;
      await walkDir(join(dir, entry.name), depth + 1, maxDepth, credentials, exposures, opts);
    } else if (entry.isFile()) {
      const name = entry.name;
      const fullPath = join(dir, name);

      let source: SourceType | null = null;
      if (ENV_FILE_RE.test(name)) source = 'env-file';
      else if (name === '.npmrc') source = 'npmrc';
      else if (name === '.pypirc') source = 'pypirc';
      else if (ENC_FILE_RE.test(name)) source = 'encrypted-file';
      else if (JSON_CONFIG_RE.test(name) && isConfigLike(name)) source = 'json-config';

      if (source) {
        const found = await scanFile(fullPath, source, opts);
        credentials.push(...found);

        // Check if env file might be missing from gitignore
        if (source === 'env-file') {
          const gitignorePath = join(dir, '.gitignore');
          try {
            const gitignore = await readFile(gitignorePath, 'utf-8');
            if (!gitignore.includes('.env')) {
              exposures.push({
                type: 'no-gitignore',
                location: fullPath,
                description: `.env file found but .gitignore doesn't include .env pattern`,
                severity: 'high',
              });
            }
          } catch {
            // No .gitignore — flag it if in a git repo
            try {
              await access(join(dir, '.git'));
              exposures.push({
                type: 'no-gitignore',
                location: fullPath,
                description: `No .gitignore found in git repo root — .env may be tracked`,
                severity: 'high',
              });
            } catch { /* not git root */ }
          }
        }
      }
    }
  }
}

function isConfigLike(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    lower.includes('credential') || lower.includes('secret') ||
    lower.includes('auth') || lower.includes('token') ||
    lower.includes('config') || lower.includes('mcp')
  );
}

async function scanFile(
  filePath: string, source: SourceType, opts: ScanOptions,
): Promise<CredentialEntry[]> {
  const results: CredentialEntry[] = [];
  let content: string;
  let fileStat;

  try {
    [content, fileStat] = await Promise.all([
      readFile(filePath, 'utf-8'),
      stat(filePath),
    ]);
  } catch {
    return results;
  }

  // Don't scan huge files
  if (content.length > 512 * 1024) return results;

  const lastModified = fileStat.mtime.toISOString();
  const ageDays = Math.floor((Date.now() - fileStat.mtime.getTime()) / 86400000);

  if (source === 'env-file' || source === 'shell-config') {
    parseEnvLike(content, filePath, source, lastModified, ageDays, results);
  } else if (source === 'json-config' || source === 'ai-agent-config') {
    parseJsonConfig(content, filePath, source, lastModified, ageDays, results);
  } else if (source === 'npmrc') {
    parseNpmrc(content, filePath, lastModified, ageDays, results);
  } else if (source === 'ssh-directory') {
    // Just note existence of key files
    results.push({
      name: basename(filePath),
      location: filePath,
      type: 'ssh-key',
      source,
      risk: 5,
      riskReason: 'SSH private key on disk',
      lastModified,
      ageDays,
      hasValue: true,
    });
  } else if (source === 'encrypted-file') {
    results.push({
      name: basename(filePath),
      location: filePath,
      type: 'unknown',
      source,
      risk: 3,
      riskReason: 'Encrypted credential file (lower risk if encryption is strong)',
      lastModified,
      ageDays,
      hasValue: true,
    });
  } else if (source === 'git-credentials') {
    parseGitCredentials(content, filePath, lastModified, ageDays, results);
  } else if (source === 'pypirc' || source === 'toml-config' || source === 'yaml-config') {
    // Scan for key=value patterns
    parseEnvLike(content, filePath, source, lastModified, ageDays, results);
  }

  return results;
}

function parseEnvLike(
  content: string, filePath: string, source: SourceType,
  lastModified: string, ageDays: number,
  results: CredentialEntry[],
): void {
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;

    // Handle export KEY=VALUE and KEY=VALUE
    const match = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)[\s]*=[\s]*(.*)/);
    if (!match) continue;

    const [, key, rawValue] = match;
    const value = rawValue.replace(/^["']|["']$/g, '').trim();

    const pattern = KEY_PATTERNS.find(p => p.keyPattern.test(key));
    if (!pattern) continue;

    const hasValue = value.length > 0 && !VALUE_PATTERNS.placeholder.test(value);
    let risk = pattern.baseRisk;
    if (!hasValue) risk = Math.max(1, risk - 4);
    if (ageDays > 365) risk = Math.min(10, risk + 1);

    results.push({
      name: key,
      location: filePath,
      type: pattern.type,
      source,
      risk,
      riskReason: buildRiskReason(pattern.type, hasValue, ageDays),
      lastModified,
      ageDays,
      hasValue,
      maskedValue: hasValue ? maskValue(value) : undefined,
    });
  }
}

function parseJsonConfig(
  content: string, filePath: string, source: SourceType,
  lastModified: string, ageDays: number,
  results: CredentialEntry[],
): void {
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(content);
  } catch {
    return;
  }

  extractKeysFromObj(obj, '', filePath, source, lastModified, ageDays, results);
}

function extractKeysFromObj(
  obj: Record<string, unknown>, prefix: string,
  filePath: string, source: SourceType,
  lastModified: string, ageDays: number,
  results: CredentialEntry[],
  depth = 0,
): void {
  if (depth > 10) return;
  for (const [key, val] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;

    if (val && typeof val === 'object' && !Array.isArray(val)) {
      extractKeysFromObj(val as Record<string, unknown>, fullKey, filePath, source, lastModified, ageDays, results, depth + 1);
      continue;
    }

    if (typeof val !== 'string') continue;

    const pattern = KEY_PATTERNS.find(p => p.keyPattern.test(key));
    if (!pattern) {
      // Also check if the value looks like a secret
      if (VALUE_PATTERNS.awsKey.test(val) || VALUE_PATTERNS.githubToken.test(val) ||
          VALUE_PATTERNS.privateKeyBlock.test(val) || VALUE_PATTERNS.jwt.test(val)) {
        results.push({
          name: fullKey,
          location: filePath,
          type: inferTypeFromValue(val),
          source,
          risk: 8,
          riskReason: 'Value matches known secret pattern',
          lastModified, ageDays,
          hasValue: true,
          maskedValue: maskValue(val),
        });
      }
      continue;
    }

    const hasValue = val.length > 0 && !VALUE_PATTERNS.placeholder.test(val);
    let risk = pattern.baseRisk;
    if (!hasValue) risk = Math.max(1, risk - 4);

    results.push({
      name: fullKey,
      location: filePath,
      type: pattern.type,
      source,
      risk,
      riskReason: buildRiskReason(pattern.type, hasValue, ageDays),
      lastModified, ageDays,
      hasValue,
      maskedValue: hasValue ? maskValue(val) : undefined,
    });
  }
}

function parseNpmrc(
  content: string, filePath: string,
  lastModified: string, ageDays: number,
  results: CredentialEntry[],
): void {
  for (const line of content.split('\n')) {
    if (line.includes('_authToken') || line.includes('_password') || line.includes('_auth')) {
      const match = line.match(/(?:_authToken|_password|_auth)\s*=\s*(.*)/);
      const value = match?.[1]?.trim() ?? '';
      const hasValue = value.length > 0 && !VALUE_PATTERNS.placeholder.test(value);
      results.push({
        name: line.split('=')[0].trim(),
        location: filePath,
        type: 'token',
        source: 'npmrc',
        risk: hasValue ? 7 : 3,
        riskReason: 'NPM auth token',
        lastModified, ageDays,
        hasValue,
        maskedValue: hasValue ? maskValue(value) : undefined,
      });
    }
  }
}

function parseGitCredentials(
  content: string, filePath: string,
  lastModified: string, ageDays: number,
  results: CredentialEntry[],
): void {
  for (const line of content.split('\n')) {
    const match = line.match(/https?:\/\/([^:]+):([^@]+)@(.+)/);
    if (match) {
      results.push({
        name: `git-credentials:${match[3]}`,
        location: filePath,
        type: 'password',
        source: 'git-credentials',
        risk: 8,
        riskReason: 'Plaintext git credentials',
        lastModified, ageDays,
        hasValue: true,
        maskedValue: maskValue(match[2]),
      });
    }
  }
}

async function checkGitTracked(
  rootDir: string, credentials: CredentialEntry[], exposures: Exposure[],
): Promise<void> {
  // Check if any found credential files are git-tracked
  try {
    const { execSync } = await import('node:child_process');
    const tracked = execSync('git ls-files', { cwd: rootDir, encoding: 'utf-8', timeout: 5000 })
      .split('\n').filter(Boolean);

    for (const cred of credentials) {
      const rel = relative(rootDir, cred.location);
      if (tracked.includes(rel) && cred.hasValue && cred.risk >= 5) {
        exposures.push({
          type: 'git-tracked',
          location: cred.location,
          description: `${cred.name} in ${rel} is tracked by git with a real value`,
          severity: 'critical',
        });
        cred.risk = Math.min(10, cred.risk + 2);
        cred.riskReason += ' [GIT-TRACKED]';
      }
    }
  } catch {
    // Not a git repo or git not available
  }
}

function inferTypeFromValue(val: string): CredentialType {
  if (VALUE_PATTERNS.awsKey.test(val)) return 'api-key';
  if (VALUE_PATTERNS.githubToken.test(val)) return 'token';
  if (VALUE_PATTERNS.jwt.test(val)) return 'oauth-token';
  if (VALUE_PATTERNS.privateKeyBlock.test(val)) return 'ssh-key';
  return 'secret';
}

function buildRiskReason(type: CredentialType, hasValue: boolean, ageDays: number): string {
  const parts: string[] = [];
  if (!hasValue) return 'Placeholder/empty value';
  parts.push(`${type} with real value`);
  if (ageDays > 365) parts.push(`not rotated in ${ageDays} days`);
  else if (ageDays > 180) parts.push(`${ageDays} days old`);
  return parts.join(', ');
}

export function maskValue(val: string): string {
  if (val.length <= 8) return '****';
  return val.slice(0, 4) + '****' + val.slice(-4);
}
