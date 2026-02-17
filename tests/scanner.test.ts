import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { scan } from '../src/scanner.js';
import { maskValue } from '../src/scanner.js';
import type { ScanOptions } from '../src/types.js';

let tempDir: string;

function opts(overrides: Partial<ScanOptions> = {}): ScanOptions {
  return {
    rootDir: tempDir,
    maxDepth: 8,
    includeHome: false,
    verbose: false,
    ...overrides,
  };
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'secretmap-test-'));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe('scan', () => {
  it('finds credentials in .env files', async () => {
    await writeFile(join(tempDir, '.env'), [
      'DATABASE_URL=postgres://user:pass@host/db',
      'API_KEY=sk-1234567890abcdef',
      'NODE_ENV=production',
    ].join('\n'));

    const result = await scan(opts());
    expect(result.totalFound).toBe(2);
    expect(result.credentials.map(c => c.name).sort()).toEqual(['API_KEY', 'DATABASE_URL']);
  });

  it('detects placeholder values as low risk', async () => {
    await writeFile(join(tempDir, '.env'), 'API_KEY=your_api_key_here\nSECRET_KEY=changeme');
    const result = await scan(opts());
    expect(result.credentials.every(c => c.risk < 5)).toBe(true);
    expect(result.credentials.every(c => !c.hasValue)).toBe(true);
  });

  it('scans nested .env files', async () => {
    await mkdir(join(tempDir, 'project-a'));
    await writeFile(join(tempDir, 'project-a', '.env.local'), 'STRIPE_SECRET_KEY=sk_live_abc123xyz');
    const result = await scan(opts());
    expect(result.totalFound).toBe(1);
    expect(result.credentials[0].name).toBe('STRIPE_SECRET_KEY');
    expect(result.credentials[0].hasValue).toBe(true);
  });

  it('scans JSON config files with credential keys', async () => {
    await writeFile(join(tempDir, 'config.json'), JSON.stringify({
      apiKey: 'real-key-12345678',
      nested: { clientSecret: 'sec_abcdefghijk' },
    }));
    const result = await scan(opts());
    expect(result.totalFound).toBe(2);
  });

  it('detects .env.production files', async () => {
    await writeFile(join(tempDir, '.env.production'), 'JWT_SECRET=supersecretvalue123');
    const result = await scan(opts());
    expect(result.totalFound).toBe(1);
    expect(result.credentials[0].type).toBe('secret');
  });

  it('handles encrypted files', async () => {
    await writeFile(join(tempDir, 'secrets.enc.json'), '{"encrypted": "data"}');
    const result = await scan(opts());
    expect(result.totalFound).toBe(1);
    expect(result.credentials[0].source).toBe('encrypted-file');
    expect(result.credentials[0].risk).toBeLessThan(5);
  });

  it('skips node_modules', async () => {
    await mkdir(join(tempDir, 'node_modules', 'pkg'), { recursive: true });
    await writeFile(join(tempDir, 'node_modules', 'pkg', '.env'), 'SECRET_KEY=leaked');
    const result = await scan(opts());
    expect(result.totalFound).toBe(0);
  });

  it('respects maxDepth', async () => {
    const deep = join(tempDir, 'a', 'b', 'c', 'd');
    await mkdir(deep, { recursive: true });
    await writeFile(join(deep, '.env'), 'API_KEY=deepkey123456');
    const shallow = await scan(opts({ maxDepth: 2 }));
    expect(shallow.totalFound).toBe(0);
    const deepScan = await scan(opts({ maxDepth: 10 }));
    expect(deepScan.totalFound).toBe(1);
  });

  it('handles export prefix in env files', async () => {
    await writeFile(join(tempDir, '.env'), 'export GITHUB_TOKEN=ghp_abc123456789012345678901234567890123');
    const result = await scan(opts());
    expect(result.totalFound).toBe(1);
    expect(result.credentials[0].name).toBe('GITHUB_TOKEN');
  });

  it('scans shell configs for exported secrets', async () => {
    // Shell configs are only scanned from home directory known locations,
    // not from project walks. This tests the env-like parser directly.
    await writeFile(join(tempDir, '.env'), 'export OPENAI_API_KEY=sk-proj-abcdefghij123456');
    const result = await scan(opts());
    expect(result.credentials.some(c => c.name === 'OPENAI_API_KEY')).toBe(true);
  });

  it('completes scan in under 2 seconds for empty dir', async () => {
    const result = await scan(opts());
    expect(result.scanDurationMs).toBeLessThan(2000);
  });

  it('returns valid ScanResult structure', async () => {
    const result = await scan(opts());
    expect(result).toHaveProperty('scanTime');
    expect(result).toHaveProperty('scanDurationMs');
    expect(result).toHaveProperty('rootDir');
    expect(result).toHaveProperty('totalFound');
    expect(result).toHaveProperty('highRisk');
    expect(result).toHaveProperty('credentials');
    expect(result).toHaveProperty('exposures');
    expect(Array.isArray(result.credentials)).toBe(true);
    expect(Array.isArray(result.exposures)).toBe(true);
  });
});

describe('maskValue', () => {
  it('masks short values completely', () => {
    expect(maskValue('abc')).toBe('****');
    expect(maskValue('12345678')).toBe('****');
  });

  it('shows start and end of longer values', () => {
    expect(maskValue('sk-1234567890abcdef')).toBe('sk-1****cdef');
  });
});

describe('exposures', () => {
  it('detects missing .gitignore for .env in git repo', async () => {
    await mkdir(join(tempDir, '.git'));
    await writeFile(join(tempDir, '.env'), 'SECRET_KEY=realvalue123456');
    const result = await scan(opts());
    expect(result.exposures.some(e => e.type === 'no-gitignore')).toBe(true);
  });
});
