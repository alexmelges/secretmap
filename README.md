# 🗺️ SecretMap

[![npm version](https://img.shields.io/npm/v/secretmap)](https://www.npmjs.com/package/secretmap)
[![license](https://img.shields.io/npm/l/secretmap)](https://github.com/alexmelges/secretmap/blob/main/LICENSE)
[![node](https://img.shields.io/node/v/secretmap)](https://nodejs.org)

**Unified credential inventory scanner for dev environments and AI agents.**

SecretMap scans your filesystem for scattered credentials — `.env` files, config files, SSH keys, AI agent configs, package manager tokens — and gives you a single inventory with risk scores.

## Why?

Developers scatter secrets across dozens of locations. During migrations, rotations, or security audits, there's no single view of "where are all my secrets?" Existing tools are either cloud-first secret managers (Doppler, Infisical) or git-focused leak scanners (truffleHog, detect-secrets). Nothing does offline, filesystem-wide credential discovery with AI agent config awareness.

## Install

```bash
npm install -g secretmap
# or
npx secretmap
```

## Usage

```bash
# Scan current directory + home directory known locations
secretmap

# Scan specific directory
secretmap ~/projects

# JSON output for piping
secretmap --json .

# Show fix suggestions
secretmap --fix .

# Skip home directory scan
secretmap --no-home .

# Limit depth
secretmap --depth 3 ~/projects
```

## Real-World Examples

### Finding scattered credentials

```
🗺️  SecretMap Scan Results
Scanned: /Users/dev/projects
Summary: 12 credentials found, 4 high-risk
⚠️  2 exposure(s) detected

━━━ Exposures ━━━
  [CRITICAL] OPENAI_API_KEY in .env is tracked by git with a real value
  [HIGH] .env file found but .gitignore doesn't include .env pattern

━━━ Credentials Inventory ━━━
  [env-file]
    ● OPENAI_API_KEY sk-p****Kx3m (142d old)
    ● SUPABASE_SERVICE_ROLE_KEY eyJh****...
    ● RESEND_API_KEY re_1****abc
    ○ DATABASE_URL (empty/placeholder)
```

### Fix suggestions mode

```bash
secretmap --fix .
```

```
━━━ Fix Suggestions ━━━

  📄 .gitignore
    Add .env pattern to .gitignore in .
    $ echo '.env*' >> ./.gitignore

  🔒 Permissions
    Fix permissions on id_rsa (should be 600)
    $ chmod 600 ~/.ssh/id_rsa

  📋 .env.example
    Create .env.example with placeholder values for safe sharing
    $ sed 's/=.*/=/' .env > .env.example

  🔄 Rotation
    Rotate AWS_SECRET_ACCESS_KEY — last modified 412 days ago
```

## What it scans

- **Environment files**: `.env`, `.env.local`, `.env.production`, etc.
- **JSON/YAML configs**: Any config file with credential-like keys
- **Home directory**: `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.aws/credentials`, `.docker/config.json`, `.kube/config`
- **SSH keys**: `~/.ssh/id_*`
- **AI agent configs**: OpenClaw, Claude Code, Cursor MCP, GitHub CLI
- **Shell configs**: `.zshrc`, `.bashrc`, `.profile` (for exported secrets)
- **Encrypted files**: `*.enc.json` etc. (noted as lower risk)

## Supported credential patterns (60+)

- **Cloud providers**: AWS, GCP, Azure, Cloudflare
- **Databases**: PostgreSQL, MongoDB, Redis, PlanetScale, Turso, Neon, Upstash
- **Platforms**: Railway, Vercel, Netlify, Supabase, Firebase
- **Email/SMS**: Resend, SendGrid, Postmark, Twilio
- **Auth**: Clerk, JWT secrets, OAuth tokens
- **AI services**: OpenAI, Anthropic, ElevenLabs
- **Dev tools**: GitHub, NPM, Stripe, Sentry
- **General**: API keys, tokens, passwords, SSH keys, connection strings

## What it detects

- **Real vs placeholder values**: Distinguishes `API_KEY=sk-real123` from `API_KEY=your_key_here`
- **Known secret patterns**: AWS keys (`AKIA...`), GitHub tokens (`ghp_...`), Resend keys (`re_...`), JWTs, private key blocks
- **Exposure risks**: Git-tracked secrets, world-readable SSH keys, missing `.gitignore`
- **Age**: Flags credentials not rotated in >180 days

## CI Integration

### GitHub Actions

```yaml
- name: Secret scan
  run: npx secretmap --no-home --json . | jq '.exposures[] | select(.severity == "critical")'
```

### Pre-commit hook

```bash
#!/bin/sh
npx secretmap --no-home . 2>/dev/null
```

## Programmatic API

```typescript
import { scan, generateFixSuggestions } from 'secretmap';

const result = await scan({
  rootDir: './my-project',
  maxDepth: 8,
  includeHome: false,
  verbose: false,
});

console.log(`Found ${result.totalFound} credentials, ${result.highRisk} high-risk`);

const suggestions = generateFixSuggestions(result);
for (const s of suggestions) {
  console.log(`${s.type}: ${s.description}`);
  if (s.command) console.log(`  $ ${s.command}`);
}
```

## Exit codes

- `0`: Scan complete, no critical exposures
- `1`: Critical exposures found (git-tracked secrets, world-readable keys)
- `2`: Scanner error

## License

MIT
