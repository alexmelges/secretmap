# 🗺️ SecretMap

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

# Skip home directory scan
secretmap --no-home .

# Limit depth
secretmap --depth 3 ~/projects
```

## What it scans

- **Environment files**: `.env`, `.env.local`, `.env.production`, etc.
- **JSON/YAML configs**: Any config file with credential-like keys
- **Home directory**: `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.aws/credentials`, `.docker/config.json`, `.kube/config`
- **SSH keys**: `~/.ssh/id_*`
- **AI agent configs**: OpenClaw, Claude Code, Cursor MCP, GitHub CLI
- **Shell configs**: `.zshrc`, `.bashrc`, `.profile` (for exported secrets)
- **Encrypted files**: `*.enc.json` etc. (noted as lower risk)

## What it detects

- **Real vs placeholder values**: Distinguishes `API_KEY=sk-real123` from `API_KEY=your_key_here`
- **Known secret patterns**: AWS keys, GitHub tokens, JWTs, private key blocks
- **Exposure risks**: Git-tracked secrets, world-readable SSH keys, missing `.gitignore`
- **Age**: Flags credentials not rotated in >180 days

## Output

Human-readable (default) with color-coded risk indicators, or `--json` for structured output.

Each credential entry includes:
- `name`: Key name or identifier
- `location`: File path
- `type`: api-key, token, password, secret, ssh-key, etc.
- `source`: env-file, json-config, ssh-directory, ai-agent-config, etc.
- `risk`: 1-10 score
- `ageDays`: Days since file was modified
- `hasValue`: Whether it contains a real (non-placeholder) value
- `maskedValue`: Preview with middle characters hidden

## Exit codes

- `0`: Scan complete, no critical exposures
- `1`: Critical exposures found (git-tracked secrets, world-readable keys)
- `2`: Scanner error

## License

MIT
