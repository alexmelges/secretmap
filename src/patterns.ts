import type { CredentialType, SourceType } from './types.js';

/** Pattern for detecting credential keys in env/config files */
export interface CredentialPattern {
  /** Regex to match the key name */
  keyPattern: RegExp;
  /** What type of credential this is */
  type: CredentialType;
  /** Base risk score (modified by context) */
  baseRisk: number;
}

/** Well-known credential key patterns */
export const KEY_PATTERNS: CredentialPattern[] = [
  { keyPattern: /(?:^|_)API[_-]?KEY$/i, type: 'api-key', baseRisk: 7 },
  { keyPattern: /(?:^|_)SECRET[_-]?KEY$/i, type: 'secret', baseRisk: 8 },
  { keyPattern: /(?:^|_)ACCESS[_-]?KEY/i, type: 'api-key', baseRisk: 7 },
  { keyPattern: /(?:^|_)AUTH[_-]?TOKEN$/i, type: 'token', baseRisk: 8 },
  { keyPattern: /(?:^|_)TOKEN$/i, type: 'token', baseRisk: 6 },
  { keyPattern: /(?:^|_)PASSWORD$/i, type: 'password', baseRisk: 9 },
  { keyPattern: /(?:^|_)PASSWD$/i, type: 'password', baseRisk: 9 },
  { keyPattern: /(?:^|_)SECRET$/i, type: 'secret', baseRisk: 8 },
  { keyPattern: /(?:^|_)PRIVATE[_-]?KEY/i, type: 'secret', baseRisk: 9 },
  { keyPattern: /(?:^|_)CLIENT[_-]?SECRET/i, type: 'secret', baseRisk: 8 },
  { keyPattern: /(?:^|_)REFRESH[_-]?TOKEN/i, type: 'oauth-token', baseRisk: 8 },
  { keyPattern: /(?:^|_)ACCESS[_-]?TOKEN/i, type: 'oauth-token', baseRisk: 8 },
  { keyPattern: /(?:^|_)DATABASE[_-]?URL$/i, type: 'connection-string', baseRisk: 9 },
  { keyPattern: /(?:^|_)REDIS[_-]?URL$/i, type: 'connection-string', baseRisk: 7 },
  { keyPattern: /(?:^|_)MONGODB[_-]?URI$/i, type: 'connection-string', baseRisk: 8 },
  { keyPattern: /(?:^|_)CONNECTION[_-]?STRING$/i, type: 'connection-string', baseRisk: 8 },
  { keyPattern: /(?:^|_)WEBHOOK[_-]?(?:URL|SECRET)/i, type: 'secret', baseRisk: 6 },
  { keyPattern: /(?:^|_)SIGNING[_-]?(?:KEY|SECRET)/i, type: 'secret', baseRisk: 9 },
  { keyPattern: /(?:^|_)ENCRYPTION[_-]?KEY/i, type: 'secret', baseRisk: 9 },
  { keyPattern: /(?:^|_)JWT[_-]?SECRET/i, type: 'secret', baseRisk: 9 },
  { keyPattern: /(?:^|_)SMTP[_-]?PASS/i, type: 'password', baseRisk: 7 },
  { keyPattern: /(?:^|_)AWS[_-]?SECRET/i, type: 'secret', baseRisk: 9 },
  { keyPattern: /(?:^|_)GCP[_-]?(?:KEY|CREDENTIALS)/i, type: 'api-key', baseRisk: 8 },
  { keyPattern: /(?:^|_)AZURE[_-]?(?:KEY|SECRET)/i, type: 'secret', baseRisk: 8 },
  { keyPattern: /OPENAI[_-]?API[_-]?KEY/i, type: 'api-key', baseRisk: 8 },
  { keyPattern: /ANTHROPIC[_-]?API[_-]?KEY/i, type: 'api-key', baseRisk: 8 },
  { keyPattern: /ELEVENLABS[_-]?API[_-]?KEY/i, type: 'api-key', baseRisk: 7 },
  { keyPattern: /BRAVE[_-]?SEARCH[_-]?API[_-]?KEY/i, type: 'api-key', baseRisk: 6 },
  { keyPattern: /STRIPE[_-]?(?:SECRET|KEY)/i, type: 'api-key', baseRisk: 9 },
  { keyPattern: /GITHUB[_-]?TOKEN/i, type: 'token', baseRisk: 8 },
  { keyPattern: /NPM[_-]?TOKEN/i, type: 'token', baseRisk: 7 },
  { keyPattern: /VERCEL[_-]?TOKEN/i, type: 'token', baseRisk: 7 },
  { keyPattern: /NETLIFY[_-]?(?:TOKEN|AUTH)/i, type: 'token', baseRisk: 7 },
  { keyPattern: /RAILWAY[_-]?TOKEN/i, type: 'token', baseRisk: 7 },
  { keyPattern: /SUPABASE[_-]?(?:KEY|SECRET|URL)/i, type: 'api-key', baseRisk: 7 },
  { keyPattern: /FIREBASE[_-]?(?:KEY|TOKEN|SECRET)/i, type: 'api-key', baseRisk: 7 },
];

/** Value patterns that look like real secrets (not placeholders) */
export const VALUE_PATTERNS = {
  placeholder: /^(xxx|your[_-]|changeme|TODO|FIXME|replace|<|dummy|test|example|null|undefined|none|false|true|\$\{)/i,
  awsKey: /^AKIA[0-9A-Z]{16}$/,
  githubToken: /^gh[ps]_[A-Za-z0-9_]{36,}$/,
  npmToken: /^npm_[A-Za-z0-9]{36,}$/,
  base64Long: /^[A-Za-z0-9+/=]{40,}$/,
  jwt: /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  hexKey: /^[0-9a-f]{32,}$/i,
  privateKeyBlock: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
};

/** Files/dirs to always skip */
export const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '__pycache__',
  '.next', '.nuxt', '.output', 'vendor', '.cache',
  'coverage', '.turbo', '.vercel',
]);

/** Well-known credential file locations relative to a project or home */
export interface KnownLocation {
  /** Glob-like path (relative to scan root or ~) */
  path: string;
  /** Source classification */
  source: SourceType;
  /** Whether this is relative to home directory */
  isHome: boolean;
  /** Description */
  description: string;
}

export const KNOWN_LOCATIONS: KnownLocation[] = [
  // Project-level
  { path: '.env', source: 'env-file', isHome: false, description: 'Environment variables' },
  { path: '.env.local', source: 'env-file', isHome: false, description: 'Local env overrides' },
  { path: '.env.development', source: 'env-file', isHome: false, description: 'Dev environment' },
  { path: '.env.production', source: 'env-file', isHome: false, description: 'Production environment' },
  { path: '.env.staging', source: 'env-file', isHome: false, description: 'Staging environment' },
  { path: '.env.test', source: 'env-file', isHome: false, description: 'Test environment' },

  // Home-level configs
  { path: '.npmrc', source: 'npmrc', isHome: true, description: 'NPM config (may contain auth tokens)' },
  { path: '.pypirc', source: 'pypirc', isHome: true, description: 'PyPI config (may contain passwords)' },
  { path: '.netrc', source: 'git-credentials', isHome: true, description: 'Network credentials' },
  { path: '.git-credentials', source: 'git-credentials', isHome: true, description: 'Git stored credentials' },
  { path: '.docker/config.json', source: 'json-config', isHome: true, description: 'Docker auth' },
  { path: '.kube/config', source: 'yaml-config', isHome: true, description: 'Kubernetes config' },
  { path: '.aws/credentials', source: 'toml-config', isHome: true, description: 'AWS credentials' },

  // SSH
  { path: '.ssh/id_rsa', source: 'ssh-directory', isHome: true, description: 'RSA private key' },
  { path: '.ssh/id_ed25519', source: 'ssh-directory', isHome: true, description: 'Ed25519 private key' },
  { path: '.ssh/id_ecdsa', source: 'ssh-directory', isHome: true, description: 'ECDSA private key' },

  // AI agent configs
  { path: '.openclaw/openclaw.json', source: 'ai-agent-config', isHome: true, description: 'OpenClaw config' },
  { path: '.openclaw/workspace/.credentials', source: 'ai-agent-config', isHome: true, description: 'OpenClaw credentials dir' },
  { path: '.cursor/mcp.json', source: 'ai-agent-config', isHome: true, description: 'Cursor MCP config' },
  { path: '.config/claude/config.json', source: 'ai-agent-config', isHome: true, description: 'Claude Code config' },
  { path: '.claude/settings.json', source: 'ai-agent-config', isHome: true, description: 'Claude settings' },
  { path: '.config/gh/hosts.yml', source: 'ai-agent-config', isHome: true, description: 'GitHub CLI auth' },

  // Shell configs (may export secrets)
  { path: '.zshrc', source: 'shell-config', isHome: true, description: 'Zsh config' },
  { path: '.bashrc', source: 'shell-config', isHome: true, description: 'Bash config' },
  { path: '.bash_profile', source: 'shell-config', isHome: true, description: 'Bash profile' },
  { path: '.zshenv', source: 'shell-config', isHome: true, description: 'Zsh environment' },
  { path: '.profile', source: 'shell-config', isHome: true, description: 'Shell profile' },
];
