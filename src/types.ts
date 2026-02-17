export interface CredentialEntry {
  /** Human-readable name or key */
  name: string;
  /** File path where found */
  location: string;
  /** Category of credential */
  type: CredentialType;
  /** How it was detected */
  source: SourceType;
  /** Risk level 1-10 */
  risk: number;
  /** Risk explanation */
  riskReason: string;
  /** File modification time (ISO) */
  lastModified: string;
  /** Days since last modified */
  ageDays: number;
  /** Is the value actually present (not empty/placeholder) */
  hasValue: boolean;
  /** Masked preview of the value */
  maskedValue?: string;
}

export type CredentialType =
  | 'api-key'
  | 'token'
  | 'password'
  | 'secret'
  | 'certificate'
  | 'ssh-key'
  | 'oauth-token'
  | 'connection-string'
  | 'env-var'
  | 'unknown';

export type SourceType =
  | 'env-file'
  | 'json-config'
  | 'yaml-config'
  | 'toml-config'
  | 'ssh-directory'
  | 'npmrc'
  | 'pypirc'
  | 'git-credentials'
  | 'ai-agent-config'
  | 'encrypted-file'
  | 'keychain-ref'
  | 'shell-config';

export interface ScanResult {
  scanTime: string;
  scanDurationMs: number;
  rootDir: string;
  totalFound: number;
  highRisk: number;
  credentials: CredentialEntry[];
  exposures: Exposure[];
}

export interface Exposure {
  type: 'git-tracked' | 'world-readable' | 'no-gitignore' | 'plaintext-password' | 'expired-token';
  location: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface ScanOptions {
  rootDir: string;
  maxDepth: number;
  includeHome: boolean;
  verbose: boolean;
}

export interface FixSuggestion {
  type: 'gitignore' | 'permission' | 'env-example' | 'rotation';
  location: string;
  description: string;
  command?: string;
}
