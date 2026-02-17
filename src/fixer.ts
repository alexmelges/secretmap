import { dirname, basename, relative } from 'node:path';
import type { ScanResult, FixSuggestion, Exposure, CredentialEntry } from './types.js';

/** Generate fix suggestions for scan results. */
export function generateFixSuggestions(result: ScanResult): FixSuggestion[] {
  const suggestions: FixSuggestion[] = [];

  // Suggest .gitignore entries for exposures
  for (const exposure of result.exposures) {
    if (exposure.type === 'no-gitignore') {
      const rel = relative(result.rootDir, exposure.location);
      const dir = dirname(exposure.location);
      suggestions.push({
        type: 'gitignore',
        location: exposure.location,
        description: `Add .env pattern to .gitignore in ${dirname(rel) || '.'}`,
        command: `echo '.env*' >> ${dir}/.gitignore`,
      });
    }

    if (exposure.type === 'world-readable') {
      suggestions.push({
        type: 'permission',
        location: exposure.location,
        description: `Fix permissions on ${basename(exposure.location)} (should be 600)`,
        command: `chmod 600 ${exposure.location}`,
      });
    }

    if (exposure.type === 'git-tracked') {
      const rel = relative(result.rootDir, exposure.location);
      suggestions.push({
        type: 'gitignore',
        location: exposure.location,
        description: `Remove ${rel} from git tracking and add to .gitignore`,
        command: `git rm --cached ${rel} && echo '${rel}' >> .gitignore`,
      });
    }
  }

  // Suggest .env.example for env files with real values
  const envFiles = new Set<string>();
  for (const cred of result.credentials) {
    if (cred.source === 'env-file' && cred.hasValue) {
      envFiles.add(cred.location);
    }
  }
  for (const envFile of envFiles) {
    const rel = relative(result.rootDir, envFile);
    suggestions.push({
      type: 'env-example',
      location: envFile,
      description: `Create ${rel}.example with placeholder values for safe sharing`,
      command: `sed 's/=.*/=/' ${envFile} > ${envFile}.example`,
    });
  }

  // Suggest rotation for old credentials
  for (const cred of result.credentials) {
    if (cred.hasValue && cred.ageDays > 365) {
      suggestions.push({
        type: 'rotation',
        location: cred.location,
        description: `Rotate ${cred.name} — last modified ${cred.ageDays} days ago`,
      });
    }
  }

  return suggestions;
}

/** Format fix suggestions for human output. */
export function formatFixSuggestions(suggestions: FixSuggestion[]): string {
  if (suggestions.length === 0) return '';

  const BOLD = '\x1b[1m';
  const DIM = '\x1b[2m';
  const RESET = '\x1b[0m';
  const CYAN = '\x1b[36m';

  const lines: string[] = [
    '',
    `${BOLD}━━━ Fix Suggestions ━━━${RESET}`,
    '',
  ];

  const byType = new Map<string, FixSuggestion[]>();
  for (const s of suggestions) {
    const group = byType.get(s.type) ?? [];
    group.push(s);
    byType.set(s.type, group);
  }

  const labels: Record<string, string> = {
    gitignore: '📄 .gitignore',
    permission: '🔒 Permissions',
    'env-example': '📋 .env.example',
    rotation: '🔄 Rotation',
  };

  for (const [type, sugs] of byType) {
    lines.push(`  ${BOLD}${labels[type] ?? type}${RESET}`);
    for (const s of sugs) {
      lines.push(`    ${s.description}`);
      if (s.command) {
        lines.push(`    ${CYAN}$ ${s.command}${RESET}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}
