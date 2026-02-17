import type { ScanResult, CredentialEntry, Exposure } from './types.js';

const RISK_COLORS: Record<string, string> = {
  critical: '\x1b[91m',  // bright red
  high: '\x1b[31m',      // red
  medium: '\x1b[33m',    // yellow
  low: '\x1b[32m',       // green
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

export function formatHuman(result: ScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${BOLD}🗺️  SecretMap Scan Results${RESET}`);
  lines.push(`${DIM}Scanned: ${result.rootDir}${RESET}`);
  lines.push(`${DIM}Time: ${result.scanTime} (${result.scanDurationMs}ms)${RESET}`);
  lines.push('');

  // Summary
  lines.push(`${BOLD}Summary:${RESET} ${result.totalFound} credentials found, ${riskBadge(result.highRisk)} high-risk`);
  if (result.exposures.length > 0) {
    lines.push(`${BOLD}⚠️  ${result.exposures.length} exposure(s) detected${RESET}`);
  }
  lines.push('');

  // Exposures first
  if (result.exposures.length > 0) {
    lines.push(`${BOLD}━━━ Exposures ━━━${RESET}`);
    for (const exp of result.exposures) {
      const color = RISK_COLORS[exp.severity] ?? '';
      lines.push(`  ${color}[${exp.severity.toUpperCase()}]${RESET} ${exp.description}`);
      lines.push(`  ${DIM}${exp.location}${RESET}`);
      lines.push('');
    }
  }

  // Credentials table
  if (result.credentials.length > 0) {
    lines.push(`${BOLD}━━━ Credentials Inventory ━━━${RESET}`);
    lines.push('');

    // Group by source
    const bySource = new Map<string, CredentialEntry[]>();
    for (const cred of result.credentials) {
      const group = bySource.get(cred.source) ?? [];
      group.push(cred);
      bySource.set(cred.source, group);
    }

    for (const [source, creds] of bySource) {
      lines.push(`  ${BOLD}[${source}]${RESET}`);
      for (const c of creds) {
        const riskStr = riskIndicator(c.risk);
        const valueStr = c.hasValue
          ? (c.maskedValue ? `${DIM}${c.maskedValue}${RESET}` : '(has value)')
          : `${DIM}(empty/placeholder)${RESET}`;
        const ageStr = c.ageDays > 180 ? ` ${DIM}(${c.ageDays}d old)${RESET}` : '';
        lines.push(`    ${riskStr} ${c.name} ${valueStr}${ageStr}`);
        lines.push(`      ${DIM}${c.location}${RESET}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

function riskIndicator(risk: number): string {
  if (risk >= 8) return '\x1b[91m●\x1b[0m';
  if (risk >= 6) return '\x1b[33m●\x1b[0m';
  if (risk >= 4) return '\x1b[32m●\x1b[0m';
  return '\x1b[2m○\x1b[0m';
}

function riskBadge(count: number): string {
  if (count === 0) return '\x1b[32m0\x1b[0m';
  return `\x1b[91m${count}\x1b[0m`;
}

export function formatJSON(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
