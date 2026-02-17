#!/usr/bin/env node
import { resolve } from 'node:path';
import { scan } from './scanner.js';
import { formatHuman, formatJSON } from './formatter.js';
import { generateFixSuggestions, formatFixSuggestions } from './fixer.js';
import type { ScanOptions } from './types.js';

function usage(): void {
  console.log(`
🗺️  SecretMap — Unified Credential Inventory Scanner

Usage: secretmap [options] [directory]

Options:
  --json          Output as JSON
  --fix           Show fix suggestions (.gitignore entries, permission fixes)
  --no-home       Skip scanning home directory known locations
  --depth <n>     Max directory depth (default: 8)
  --verbose       Show all findings including low-risk
  -h, --help      Show this help

Examples:
  secretmap                  # Scan current dir + home
  secretmap ~/projects       # Scan specific directory
  secretmap --json .         # JSON output for piping
  secretmap --fix .          # Scan + show fix suggestions
  secretmap --no-home .      # Only scan project directory
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('-h') || args.includes('--help')) {
    usage();
    process.exit(0);
  }

  const json = args.includes('--json');
  const noHome = args.includes('--no-home');
  const verbose = args.includes('--verbose');
  const fix = args.includes('--fix');

  let maxDepth = 8;
  const depthIdx = args.indexOf('--depth');
  if (depthIdx !== -1 && args[depthIdx + 1]) {
    maxDepth = parseInt(args[depthIdx + 1], 10);
  }

  // Find the directory argument (first non-flag arg)
  const dir = args.find(a => !a.startsWith('-') && (depthIdx === -1 || args.indexOf(a) !== depthIdx + 1));

  const opts: ScanOptions = {
    rootDir: resolve(dir ?? '.'),
    maxDepth,
    includeHome: !noHome,
    verbose,
  };

  const result = await scan(opts);

  if (json) {
    const output: Record<string, unknown> = { ...result };
    if (fix) {
      output.suggestions = generateFixSuggestions(result);
    }
    console.log(JSON.stringify(output, null, 2));
  } else {
    console.log(formatHuman(result));
    if (fix) {
      const suggestions = generateFixSuggestions(result);
      console.log(formatFixSuggestions(suggestions));
    }
  }

  // Exit with error code if critical exposures found
  const hasCritical = result.exposures.some(e => e.severity === 'critical');
  process.exit(hasCritical ? 1 : 0);
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(2);
});
