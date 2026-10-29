// Demo runs sign with a throwaway demo key (id mcpg-demo-…, receipts carry scope "demo")
// in a fresh temp directory, never the operator's real keys. Gates in the demos pin it
// with --keys/--trust and pass --allow-demo, since a demo receipt authorizes nothing real.
import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

let created = null;

/** Point PP_KEYS_DIR at a fresh demo key for this process (an existing PP_KEYS_DIR is ignored). */
export function demoKeys() {
  if (created) return created;
  process.env.PP_KEYS_DIR = join(mkdtempSync(join(tmpdir(), 'mcp-guard-demo-')), 'keys');
  const out = execFileSync('node', [join(ROOT, 'dist/src/cli.js'), 'keys', 'init', '--demo'], { stdio: 'pipe' }).toString();
  const trust = out.match(/--trust (\S+=sha256:[0-9a-f]{64})/)[1];
  const keys = join(process.env.PP_KEYS_DIR, 'keys.json');
  created = { dir: process.env.PP_KEYS_DIR, keys, trust, gateArgs: ['--keys', keys, '--trust', trust, '--allow-demo'] };
  return created;
}
