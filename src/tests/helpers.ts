import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Config, Rule } from '../config.js';
import { _resetSigner } from '../signer.js';

/** A complete Config for tests that build policies in code. */
export function testConfig(over: Partial<Config> & { rules?: Rule[] } = {}): Config {
  return {
    default_action: 'allow',
    mode: 'enforce',
    rules: [],
    approval_ttl_seconds: 900,
    receipt_ttl_seconds: 900,
    policy_sha256: 'test-policy',
    ...over,
  };
}

/** Point the signer and receipt log at a fresh private temp dir. */
export function isolateKeys(): string {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-test-'));
  process.env.PP_KEYS_DIR = join(dir, 'keys');
  process.env.PP_SHARED_RECEIPTS_PATH = join(dir, 'receipts.jsonl');
  _resetSigner();
  return dir;
}
