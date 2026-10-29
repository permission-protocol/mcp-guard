import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Config, Rule } from '../config.js';
import { createKey } from '../keystore.js';
import { Issuer } from '../issuer.js';
import { _resetReceiptLog } from '../receipt-log.js';

/** A complete Config for tests that build policies in code. */
export function testConfig(over: Partial<Config> & { rules?: Rule[] } = {}): Config {
  return {
    default_action: 'allow',
    mode: 'enforce',
    rules: [],
    approval_ttl_seconds: 900,
    receipt_ttl_seconds: 3600,
    scoped_receipt_ttl_seconds: 900,
    server_label: 'test-server',
    signing: 'required',
    policy_sha256: 'a'.repeat(64),
    ...over,
  };
}

/**
 * Point the keystore and receipt log at a fresh private temp dir. Creates a signing key
 * unless `init` is false (a guard never creates one itself).
 */
export function isolateKeys(opts: { init?: boolean; demo?: boolean } = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-test-'));
  process.env.PP_KEYS_DIR = join(dir, 'keys');
  process.env.PP_SHARED_RECEIPTS_PATH = join(dir, 'receipts.jsonl');
  _resetReceiptLog();
  if (opts.init !== false) createKey({ demo: opts.demo });
  return dir;
}

export function testIssuer(over: Partial<Config> = {}, agentId = 'agent'): Issuer {
  return new Issuer({ config: testConfig(over), agentId });
}
