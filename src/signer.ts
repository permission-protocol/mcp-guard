import { createHash, createPublicKey, type KeyObject } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { keysDir } from './keystore.js';

/**
 * The mcp-guard 0.2 signing key, kept only so legacy receipts stay verifiable.
 *
 * 0.3 signs nothing with it: receipts are signed by the keys `mcp-guard keys init`
 * creates (src/keystore.ts). Nothing here creates a key.
 */

const LEGACY_PRIVATE_FILE = 'signing.private.pem';
const LEGACY_PUBLIC_FILE = 'signing.public.pem';

/** The 0.2 key id: `pp-dev-` + the first 16 hex chars of sha256(SPKI DER). */
export function keyIdForPublicKey(publicKey: KeyObject | string): string {
  const key = typeof publicKey === 'string' ? createPublicKey(publicKey) : publicKey;
  const der = key.export({ type: 'spki', format: 'der' });
  return 'pp-dev-' + createHash('sha256').update(der).digest('hex').slice(0, 16);
}

/**
 * Write the 0.2 public key to `out` so a gate can still verify old receipts with
 * `--accept-legacy --pubkey`. Throws when there is no 0.2 key; never creates one.
 */
export function exportLegacyPublicKey(out: string, dir: string = keysDir()): string {
  const pub = join(dir, LEGACY_PUBLIC_FILE);
  const priv = join(dir, LEGACY_PRIVATE_FILE);
  let pem: string;
  if (existsSync(pub)) pem = readFileSync(pub, 'utf-8');
  else if (existsSync(priv)) pem = createPublicKey(readFileSync(priv, 'utf-8')).export({ type: 'spki', format: 'pem' }).toString();
  else throw new Error(`no mcp-guard 0.2 key in ${dir}. 0.3 keys are published with \`mcp-guard keys show\` (keys.json)`);
  writeFileSync(out, pem, { mode: 0o644 });
  return keyIdForPublicKey(pem);
}
