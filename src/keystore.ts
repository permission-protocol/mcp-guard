import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fingerprintOf, mcpgKeyId, rawPublicKey, MCPG_KEY_ID_PATTERN, type KeySet, type KeySetEntry } from './signing/keys.js';

/**
 * The operator's signing keys, created only by `mcp-guard keys init` / `keys rotate`.
 *
 * The directory (`$PP_KEYS_DIR`, else `$XDG_CONFIG_HOME/mcp-guard/keys`, else
 * `~/.config/mcp-guard/keys`) holds `keys.json` in the receipt-spec key-set shape and one
 * `<key id>.private.pem` (0600) per key. It is never the working directory, which is
 * usually the agent's workspace.
 *
 * The signer uses the NEWEST key in keys.json and never creates one. A missing, invalid
 * or revoked key is a typed error, never a fallback to another key.
 */

export const KEYS_FILE = 'keys.json';
export const KEY_SET_ISSUER = 'local:mcp-guard';

export type SigningErrorCode =
  | 'SIGNING_KEY_MISSING'
  | 'SIGNING_KEY_INVALID'
  | 'SIGNING_KEY_REVOKED'
  | 'UNATTRIBUTED_PRODUCTION_DECIDER';

export class SigningError extends Error {
  constructor(readonly code: SigningErrorCode, message: string) {
    super(`${code}: ${message}`);
  }
}

export function keysDir(): string {
  if (process.env.PP_KEYS_DIR) return process.env.PP_KEYS_DIR;
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(base, 'mcp-guard', 'keys');
}

export interface SigningKey {
  keyId: string;
  privateKey: KeyObject;
  rawPublicKey: Buffer;
  /** `sha256:<hex>` of the raw public key: the value gates pin with --trust. */
  fingerprint: string;
  demo: boolean;
  /** The key set the key was loaded from (what a verifier of these receipts is given). */
  keySet: KeySet;
}

const FIX = 'run `mcp-guard keys init` (or set PP_KEYS_DIR to the directory that holds keys.json)';

function privatePath(dir: string, keyId: string): string {
  return join(dir, `${keyId}.private.pem`);
}

function readKeySet(dir: string): KeySet | null {
  const p = join(dir, KEYS_FILE);
  if (!existsSync(p)) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(p, 'utf-8'));
  } catch (e: any) {
    throw new SigningError('SIGNING_KEY_INVALID', `${p} is not valid JSON (${e.message})`);
  }
  const keys = (parsed as KeySet | null)?.keys;
  if (!Array.isArray(keys)) throw new SigningError('SIGNING_KEY_INVALID', `${p} has no "keys" array`);
  return parsed as KeySet;
}

function writeKeySet(dir: string, keySet: KeySet): void {
  const p = join(dir, KEYS_FILE);
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(keySet, null, 2) + '\n', { mode: 0o644 });
  renameSync(tmp, p);
}

function assertPrivate(path: string, mask: number): void {
  if (process.platform === 'win32') return;
  const mode = statSync(path).mode & 0o777;
  if (mode & mask) {
    throw new SigningError(
      'SIGNING_KEY_INVALID',
      `refusing key material at ${path}: mode ${mode.toString(8)} is readable or writable by others (key must be 0600 in a directory only you can write)`,
    );
  }
}

/**
 * Load the newest key in keys.json for signing. Throws SigningError: MISSING when there
 * is no key set or private key, INVALID when the key is unreadable, exposed, not Ed25519,
 * or not the key its id and key-set entry name, REVOKED when keys.json revokes it.
 */
export function loadSigningKey(dir: string = keysDir()): SigningKey {
  const keySet = readKeySet(dir);
  if (!keySet || keySet.keys.length === 0) {
    throw new SigningError('SIGNING_KEY_MISSING', `no signing key in ${join(dir, KEYS_FILE)}; ${FIX}`);
  }
  const entry = keySet.keys[keySet.keys.length - 1];
  const keyId = String(entry?.key_id ?? '');
  if (!MCPG_KEY_ID_PATTERN.test(keyId)) {
    throw new SigningError('SIGNING_KEY_INVALID', `newest key id "${keyId}" is not an mcpg- key id`);
  }
  if (entry.status === 'revoked' || (entry.revoked_at !== undefined && entry.revoked_at !== null)) {
    throw new SigningError('SIGNING_KEY_REVOKED', `newest key ${keyId} is revoked in ${join(dir, KEYS_FILE)}; run \`mcp-guard keys rotate\``);
  }
  const pemPath = privatePath(dir, keyId);
  if (!existsSync(pemPath)) {
    throw new SigningError('SIGNING_KEY_MISSING', `private key for ${keyId} not found at ${pemPath}; ${FIX}`);
  }
  assertPrivate(dir, 0o022);
  assertPrivate(pemPath, 0o077);

  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(readFileSync(pemPath, 'utf-8'));
  } catch (e: any) {
    throw new SigningError('SIGNING_KEY_INVALID', `${pemPath} is not a readable private key (${e.message})`);
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new SigningError('SIGNING_KEY_INVALID', `${pemPath} is ${privateKey.asymmetricKeyType}, not ed25519`);
  }
  const raw = rawPublicKey(createPublicKey(privateKey));
  const demo = keyId.startsWith('mcpg-demo-');
  if (mcpgKeyId(raw, demo) !== keyId) {
    throw new SigningError('SIGNING_KEY_INVALID', `${pemPath} is not the key ${keyId} names (its id would be ${mcpgKeyId(raw, demo)})`);
  }
  if (Buffer.from(String(entry.public_key_b64 ?? ''), 'base64').compare(raw) !== 0) {
    throw new SigningError('SIGNING_KEY_INVALID', `the public key listed for ${keyId} in keys.json is not the private key's`);
  }
  return { keyId, privateKey, rawPublicKey: raw, fingerprint: fingerprintOf(raw), demo, keySet };
}

/** Create a key and append it to keys.json. `init` refuses when a key set exists; `rotate` requires one. */
export function createKey(opts: { demo?: boolean; rotate?: boolean; dir?: string; now?: Date } = {}): SigningKey {
  const dir = opts.dir ?? keysDir();
  const existing = readKeySet(dir);
  if (opts.rotate && !existing) throw new SigningError('SIGNING_KEY_MISSING', `no key set in ${dir} to rotate; run \`mcp-guard keys init\``);
  if (!opts.rotate && existing && existing.keys.length > 0) {
    throw new Error(`a key set already exists in ${join(dir, KEYS_FILE)}; use \`mcp-guard keys rotate\` to add a new key`);
  }

  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { chmodSync(dir, 0o700); } catch { /* best effort on platforms without chmod */ }
  const pair = generateKeyPairSync('ed25519');
  const raw = rawPublicKey(pair.publicKey);
  const keyId = mcpgKeyId(raw, !!opts.demo);
  writeFileSync(privatePath(dir, keyId), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), { mode: 0o600, flag: 'wx' });

  const entry: KeySetEntry = {
    key_id: keyId,
    alg: 'ed25519',
    public_key_b64: raw.toString('base64'),
    status: 'active',
    created_at: (opts.now ?? new Date()).toISOString(),
    revoked_at: null,
  };
  writeKeySet(dir, { issuer: existing?.issuer ?? KEY_SET_ISSUER, keys: [...(existing?.keys ?? []), entry] });
  return loadSigningKey(dir);
}

/** Mark a key revoked: every receipt it signed then fails verification (KEY_REVOKED). */
export function revokeKey(keyId: string, opts: { dir?: string; now?: Date } = {}): void {
  const dir = opts.dir ?? keysDir();
  const keySet = readKeySet(dir);
  const entry = keySet?.keys.find((k) => k.key_id === keyId);
  if (!keySet || !entry) throw new Error(`key ${keyId} is not in ${join(dir, KEYS_FILE)}`);
  entry.status = 'revoked';
  entry.revoked_at = (opts.now ?? new Date()).toISOString();
  writeKeySet(dir, keySet);
}

/** The key set file, for `keys show` and for publishing to gates. */
export function keySetPath(dir: string = keysDir()): string {
  return join(dir, KEYS_FILE);
}
