import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Local Ed25519 dev signer.
 *
 * The keypair is generated once and kept in the operator's config directory
 * (`$PP_KEYS_DIR`, else `$XDG_CONFIG_HOME/mcp-guard/keys`, else
 * `~/.config/mcp-guard/keys`) — never in the working directory, which is usually the
 * agent's workspace. The directory is 0700 and the private key 0600; a key with looser
 * permissions is refused rather than used.
 *
 * The key id is derived from the public key (`pp-dev-<fingerprint>`), so pinning a
 * public key pins its id and a regenerated key can never pass as the old one.
 *
 * This is the dev signer of the open-core boundary; the managed PP signer replaces it.
 */

export const SIGN_ALGORITHM = 'ed25519';
const PRIVATE_FILE = 'signing.private.pem';
const PUBLIC_FILE = 'signing.public.pem';

export class KeyPermissionError extends Error {
  readonly code = 'PP_KEY_PERMISSIONS';
}

export function keysDir(): string {
  if (process.env.PP_KEYS_DIR) return process.env.PP_KEYS_DIR;
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(base, 'mcp-guard', 'keys');
}

/** `pp-dev-` + the first 16 hex chars of sha256(SPKI DER). */
export function keyIdForPublicKey(publicKey: KeyObject | string): string {
  const key = typeof publicKey === 'string' ? createPublicKey(publicKey) : publicKey;
  const der = key.export({ type: 'spki', format: 'der' });
  return 'pp-dev-' + createHash('sha256').update(der).digest('hex').slice(0, 16);
}

interface Keypair {
  dir: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  keyId: string;
}

let cached: Keypair | null = null;

function assertPrivate(path: string, mask: number): void {
  if (process.platform === 'win32') return;
  const mode = statSync(path).mode & 0o777;
  if (mode & mask) {
    throw new KeyPermissionError(
      `Refusing to use signing key material at ${path}: mode ${mode.toString(8)} is readable or writable by others (key must be 0600 in a directory only you can write)`,
    );
  }
}

function ensureKeypair(): Keypair {
  const dir = keysDir();
  if (cached && cached.dir === dir) return cached;

  const privPath = join(dir, PRIVATE_FILE);
  const pubPath = join(dir, PUBLIC_FILE);

  let privateKey: KeyObject;
  let publicKey: KeyObject;
  if (existsSync(privPath)) {
    assertPrivate(dir, 0o022);
    assertPrivate(privPath, 0o077);
    privateKey = createPrivateKey(readFileSync(privPath, 'utf-8'));
    publicKey = createPublicKey(privateKey);
  } else {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    try { chmodSync(dir, 0o700); } catch { /* best effort on platforms without chmod */ }
    const pair = generateKeyPairSync('ed25519');
    privateKey = pair.privateKey;
    publicKey = pair.publicKey;
    writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), { mode: 0o600, flag: 'wx' });
    writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }).toString(), { mode: 0o644 });
  }

  cached = { dir, privateKey, publicKey, keyId: keyIdForPublicKey(publicKey) };
  return cached;
}

/** The active signing key id. */
export function currentKeyId(): string {
  return ensureKeypair().keyId;
}

/** The active public key in SPKI PEM form — what verifiers pin. */
export function getPublicKeyPem(): string {
  return ensureKeypair().publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

/** Sign bytes with the dev key. Returns the hex signature and the key id it belongs to. */
export function signBytes(data: string | Buffer): { keyId: string; value: string } {
  const { privateKey, keyId } = ensureKeypair();
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  return { keyId, value: edSign(null, buf, privateKey).toString('hex') };
}

/**
 * Write the public key to `path` (0644) so it can be committed or distributed as the
 * pinned trust anchor. Never writes the private key.
 */
export function exportPublicKey(path: string): string {
  writeFileSync(path, getPublicKeyPem(), { mode: 0o644 });
  return path;
}

/** Test/teardown helper: forget the cached keypair. */
export function _resetSigner(): void {
  cached = null;
}
