import {
  generateKeyPairSync,
  sign as edSign,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { dirname, join } from 'node:path';

/**
 * Permission Deck Slice 1 — local Ed25519 dev signer.
 *
 * Generates (once) and loads a dev keypair under `mcp-guard/.keys/`. NEVER hardcodes
 * a secret: the private key is created locally on first use and persisted to disk
 * (gitignored). Used to sign issued receipts so the receipt `signature` block carries
 * a real, verifiable Ed25519 signature with key_id `pp-dev-1`.
 *
 * This is the dev signer of the strategy memo's open-core boundary — the managed PP
 * signer replaces it later without changing the receipt shape.
 */

export const DEV_KEY_ID = 'pp-dev-1';
export const SIGN_ALGORITHM = 'ed25519';

const KEYS_DIR = process.env.PP_KEYS_DIR || join(process.cwd(), '.keys');
const PRIVATE_KEY_PATH = join(KEYS_DIR, `${DEV_KEY_ID}.private.pem`);
const PUBLIC_KEY_PATH = join(KEYS_DIR, `${DEV_KEY_ID}.public.pem`);

let cachedPrivate: KeyObject | null = null;
let cachedPublic: KeyObject | null = null;

/** Generate the dev keypair if absent; load it either way. Idempotent. */
function ensureKeypair(): { privateKey: KeyObject; publicKey: KeyObject } {
  if (cachedPrivate && cachedPublic) {
    return { privateKey: cachedPrivate, publicKey: cachedPublic };
  }

  if (existsSync(PRIVATE_KEY_PATH) && existsSync(PUBLIC_KEY_PATH)) {
    const privPem = readFileSync(PRIVATE_KEY_PATH, 'utf-8');
    const pubPem = readFileSync(PUBLIC_KEY_PATH, 'utf-8');
    cachedPrivate = createPrivateKey(privPem);
    cachedPublic = createPublicKey(pubPem);
    return { privateKey: cachedPrivate, publicKey: cachedPublic };
  }

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

  mkdirSync(dirname(PRIVATE_KEY_PATH), { recursive: true });
  writeFileSync(PRIVATE_KEY_PATH, privPem, { mode: 0o600 });
  writeFileSync(PUBLIC_KEY_PATH, pubPem, { mode: 0o644 });
  try {
    chmodSync(PRIVATE_KEY_PATH, 0o600);
  } catch {
    // best effort on platforms without chmod semantics
  }

  cachedPrivate = privateKey;
  cachedPublic = publicKey;
  return { privateKey, publicKey };
}

/** Sign arbitrary bytes with the dev Ed25519 key. Returns a hex signature. */
export function signBytes(data: string | Buffer): string {
  const { privateKey } = ensureKeypair();
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  return edSign(null, buf, privateKey).toString('hex');
}

/** The dev public key in SPKI PEM form (for verification). */
export function getPublicKeyPem(): string {
  const { publicKey } = ensureKeypair();
  return publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

export interface ReceiptSignature {
  algorithm: string;
  key_id: string;
  value: string;
  verified: boolean;
}

/**
 * Produce a receipt signature block over the canonical signing bytes.
 * `signingBytes` should be a deterministic string identifying the authorized action
 * (e.g. receipt_id + payload hash) so the signature binds the exact decision.
 */
export function signReceiptPayload(signingBytes: string): ReceiptSignature {
  const value = signBytes(signingBytes);
  return {
    algorithm: SIGN_ALGORITHM,
    key_id: DEV_KEY_ID,
    value,
    verified: true,
  };
}
