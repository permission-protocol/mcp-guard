import { createHash, createPublicKey, type KeyObject } from 'node:crypto';

/**
 * Key sets in the receipt-spec shape (as served at
 * /.well-known/permission-protocol/keys.json) and pinning by fingerprint, matching
 * `@permission-protocol/verify` (`--keys`, `--trust KEY_ID=sha256:<hex>`).
 */

export interface KeySetEntry {
  key_id: string;
  alg: string;
  public_key_b64: string;
  status?: string;
  created_at?: string;
  revoked_at?: string | null;
}

export interface KeySet {
  issuer?: string;
  keys: KeySetEntry[];
}

/** key id → `sha256:<hex>` fingerprint of the raw 32-byte key. */
export type TrustPins = Map<string, string>;

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
export const TRUST_PATTERN = /^([^=]+)=(sha256:[a-f0-9]{64})$/;
/** mcp-guard's self-certifying key id: `mcpg-` + 16 hex of SHA-256(raw key). */
export const MCPG_KEY_ID_PATTERN = /^mcpg-(demo-)?[0-9a-f]{16}$/;

export class KeyError extends Error {
  constructor(readonly code: 'KEY_NOT_FOUND' | 'KEY_SET_INVALID' | 'KEY_NOT_TRUSTED' | 'KEY_REVOKED', message: string) {
    super(message);
  }
}

export function fingerprintOf(rawKey: Buffer): string {
  return `sha256:${createHash('sha256').update(rawKey).digest('hex')}`;
}

export function rawPublicKey(key: KeyObject): Buffer {
  const der = key.export({ type: 'spki', format: 'der' });
  return Buffer.from(der.subarray(der.length - 32));
}

export function publicKeyFromRaw(rawKey: Buffer): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, rawKey]), format: 'der', type: 'spki' });
}

/** The key id mcp-guard assigns a key (demo keys get the `mcpg-demo-` prefix). */
export function mcpgKeyId(rawKey: Buffer, demo = false): string {
  return `mcpg-${demo ? 'demo-' : ''}${createHash('sha256').update(rawKey).digest('hex').slice(0, 16)}`;
}

/** Parse `--trust KEY_ID=sha256:<hex>` values. */
export function parseTrust(values: string[]): TrustPins {
  const pins: TrustPins = new Map();
  for (const v of values) {
    const m = v.match(TRUST_PATTERN);
    if (!m) throw new Error(`--trust must be KEY_ID=sha256:<64 lowercase hex>, got "${v}"`);
    pins.set(m[1], m[2]);
  }
  return pins;
}

/**
 * The key a record names: listed exactly once, Ed25519, 32 bytes, not revoked, pinned
 * when pins are given, and, for an mcpg- id, the id must be the key's own fingerprint.
 */
export function resolveKey(keySet: unknown, keyId: unknown, trust: TrustPins | null): { entry: KeySetEntry; rawKey: Buffer } {
  const keys = (keySet as KeySet | null)?.keys;
  if (!Array.isArray(keys)) throw new KeyError('KEY_SET_INVALID', 'key set has no "keys" array');
  if (typeof keyId !== 'string' || !keyId) throw new KeyError('KEY_NOT_FOUND', 'record names no key id');
  const matches = keys.filter((k) => k?.key_id === keyId);
  if (matches.length === 0) throw new KeyError('KEY_NOT_FOUND', `key not found: ${keyId}`);
  if (matches.length > 1) throw new KeyError('KEY_SET_INVALID', `key set lists ${keyId} more than once`);
  const [entry] = matches;
  if (entry.alg !== 'ed25519') throw new KeyError('KEY_SET_INVALID', `key ${keyId} is ${String(entry.alg)}, not ed25519`);
  const rawKey = Buffer.from(String(entry.public_key_b64 ?? ''), 'base64');
  if (rawKey.length !== 32) throw new KeyError('KEY_SET_INVALID', `key ${keyId} is ${rawKey.length} bytes, expected 32`);
  if (entry.status === 'revoked' || (entry.revoked_at !== undefined && entry.revoked_at !== null)) {
    throw new KeyError('KEY_REVOKED', `signing key revoked: ${keyId}`);
  }
  if (keyId.startsWith('mcpg-')) {
    const demo = keyId.startsWith('mcpg-demo-');
    if (!MCPG_KEY_ID_PATTERN.test(keyId) || mcpgKeyId(rawKey, demo) !== keyId) {
      throw new KeyError('KEY_SET_INVALID', `key id ${keyId} is not the fingerprint of its key`);
    }
  }
  if (trust) {
    const pinned = trust.get(keyId);
    const fp = fingerprintOf(rawKey);
    if (!pinned) throw new KeyError('KEY_NOT_TRUSTED', `key ${keyId} is not pinned by --trust`);
    if (pinned !== fp) throw new KeyError('KEY_NOT_TRUSTED', `key ${keyId} is ${fp}, not the ${pinned} pinned by --trust`);
  }
  return { entry, rawKey };
}
