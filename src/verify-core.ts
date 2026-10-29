import { createPublicKey, verify as edVerify, type KeyObject } from 'node:crypto';

/**
 * The cryptographic core every verifier in mcp-guard uses: Ed25519 detached-signature
 * checks against PINNED keys, and single-use tracking. Receipt v2 verification and the
 * enforcement module's authorization tokens both build on these two primitives.
 */

/** key_id → public key (PEM or KeyObject). Only keys in this map are trusted. */
export type PinnedKeys = Record<string, string | KeyObject>;

/**
 * Verify `signatureHex` over `bytes` with the pinned key for `keyId`.
 * Returns a reason string on failure, or null when the signature verifies.
 */
export function verifyDetached(bytes: string, signatureHex: unknown, keyId: unknown, keys: PinnedKeys): string | null {
  if (typeof keyId !== 'string' || !Object.prototype.hasOwnProperty.call(keys, keyId)) {
    return `untrusted key_id "${String(keyId)}"`;
  }
  if (typeof signatureHex !== 'string' || !/^[0-9a-f]+$/i.test(signatureHex) || signatureHex.length % 2 !== 0) {
    return 'signature is not hex';
  }
  try {
    const key = keys[keyId];
    const ok = edVerify(null, Buffer.from(bytes), typeof key === 'string' ? createPublicKey(key) : key, Buffer.from(signatureHex, 'hex'));
    return ok ? null : 'signature does not verify against the pinned key';
  } catch (err) {
    return `signature verification threw (${err instanceof Error ? err.message : String(err)})`;
  }
}

/** Remembers used nonces so an authorization is honored at most once per process. */
export class ReplayCache {
  private readonly seen = new Set<string>();
  constructor(private readonly max = 10_000) {}

  /** Record `key`; returns false when it was already used. */
  use(key: string): boolean {
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    if (this.seen.size > this.max) {
      const oldest = this.seen.values().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    return true;
  }

  has(key: string): boolean {
    return this.seen.has(key);
  }
}
