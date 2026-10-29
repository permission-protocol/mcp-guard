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

export type ReplayOutcome = 'ok' | 'replayed' | 'full';

/**
 * Remembers used authorizations so each is honored at most once per process.
 *
 * An entry is kept until the authorization it records has expired, plus a grace period
 * for clock rounding: after that the authorization fails its own expiry check, so
 * forgetting it cannot re-open it. An unexpired entry is never evicted. When the cache is
 * full of unexpired entries, new authorizations are refused ('full') rather than making
 * room by forgetting one.
 */
export class ReplayCache {
  private readonly seen = new Map<string, number>(); // key -> expiry (epoch ms)

  constructor(
    private readonly max = 100_000,
    private readonly now: () => number = () => Date.now(),
    private readonly graceMs = 60_000,
  ) {}

  /** Record `key`, valid until `expiresAtMs`. Returns 'replayed' if already used, 'full' at capacity. */
  use(key: string, expiresAtMs: number): ReplayOutcome {
    const t = this.now();
    const prior = this.seen.get(key);
    if (prior !== undefined && prior > t) return 'replayed';
    if (this.seen.size >= this.max) this.prune(t);
    if (this.seen.size >= this.max) return 'full';
    this.seen.set(key, Number.isFinite(expiresAtMs) ? expiresAtMs + this.graceMs : Number.MAX_SAFE_INTEGER);
    return 'ok';
  }

  has(key: string): boolean {
    const exp = this.seen.get(key);
    return exp !== undefined && exp > this.now();
  }

  get size(): number {
    return this.seen.size;
  }

  private prune(t: number): void {
    for (const [k, exp] of this.seen) if (exp <= t) this.seen.delete(k);
  }
}
