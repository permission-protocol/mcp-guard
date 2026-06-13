import { verify as edVerify } from 'node:crypto';
import { buildSigningBytes, type Receipt } from './receipt.js';

/**
 * Permission Deck Slice 2 — OFFLINE public-key receipt verifier.
 *
 * This is the deploy-gate side of "the receipt is the bridge": given a signed receipt
 * and the publisher's Ed25519 public key, decide — with NO network, NO live PP service —
 * whether the receipt authorizes a specific code/infra action.
 *
 * It checks, in order:
 *   1. the receipt carries an Ed25519 signature from a known key,
 *   2. the signature cryptographically verifies against `publicKeyPem` over the canonical
 *      signing bytes (which fold in scope/scope_ref/scope_sha — so a tampered scope fails),
 *   3. the receipt is AUTHORIZED (not DENIED / AWAITING_APPROVAL),
 *   4. the receipt has not expired,
 *   5. (optional) the scope / scope_ref / scope_sha exactly match what the gate expects.
 *
 * Fail-closed: any failed check yields `valid: false` with a human-readable reason.
 * A wrong `scope_sha` MUST fail — that is the whole point of the gate.
 */

export interface ExpectedScope {
  scope?: string;
  scope_ref?: string;
  scope_sha?: string;
}

export interface VerifyResult {
  valid: boolean;
  reasons: string[];
}

export function verifyReceiptOffline(
  receipt: Receipt,
  publicKeyPem: string,
  expected?: ExpectedScope,
  now: Date = new Date(),
): VerifyResult {
  const reasons: string[] = [];

  // 1. Signature must be present and Ed25519.
  const sig = receipt.signature;
  if (!sig || sig.algorithm !== 'ed25519' || !sig.value) {
    reasons.push('PP_UNSIGNED_RECEIPT: receipt has no Ed25519 signature.');
    // Without a signature there is nothing to verify; still report other failures.
  }

  // 2. Cryptographic signature check over the canonical signing bytes.
  if (sig && sig.algorithm === 'ed25519' && sig.value) {
    const signingBytes = buildSigningBytes(receipt);
    let ok = false;
    try {
      ok = edVerify(
        null,
        Buffer.from(signingBytes),
        publicKeyPem,
        Buffer.from(sig.value, 'hex'),
      );
    } catch (err) {
      reasons.push(
        `PP_INVALID_SIGNATURE: signature verification threw (${err instanceof Error ? err.message : String(err)}).`,
      );
    }
    if (!ok && !reasons.some((r) => r.startsWith('PP_INVALID_SIGNATURE'))) {
      reasons.push('PP_INVALID_SIGNATURE: Ed25519 signature does not verify against the published public key.');
    }
  }

  // 3. Status must be AUTHORIZED.
  if (receipt.status !== 'AUTHORIZED') {
    reasons.push(`PP_NOT_AUTHORIZED: receipt status is "${receipt.status}", expected AUTHORIZED.`);
  }

  // 4. Expiry (only if the receipt declares one).
  if (receipt.expires_at != null) {
    const expiresAt = new Date(receipt.expires_at);
    if (Number.isNaN(expiresAt.getTime())) {
      reasons.push(`PP_EXPIRED: receipt expires_at "${receipt.expires_at}" is not a valid date.`);
    } else if (expiresAt.getTime() <= now.getTime()) {
      reasons.push(`PP_EXPIRED: receipt expired at ${expiresAt.toISOString()} (now ${now.toISOString()}).`);
    }
  }

  // 5. Scope binding — exact match when the gate supplies expectations.
  if (expected) {
    const checkField = (field: keyof ExpectedScope, receiptValue: string | null): void => {
      const want = expected[field];
      if (want === undefined) return;
      if (receiptValue !== want) {
        reasons.push(
          `PP_SCOPE_MISMATCH: expected ${field}="${want}" but receipt has ${field}="${receiptValue ?? ''}".`,
        );
      }
    };
    checkField('scope', receipt.scope);
    checkField('scope_ref', receipt.scope_ref);
    checkField('scope_sha', receipt.scope_sha);
  }

  return { valid: reasons.length === 0, reasons };
}
