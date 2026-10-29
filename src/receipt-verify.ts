import { RECEIPT_VERSION, signingBytes, type Receipt, type ReceiptEnvelope } from './receipt.js';
import { verifyDetached, type PinnedKeys, type ReplayCache } from './verify-core.js';

/**
 * OFFLINE receipt verifier — the deploy-gate side of "the receipt is the bridge".
 *
 * Given a receipt and the PINNED public keys, decide with no network whether the
 * receipt authorizes an action. Checks:
 *   1. receipt v2 with a well-formed envelope,
 *   2. Ed25519 signature over the canonical envelope, by a pinned key,
 *   3. decision is `allowed` with a recorded approval,
 *   4. not expired (expires_at is required),
 *   5. a scoped receipt was approved by a human (unless the caller allows policy approval),
 *   6. (optional) scope / scope_ref / scope_sha exactly match the gate's expectation,
 *   7. (optional) its nonce has not been used before.
 *
 * Fail-closed: any failed check yields `valid: false` with reasons. Only the envelope is
 * read; the unsigned `display` block is ignored.
 */

export interface ExpectedScope {
  scope?: string;
  scope_ref?: string;
  scope_sha?: string;
}

export interface VerifyOptions {
  expected?: ExpectedScope;
  now?: Date;
  /** Accept policy approvals (countdown, standing rule) on scoped receipts. Default false. */
  allowPolicyApproval?: boolean;
  /** When given, the receipt's nonce is consumed; a second use fails. */
  replayCache?: ReplayCache;
}

export interface VerifyResult {
  valid: boolean;
  reasons: string[];
}

const STRING_FIELDS = [
  'receipt_id', 'method', 'args_sha256', 'decision', 'actor', 'policy_sha256', 'mode', 'issued_at', 'expires_at', 'nonce', 'key_id',
] as const;

function envelopeShapeErrors(e: any): string[] {
  const errs: string[] = [];
  if (!e || typeof e !== 'object' || Array.isArray(e)) return ['envelope missing'];
  for (const f of STRING_FIELDS) if (typeof e[f] !== 'string' || !e[f]) errs.push(`${f} missing`);
  if (e.tool !== null && typeof e.tool !== 'string') errs.push('tool invalid');
  if (e.rule_id !== null && typeof e.rule_id !== 'string') errs.push('rule_id invalid');
  if (e.scope !== null) {
    const s = e.scope;
    if (!s || typeof s !== 'object' || typeof s.scope !== 'string'
      || (s.ref !== null && typeof s.ref !== 'string') || (s.sha !== null && typeof s.sha !== 'string')) {
      errs.push('scope invalid');
    }
  }
  if (e.approval !== null) {
    const a = e.approval;
    if (!a || typeof a !== 'object' || (a.kind !== 'human' && a.kind !== 'policy') || typeof a.id !== 'string' || typeof a.via !== 'string') {
      errs.push('approval invalid');
    }
  }
  return errs;
}

export function verifyReceipt(receipt: Receipt, keys: PinnedKeys, opts: VerifyOptions = {}): VerifyResult {
  const reasons: string[] = [];
  const now = opts.now ?? new Date();
  const e = (receipt as any)?.envelope as ReceiptEnvelope | undefined;

  if (!e || (e as any).v !== RECEIPT_VERSION) {
    return { valid: false, reasons: [`PP_UNSUPPORTED_VERSION: expected receipt v${RECEIPT_VERSION}.`] };
  }
  const shape = envelopeShapeErrors(e);
  if (shape.length) {
    return { valid: false, reasons: [`PP_MALFORMED_RECEIPT: ${shape.join(', ')}.`] };
  }

  // Signature over the canonical envelope, by a pinned key that the envelope also names.
  const sig = (receipt as any).signature;
  if (!sig || sig.alg !== 'ed25519' || sig.key_id !== e.key_id) {
    reasons.push('PP_INVALID_SIGNATURE: signature block missing, not Ed25519, or key_id differs from the envelope.');
  } else {
    const err = verifyDetached(signingBytes(e), sig.value, e.key_id, keys);
    if (err) reasons.push(`PP_INVALID_SIGNATURE: ${err}.`);
  }

  if (e.decision !== 'allowed' || !e.approval) {
    reasons.push(`PP_NOT_AUTHORIZED: decision is "${e.decision}"${e.approval ? '' : ' with no approval'}.`);
  }

  const issued = Date.parse(e.issued_at);
  const expires = Date.parse(e.expires_at);
  if (Number.isNaN(issued) || Number.isNaN(expires) || expires <= issued) {
    reasons.push('PP_EXPIRED: issued_at / expires_at invalid.');
  } else if (expires <= now.getTime()) {
    reasons.push(`PP_EXPIRED: receipt expired at ${new Date(expires).toISOString()} (now ${now.toISOString()}).`);
  }

  if (e.scope && e.approval && e.approval.kind !== 'human' && !opts.allowPolicyApproval) {
    reasons.push(`PP_APPROVAL_NOT_HUMAN: scoped action was authorized by ${e.approval.kind} "${e.approval.id}" (${e.approval.via}), not a human.`);
  }

  if (opts.expected) {
    const actual: Record<keyof ExpectedScope, string | null> = {
      scope: e.scope?.scope ?? null,
      scope_ref: e.scope?.ref ?? null,
      scope_sha: e.scope?.sha ?? null,
    };
    for (const field of ['scope', 'scope_ref', 'scope_sha'] as const) {
      const want = opts.expected[field];
      if (want !== undefined && actual[field] !== want) {
        reasons.push(`PP_SCOPE_MISMATCH: expected ${field}="${want}" but receipt has ${field}="${actual[field] ?? ''}".`);
      }
    }
  }

  if (reasons.length === 0 && opts.replayCache) {
    const outcome = opts.replayCache.use(`${e.receipt_id}:${e.nonce}`, expires);
    if (outcome === 'replayed') reasons.push('PP_REPLAYED: this receipt has already been used.');
    if (outcome === 'full') reasons.push('PP_REPLAY_CACHE_FULL: too many unexpired receipts in use; refusing rather than forgetting one.');
  }

  return { valid: reasons.length === 0, reasons };
}
