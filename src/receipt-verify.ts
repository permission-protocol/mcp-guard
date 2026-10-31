import { RECEIPT_VERSION, signingBytes, type Receipt, type ReceiptEnvelope } from './receipt.js';
import { verifyDetached, type PinnedKeys, type ReplayCache } from './verify-core.js';
import { checkArtifact } from './signing/artifact.js';
import { fingerprintOf, type TrustPins } from './signing/keys.js';
import { hashablePayloadInputHash } from './issuer.js';

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

// ---------------------------------------------------------------------------
// The org receipt standard (`jcs_v2` artifacts). The cryptographic checks are the
// spec's (src/signing/artifact.ts); the gate checks below read only from the signed
// payload, never from the artifact's unsigned convenience fields.
// ---------------------------------------------------------------------------

/** The call a receipt is checked against: its resource must match and its `inputHash` must recompute from it. */
export interface CallInput {
  tool: string;
  operation: string;
  resource: string;
  input: unknown;
}

export interface ArtifactVerifyOptions extends VerifyOptions {
  /** key id → sha256 fingerprint. Without pins, the key set file is the trust anchor. */
  trust?: TrustPins | null;
  /** Accept receipts signed with scope "demo" (demo keys). Default false. */
  allowDemo?: boolean;
  /** When given, the signed inputHash must be this call's pp.hashable_payload.v1 hash. */
  call?: CallInput;
  /** When given, the signed idemKey must be this one (the decision the receipt is for). */
  idemKey?: string;
}

export interface ArtifactVerifyResult extends VerifyResult {
  format: 'jcs_v2';
  payload?: Record<string, unknown>;
  keyFingerprint?: string;
}

/** The scope a `jcs_v2` request names: `scope.capability`, `scope.ref`, `scope.commitSha`. */
export function requestScope(payload: Record<string, unknown>): { capability: string; ref: string | null; commitSha: string | null } | null {
  if (typeof payload.requestJson !== 'string') return null;
  let request: any;
  try { request = JSON.parse(payload.requestJson); } catch { return null; }
  const s = request?.scope;
  if (!s || typeof s !== 'object' || typeof s.capability !== 'string') return null;
  return {
    capability: s.capability,
    ref: typeof s.ref === 'string' ? s.ref : null,
    commitSha: typeof s.commitSha === 'string' ? s.commitSha : null,
  };
}

function requestResource(payload: Record<string, unknown>): string | null {
  if (typeof payload.requestJson !== 'string') return null;
  try {
    const resource = JSON.parse(payload.requestJson)?.action?.resource;
    return typeof resource === 'string' ? resource : null;
  } catch {
    return null;
  }
}

/** A decision a person made, as opposed to a policy, a timer or an unattributed click. */
function humanDecided(payload: Record<string, unknown>): boolean {
  return typeof payload.deciderId === 'string'
    && typeof payload.deciderAuthMethod === 'string'
    && payload.deciderAuthMethod !== 'policy'
    && payload.attributionConfidence !== 'unattributed';
}

export function verifyArtifactReceipt(envelope: unknown, keySet: unknown, opts: ArtifactVerifyOptions = {}): ArtifactVerifyResult {
  const now = opts.now ?? new Date();
  const artifact = (envelope as { artifact?: unknown } | null)?.artifact ?? envelope;
  let payload: Record<string, unknown>;
  let rawKey: Buffer;
  try {
    ({ payload, rawKey } = checkArtifact(artifact, keySet, opts.trust ?? null));
  } catch (err) {
    const code = (err as { code?: string }).code ?? 'MALFORMED';
    return { valid: false, format: 'jcs_v2', reasons: [`${code}: ${(err as Error).message}.`] };
  }

  const reasons: string[] = [];
  if (payload.status !== 'APPROVED') {
    reasons.push(`PP_NOT_AUTHORIZED: signed status is ${JSON.stringify(payload.status ?? null)}, expected "APPROVED".`);
  }
  const expires = typeof payload.expiresAt === 'string' ? Date.parse(payload.expiresAt) : NaN;
  if (Number.isNaN(expires)) {
    reasons.push('PP_EXPIRED: the receipt has no signed expiresAt.');
  } else if (expires <= now.getTime()) {
    reasons.push(`PP_EXPIRED: receipt expired at ${new Date(expires).toISOString()} (now ${now.toISOString()}).`);
  }

  if (payload.scope === 'demo' && !opts.allowDemo) {
    reasons.push('PP_DEMO_RECEIPT: the receipt was signed by a demo key (scope "demo") and authorizes nothing real.');
  }
  if (opts.call) {
    const resource = requestResource(payload);
    if (resource !== opts.call.resource) {
      reasons.push(`PP_RESOURCE_MISMATCH: expected resource ${JSON.stringify(opts.call.resource)}, but the signed request has ${JSON.stringify(resource)}.`);
    }
    const want = hashablePayloadInputHash(opts.call.tool, opts.call.operation, opts.call.input);
    if (payload.inputHash !== want) {
      reasons.push(`INPUT_HASH_MISMATCH: the signed inputHash is ${JSON.stringify(payload.inputHash ?? null)}, the call hashes to ${want}.`);
    }
  }

  if (opts.idemKey !== undefined && payload.idemKey !== opts.idemKey) {
    reasons.push(`PP_DECISION_MISMATCH: the receipt is for decision ${JSON.stringify(payload.idemKey ?? null)}, not ${opts.idemKey}.`);
  }

  const scope = requestScope(payload);
  if (scope && !humanDecided(payload) && !opts.allowPolicyApproval) {
    reasons.push(`PP_APPROVAL_NOT_HUMAN: scoped action was decided by ${JSON.stringify(payload.deciderId ?? null)} (${String(payload.deciderAuthMethod ?? 'no decider')}), not an attributed human.`);
  }
  if (opts.expected) {
    const actual: Record<keyof ExpectedScope, string | null> = {
      scope: scope?.capability ?? null,
      scope_ref: scope?.ref ?? null,
      scope_sha: scope?.commitSha ?? null,
    };
    for (const field of ['scope', 'scope_ref', 'scope_sha'] as const) {
      const want = opts.expected[field];
      if (want !== undefined && actual[field] !== want) {
        reasons.push(`PP_SCOPE_MISMATCH: expected ${field}="${want}" but the signed request has "${actual[field] ?? ''}".`);
      }
    }
  }

  if (reasons.length === 0 && opts.replayCache) {
    const outcome = opts.replayCache.use(`${String(payload.id)}`, expires);
    if (outcome === 'replayed') reasons.push('PP_REPLAYED: this receipt has already been used.');
    if (outcome === 'full') reasons.push('PP_REPLAY_CACHE_FULL: too many unexpired receipts in use; refusing rather than forgetting one.');
  }

  return { valid: reasons.length === 0, format: 'jcs_v2', reasons, payload, keyFingerprint: fingerprintOf(rawKey) };
}

/** True for a 0.2.0 receipt (`{ envelope: { v: 2 }, signature, display }`). */
export function isLegacyMcpGuardReceipt(input: unknown): boolean {
  const e = (input as { envelope?: { v?: unknown } } | null)?.envelope;
  return !!e && typeof e === 'object' && e.v === 2 && !!(input as { signature?: unknown }).signature;
}

/** What a 0.2.0 receipt's signature covers, stated whenever one verifies. */
export const LEGACY_SIGNED_FIELDS_NOTE =
  'legacy mcp-guard 0.2 receipt: its own canonical envelope is signed (scope, decision, approver, expiry, nonce, key id), but it is not the org receipt standard and no other verifier reads it';
