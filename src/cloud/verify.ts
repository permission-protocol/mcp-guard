import { createHash, verify as cryptoVerify } from 'node:crypto';
import { canonicalJsonText } from '../signing/canonical.js';
import { KeyError, publicKeyFromRaw, resolveKey, type KeySet, type TrustPins } from '../signing/keys.js';
import type { ReplayCache } from '../verify-core.js';
import { isDemoKeyId } from './pinned-keys.js';

/**
 * Offline verification of a Permission Protocol receipt for a held MCP call.
 *
 * The guard trusts nothing the API says about a receipt: only the signed bytes. A
 * receipt releases a call when ALL of these hold, checked in this order:
 *
 *   1. its key is in the pinned key set, by fingerprint, Ed25519, not revoked, not a demo key;
 *   2. SHA-256(payload bytes) equals the stated hash and the signature verifies over it;
 *   3. the bytes are canonical JSON in a format this guard knows (jcs_v2, jcs_v3, jcs_v4),
 *      and name the same receipt id and key id as the envelope;
 *   4. the signed decision is APPROVED;
 *   5. the signed action is the `mcp_guard` lane and its fingerprint equals the one the
 *      guard computed from the call it holds;
 *   6. the signed request id is the request the guard opened;
 *   7. the signed decider is a person (`user:<id>`) who authenticated with a session;
 *   8. the receipt is production scope and its signed expiry is in the future;
 *   9. it has not been used by this guard before.
 *
 * Anything else is a refusal with a typed code. There is no partial acceptance.
 */

export interface CloudReceiptArtifact {
  receipt_id: string;
  status: string;
  receipt_version: number;
  canonicalization: string | null;
  key_id: string;
  alg: string | null;
  signed_payload_hash: string;
  signature_b64: string;
  payload_bytes_b64: string;
  issued_at?: string;
  expires_at?: string | null;
}

export type CloudVerifyCode =
  | 'MALFORMED'
  | 'KEY_NOT_FOUND'
  | 'KEY_SET_INVALID'
  | 'KEY_NOT_TRUSTED'
  | 'KEY_REVOKED'
  | 'DEMO_KEY'
  | 'SIGNED_PAYLOAD_HASH_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'CANONICALIZATION_UNSUPPORTED'
  | 'NON_CANONICAL_PAYLOAD'
  | 'IDENTITY_MISMATCH'
  | 'NOT_APPROVED'
  | 'WRONG_LANE'
  | 'FINGERPRINT_MISMATCH'
  | 'REQUEST_MISMATCH'
  | 'DECIDER_NOT_HUMAN'
  | 'DEMO_RECEIPT'
  | 'EXPIRED'
  | 'REPLAYED';

export interface VerifiedCloudReceipt {
  receiptId: string;
  keyId: string;
  canonicalization: string;
  status: 'APPROVED' | 'DENIED';
  fingerprint: string;
  requestId: string;
  decider: { id: string; display: string | null; authMethod: string | null };
  issuedAt: string | null;
  expiresAt: string | null;
}

export type CloudVerifyResult =
  | { ok: true; receipt: VerifiedCloudReceipt }
  | { ok: false; code: CloudVerifyCode; message: string };

export interface CloudVerifyOptions {
  keySet: KeySet;
  trust: TrustPins;
  /** The fingerprint the guard computed from the call it holds. */
  fingerprint: string;
  /** The request the guard opened. */
  requestId: string;
  /** Which signed decision the caller expects. A release always expects APPROVED. */
  expect: 'APPROVED' | 'DENIED';
  now?: Date;
  /** Consumed last, only by a release. */
  replayCache?: ReplayCache;
}

const SUPPORTED = new Set(['jcs_v2', 'jcs_v3', 'jcs_v4']);
const HUMAN_AUTH_METHODS = new Set(['session', 'session_stepup_webauthn', 'session_reauth']);
export const MCP_GUARD_LANE_TOOL = 'mcp_guard';

const refuse = (code: CloudVerifyCode, message: string): CloudVerifyResult => ({ ok: false, code, message });
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null);

function parseJsonObject(text: unknown): Record<string, unknown> | null {
  if (typeof text !== 'string') return null;
  try {
    const parsed: unknown = JSON.parse(text);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** The signed action: inside the request (jcs_v2) or its public projection (jcs_v3, jcs_v4). */
function signedAction(payload: Record<string, unknown>, canonicalization: string): Record<string, unknown> | null {
  const carrier = canonicalization === 'jcs_v2' ? payload.requestJson : payload.publicProjectionJson;
  const action = parseJsonObject(carrier)?.action;
  return isRecord(action) ? action : null;
}

export function verifyCloudReceipt(artifact: unknown, options: CloudVerifyOptions): CloudVerifyResult {
  if (!isRecord(artifact)) return refuse('MALFORMED', 'receipt artifact is not an object');
  const a = artifact as Partial<CloudReceiptArtifact>;
  for (const field of ['receipt_id', 'key_id', 'signed_payload_hash', 'signature_b64', 'payload_bytes_b64'] as const) {
    if (typeof a[field] !== 'string' || !a[field]) return refuse('MALFORMED', `receipt artifact has no ${field}`);
  }
  if (a.alg !== 'ed25519') return refuse('MALFORMED', `receipt algorithm is ${String(a.alg)}, not ed25519`);
  if (isDemoKeyId(a.key_id!)) return refuse('DEMO_KEY', `receipt is signed by a demo key (${a.key_id})`);

  let rawKey: Buffer;
  try {
    rawKey = resolveKey(options.keySet, a.key_id, options.trust).rawKey;
  } catch (err) {
    if (err instanceof KeyError) return refuse(err.code, err.message);
    throw err;
  }

  const bytes = Buffer.from(a.payload_bytes_b64!, 'base64');
  const signature = Buffer.from(a.signature_b64!, 'base64');
  if (bytes.length === 0 || signature.length !== 64) return refuse('MALFORMED', 'receipt bytes or signature are not well formed');
  const digest = createHash('sha256').update(bytes).digest();
  if (digest.toString('hex') !== a.signed_payload_hash) {
    return refuse('SIGNED_PAYLOAD_HASH_MISMATCH', 'receipt bytes do not hash to the stated hash');
  }
  let signatureOk = false;
  try {
    signatureOk = cryptoVerify(null, digest, publicKeyFromRaw(rawKey), signature);
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) return refuse('SIGNATURE_INVALID', `signature does not verify with pinned key ${a.key_id}`);

  const text = bytes.toString('utf8');
  const payload = parseJsonObject(text);
  if (!payload) return refuse('MALFORMED', 'signed bytes are not a JSON object');
  const canonicalization = str(payload.canonicalization);
  if (!canonicalization || !SUPPORTED.has(canonicalization)) {
    return refuse('CANONICALIZATION_UNSUPPORTED', `receipt format ${String(payload.canonicalization)} is not supported by this guard`);
  }
  if (canonicalJsonText(payload) !== text) return refuse('NON_CANONICAL_PAYLOAD', 'signed bytes are not canonical JSON');
  if (payload.id !== a.receipt_id || payload.signatureKeyId !== a.key_id) {
    return refuse('IDENTITY_MISMATCH', 'signed receipt id or key id differs from the envelope');
  }

  const status = payload.status;
  if (status !== 'APPROVED' && status !== 'DENIED') return refuse('NOT_APPROVED', `signed decision is ${String(status)}`);
  if (status !== options.expect) {
    return refuse('NOT_APPROVED', `signed decision is ${status}, not ${options.expect}`);
  }

  const action = signedAction(payload, canonicalization);
  if (!action || action.tool !== MCP_GUARD_LANE_TOOL) return refuse('WRONG_LANE', 'receipt is not for an MCP Guard call');
  const fingerprint = str(action.operation);
  if (!fingerprint || fingerprint !== options.fingerprint) {
    return refuse('FINGERPRINT_MISMATCH', 'receipt fingerprint is not the fingerprint of the held call');
  }
  if (payload.runId !== options.requestId) return refuse('REQUEST_MISMATCH', 'receipt answers a different request');

  const deciderId = str(payload.deciderId);
  const authMethod = str(payload.deciderAuthMethod);
  if (status === 'APPROVED') {
    if (!deciderId || !deciderId.startsWith('user:') || deciderId.length <= 'user:'.length) {
      return refuse('DECIDER_NOT_HUMAN', `signed decider is ${deciderId ?? 'absent'}, not a person`);
    }
    if (!authMethod || !HUMAN_AUTH_METHODS.has(authMethod)) {
      return refuse('DECIDER_NOT_HUMAN', `signed decider authenticated by ${authMethod ?? 'nothing'}, not a session`);
    }
    if (payload.scope !== 'production') return refuse('DEMO_RECEIPT', `receipt scope is ${String(payload.scope)}, not production`);
    const expiresAt = str(payload.expiresAt);
    const expiresMs = expiresAt ? Date.parse(expiresAt) : NaN;
    const now = (options.now ?? new Date()).getTime();
    if (!Number.isFinite(expiresMs) || expiresMs <= now) return refuse('EXPIRED', `receipt expired at ${expiresAt ?? 'an unstated time'}`);
    if (options.replayCache && options.replayCache.use(a.receipt_id!, expiresMs) !== 'ok') {
      return refuse('REPLAYED', 'receipt was already used by this guard');
    }
  }

  return {
    ok: true,
    receipt: {
      receiptId: a.receipt_id!,
      keyId: a.key_id!,
      canonicalization,
      status,
      fingerprint,
      requestId: options.requestId,
      decider: { id: deciderId ?? 'unknown', display: str(payload.deciderDisplay), authMethod },
      issuedAt: str(payload.createdAt),
      expiresAt: str(payload.expiresAt),
    },
  };
}
