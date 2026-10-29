import { createHash, sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';
import { JCS_V2, canonicalizeJcsV2 } from './canonical.js';
import { publicKeyFromRaw, resolveKey, KeyError, type TrustPins } from './keys.js';

/**
 * The portable receipt artifact of the org receipt standard: the signed `jcs_v2` bytes
 * plus their SHA-256 and an Ed25519 signature over that digest (base64), exactly as the
 * app signs (service.ts) and `@permission-protocol/verify` checks. The top-level
 * `status`, `issued_at` and `expires_at` are conveniences: verifiers read decisions only
 * from the decoded signed payload.
 */
export interface ReceiptArtifact {
  receipt_id: string;
  status: string;
  receipt_version: number;
  canonicalization: string;
  key_id: string;
  alg: string;
  signed_payload_hash: string;
  signature_b64: string;
  payload_bytes_b64: string;
  issued_at?: string | null;
  expires_at?: string | null;
}

export type ArtifactCheckCode =
  | 'MALFORMED'
  | 'SIGNED_PAYLOAD_HASH_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'CANONICALIZATION_UNSUPPORTED'
  | 'NON_CANONICAL_PAYLOAD'
  | 'IDENTITY_MISMATCH'
  | KeyError['code'];

export class ArtifactError extends Error {
  constructor(readonly code: ArtifactCheckCode, message: string) {
    super(message);
  }
}

/** Build and sign the artifact for a `jcs_v2` record. The record must name the key id. */
export function buildArtifact(record: Record<string, unknown>, privateKey: KeyObject): ReceiptArtifact {
  if (record.canonicalization !== JCS_V2) throw new Error('record.canonicalization must be jcs_v2');
  const bytes = Buffer.from(canonicalizeJcsV2(record), 'utf8');
  const digest = createHash('sha256').update(bytes).digest();
  return {
    receipt_id: String(record.id),
    status: String(record.status),
    receipt_version: Number(record.receiptVersion),
    canonicalization: JCS_V2,
    key_id: String(record.signatureKeyId),
    alg: 'ed25519',
    signed_payload_hash: digest.toString('hex'),
    signature_b64: edSign(null, digest, privateKey).toString('base64'),
    payload_bytes_b64: bytes.toString('base64'),
    issued_at: (record.createdAt as string | undefined) ?? null,
    expires_at: (record.expiresAt as string | undefined) ?? null,
  };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * The spec's checks, in the spec's order (SPEC.md 6.2): key (listed once, pinned,
 * not revoked), signature material, SHA-256 of the bytes equals signed_payload_hash,
 * Ed25519 over the digest, the bytes are a JSON object, the canonicalization is one this
 * verifier implements, the bytes are exactly the canonical `jcs_v2` text of the payload
 * they decode to, and the signed id and key id equal the artifact's. Returns the signed
 * payload or throws ArtifactError / KeyError.
 */
export function checkArtifact(artifact: unknown, keySet: unknown, trust: TrustPins | null): {
  payload: Record<string, unknown>;
  rawKey: Buffer;
} {
  if (!isPlainObject(artifact)) throw new ArtifactError('MALFORMED', 'artifact is not an object');
  const a = artifact as Partial<ReceiptArtifact>;
  const { rawKey } = resolveKey(keySet, a.key_id, trust);
  if (a.alg !== 'ed25519') throw new ArtifactError('MALFORMED', `unsupported algorithm ${String(a.alg)}`);
  if (typeof a.signed_payload_hash !== 'string' || typeof a.signature_b64 !== 'string' || typeof a.payload_bytes_b64 !== 'string') {
    throw new ArtifactError('MALFORMED', 'artifact is missing signed_payload_hash, signature_b64 or payload_bytes_b64');
  }
  const bytes = Buffer.from(a.payload_bytes_b64, 'base64');
  const signature = Buffer.from(a.signature_b64, 'base64');
  if (signature.length !== 64) throw new ArtifactError('MALFORMED', `signature is ${signature.length} bytes, expected 64`);
  const digest = createHash('sha256').update(bytes).digest();
  if (digest.toString('hex') !== a.signed_payload_hash.toLowerCase()) {
    throw new ArtifactError('SIGNED_PAYLOAD_HASH_MISMATCH', 'SHA-256 of the signed bytes does not equal signed_payload_hash');
  }
  if (!edVerify(null, digest, publicKeyFromRaw(rawKey), signature)) {
    throw new ArtifactError('SIGNATURE_INVALID', 'Ed25519 signature does not verify against the key');
  }
  let payload: unknown;
  try {
    payload = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new ArtifactError('MALFORMED', 'signed bytes are not JSON');
  }
  if (!isPlainObject(payload)) throw new ArtifactError('MALFORMED', 'signed bytes are not a JSON object');
  if (payload.canonicalization !== JCS_V2) {
    throw new ArtifactError(
      'CANONICALIZATION_UNSUPPORTED',
      `the signature verifies, but the receipt is signed under ${JSON.stringify(payload.canonicalization ?? null)}, which this verifier does not implement (jcs_v2 only): unverifiable here, not tampered`,
    );
  }
  if (canonicalizeJcsV2(payload) !== bytes.toString('utf8')) {
    throw new ArtifactError('NON_CANONICAL_PAYLOAD', 'the signed bytes are not the canonical jcs_v2 text of the payload they encode');
  }
  if (typeof payload.id !== 'string' || payload.id !== a.receipt_id) {
    throw new ArtifactError('IDENTITY_MISMATCH', `signed receipt id ${JSON.stringify(payload.id ?? null)} does not match the artifact's ${JSON.stringify(a.receipt_id ?? null)}`);
  }
  if (payload.signatureKeyId !== a.key_id) {
    throw new ArtifactError('IDENTITY_MISMATCH', `signed key id ${JSON.stringify(payload.signatureKeyId ?? null)} does not match the verifying key ${JSON.stringify(a.key_id)}`);
  }
  return { payload, rawKey };
}
