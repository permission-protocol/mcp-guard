import stableStringify from 'fast-json-stable-stringify';
import crypto from 'crypto';
import { CanonicalPayload, SignedToken } from './types';
import { ToolPolicy, assertEnforceablePolicy } from './policy';
import { ReplayCache, verifyDetached } from '../verify-core.js';

/** A token whose format cannot prove what the policy asks for. */
export class AuthorizationError extends Error {
  constructor(readonly code: 'PP_ROLE_NOT_BOUND', message: string) {
    super(message);
  }
}

// In-memory replay cache: each authorization is honored once per process.
const usedNonces = new ReplayCache();

export function buildAuthorizationSigningBytes(token: SignedToken): string {
  return stableStringify({
    request_id: token.request_id,
    decision: token.decision,
    payload_hash: token.payload_hash,
    signers: token.signers,
    roles: token.roles,
    signed_at: token.signed_at,
    expires_at: token.expires_at,
    key_id: token.key_id,
  });
}

export async function verifyAuthorization(
  payload: CanonicalPayload,
  token: SignedToken,
  publicKeyPem: string,
  policy: ToolPolicy,
  expectedKeyId: string = 'pp-prod-1'
): Promise<boolean> {
  // A policy this token format cannot enforce is refused before anything else (PolicyError).
  assertEnforceablePolicy(policy);

  // 0. Schema Validation (Fail fast)
  if (!payload || typeof payload !== 'object') {
    throw new Error('Missing or invalid payload block');
  }
  if (!payload.request_id || !payload.action || !payload.args || !payload.issued_at || !payload.expires_at || !payload.nonce) {
    throw new Error('Malformed payload schema: missing required fields');
  }

  if (!token || typeof token !== 'object') {
    throw new Error('Missing or invalid token block');
  }
  if (!token.request_id || !token.decision || !token.payload_hash || !token.signers || !token.roles || !token.signed_at || !token.expires_at || !token.key_id || !token.signature) {
    throw new Error('Malformed token schema: missing required fields');
  }
  if (!Array.isArray(token.signers) || !Array.isArray(token.roles)
    || !token.signers.every((x) => typeof x === 'string') || !token.roles.every((x) => typeof x === 'string')) {
    throw new Error('Malformed token schema: signers and roles must be arrays of strings');
  }
  if (token.request_id !== payload.request_id) {
    throw new Error('Request ID mismatch - token does not authorize this payload');
  }

  // Trust boundary: Check key identity
  if (token.key_id !== expectedKeyId) {
    throw new Error(`Untrusted key_id: expected ${expectedKeyId}, got ${token.key_id}`);
  }

  // 1. Check Expiry & Timestamp Bounds
  const now = Math.floor(Date.now() / 1000);
  if (
    typeof token.signed_at !== 'number' ||
    typeof token.expires_at !== 'number' ||
    typeof payload.issued_at !== 'number' ||
    typeof payload.expires_at !== 'number' ||
    !Number.isFinite(token.signed_at) ||
    !Number.isFinite(token.expires_at) ||
    !Number.isFinite(payload.issued_at) ||
    !Number.isFinite(payload.expires_at)
  ) {
    throw new Error('Malformed timestamp fields');
  }
  if (token.signed_at > now || token.expires_at <= token.signed_at) {
    throw new Error('Invalid token timestamps: signed_at must not be in the future and expires_at must exceed signed_at');
  }
  if (payload.issued_at > now || payload.expires_at <= payload.issued_at) {
    throw new Error('Invalid payload timestamps: issued_at must not be in the future and expires_at must exceed issued_at');
  }
  if (token.expires_at < now) {
    throw new Error('Authorization token expired');
  }
  if (payload.expires_at < now) {
    throw new Error('Payload expired');
  }

  // 2. Enforce Decision
  if (token.decision !== 'approved') {
    throw new Error(`Invalid decision: ${token.decision}`);
  }

  // 3. Stable Stringify & Hash
  const canonicalString = stableStringify(payload);
  const recomputedHash = crypto.createHash('sha256').update(canonicalString).digest('hex');

  // 4. Compare Hashes (Exact Binding)
  if (recomputedHash !== token.payload_hash.replace('sha256:', '')) {
    throw new Error('Payload hash mismatch - args were modified after approval');
  }

  // 5. Verify Signature (shared core: pinned key for the expected key id only)
  const sigError = verifyDetached(
    buildAuthorizationSigningBytes(token),
    token.signature,
    token.key_id,
    { [expectedKeyId]: publicKeyPem },
  );
  if (sigError) {
    throw new Error(`Cryptographic signature verification failed: ${sigError}`);
  }

  // 6. Policy Enforcement (The Authority Plane)
  
  // A. Signer & Role-Based Auth
  // One signature, one approval: assertEnforceablePolicy refused required_approvals > 1.
  const signers = [...new Set(token.signers)];

  // `roles` is one list for the whole token, not a role per signer. It is bound to a signer
  // only when the token names exactly one; with several, a role held by one of them could
  // be credited to another, so a role policy refuses such a token.
  if (policy.allowed_roles && signers.length !== 1) {
    throw new AuthorizationError(
      'PP_ROLE_NOT_BOUND',
      `Policy violation: allowed_roles needs a token with exactly one signer; this token lists ${signers.length} (${signers.join(', ')}) under one signature, so its roles cannot be bound to a signer`,
    );
  }

  const approved = signers.filter((signer) => {
    const isAllowedSigner = policy.allowed_signers ? policy.allowed_signers.includes(signer) : true;
    const hasAllowedRole = policy.allowed_roles ? token.roles.some((r) => policy.allowed_roles!.includes(r)) : true;
    return isAllowedSigner && hasAllowedRole;
  });
  if (approved.length < 1) {
    throw new Error(`Policy violation: Requires 1 valid approval, found 0. Evaluated signers: ${token.signers.join(', ')}`);
  }

  // B. Basic Conditions
  if (policy.conditions) {
    for (const cond of policy.conditions) {
      const keys = cond.field.split('.');
      let val: any = payload;
      for (const k of keys) {
        val = val?.[k];
      }
      if (val !== cond.equals) {
        throw new Error(`Policy violation: Condition '${cond.field} == ${cond.equals}' failed (got '${val}')`);
      }
    }
  }

  if (policy.max_ttl_seconds) {
    const ttl = token.expires_at - token.signed_at;
    const payloadTtl = payload.expires_at - payload.issued_at;
    if (ttl > policy.max_ttl_seconds || payloadTtl > policy.max_ttl_seconds) {
      throw new Error(`Policy violation: Token TTL (${Math.max(ttl, payloadTtl)}s) exceeds policy max_ttl_seconds (${policy.max_ttl_seconds}s)`);
    }
  }

  // 7. Replay Protection (Single-use)
  // Remember the authorization until both the token and the payload have expired.
  const outcome = usedNonces.use(
    `${payload.request_id}:${payload.nonce}`,
    Math.max(token.expires_at, payload.expires_at) * 1000,
  );
  if (outcome === 'replayed') {
    throw new Error('Replay detected - authorization has already been used');
  }
  if (outcome === 'full') {
    throw new Error('Replay cache full - refusing authorization rather than forgetting a used one');
  }

  return true;
}
