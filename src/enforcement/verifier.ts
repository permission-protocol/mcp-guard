import stableStringify from 'fast-json-stable-stringify';
import crypto from 'crypto';
import { CanonicalPayload, SignedToken } from './types';
import { getToolPolicy, ToolPolicy } from './policy';

// Simple in-memory replay cache for the proxy
const usedNonces = new Set<string>();

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
  if (token.request_id !== payload.request_id) {
    throw new Error('Request ID mismatch - token does not authorize this payload');
  }

  // Trust boundary: Check key identity
  if (token.key_id !== expectedKeyId) {
    throw new Error(`Untrusted key_id: expected ${expectedKeyId}, got ${token.key_id}`);
  }

  // 1. Check Expiry
  const now = Math.floor(Date.now() / 1000);
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

  // 5. Verify Signature
  const isValidSig = crypto.verify(
    null,
    Buffer.from(buildAuthorizationSigningBytes(token)),
    publicKeyPem,
    Buffer.from(token.signature, 'hex')
  );

  if (!isValidSig) {
    throw new Error('Cryptographic signature verification failed');
  }

  // 6. Policy Enforcement (The Authority Plane)
  
  // A. Multi-Sig & Role-Based Auth
  const requiredApprovals = policy.required_approvals || 1;
  let validSignatures = 0;
  
  for (const signer of token.signers) {
    const isAllowedSigner = policy.allowed_signers ? policy.allowed_signers.includes(signer) : true;
    const hasAllowedRole = policy.allowed_roles ? token.roles.some(r => policy.allowed_roles!.includes(r)) : true;
    
    if (isAllowedSigner && hasAllowedRole) {
      validSignatures++;
    }
  }

  if (validSignatures < requiredApprovals) {
    throw new Error(`Policy violation: Requires ${requiredApprovals} valid approvals, found ${validSignatures}. Evaluated signers: ${token.signers.join(', ')}`);
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
    if (ttl > policy.max_ttl_seconds) {
      throw new Error(`Policy violation: Token TTL (${ttl}s) exceeds policy max_ttl_seconds (${policy.max_ttl_seconds}s)`);
    }
  }

  // 7. Replay Protection (Single-use)
  const replayKey = `${payload.request_id}:${payload.nonce}`;
  if (usedNonces.has(replayKey)) {
    throw new Error('Replay detected - authorization has already been used');
  }
  usedNonces.add(replayKey);

  return true;
}
