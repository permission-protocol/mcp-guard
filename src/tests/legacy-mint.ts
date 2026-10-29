import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { hashArgs, signingBytes, type Approval, type Receipt, type ReceiptEnvelope, type ScopeBinding } from '../receipt.js';
import type { Decision } from '../engine.js';
import { keyIdForPublicKey } from '../signer.js';

/**
 * Test-only: mints mcp-guard 0.2 receipts with an in-memory key, so the legacy verifier
 * keeps its tamper tests after 0.3 stopped issuing this format.
 */

export interface LegacyInput {
  method: string;
  tool: string | null;
  args: Record<string, unknown> | undefined;
  decision: Decision;
  approval: Approval | null;
  actor: string;
  mode: 'enforce' | 'observe';
  policy_sha256: string;
  ttl_seconds: number;
  target_server: string;
  scope?: ScopeBinding;
  now?: Date;
}

const pair = generateKeyPairSync('ed25519');
export const LEGACY_PUBLIC_PEM = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
export const LEGACY_KEY_ID = keyIdForPublicKey(LEGACY_PUBLIC_PEM);

export function mintLegacy(input: LegacyInput): Receipt {
  const now = input.now ?? new Date();
  const envelope: ReceiptEnvelope = {
    v: 2,
    receipt_id: `rcpt_mg_${now.getTime().toString(36)}_${randomBytes(6).toString('hex')}`,
    method: input.method,
    tool: input.tool,
    args_sha256: hashArgs(input.args),
    scope: input.scope?.scope ? { scope: input.scope.scope, ref: input.scope.scope_ref ?? null, sha: input.scope.scope_sha ?? null } : null,
    decision: input.decision.decision,
    approval: input.approval,
    actor: input.actor,
    rule_id: input.decision.rule_id,
    policy_sha256: input.policy_sha256,
    mode: input.mode,
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + input.ttl_seconds * 1000).toISOString(),
    nonce: randomBytes(16).toString('hex'),
    key_id: LEGACY_KEY_ID,
  };
  return {
    envelope,
    signature: { alg: 'ed25519', key_id: LEGACY_KEY_ID, value: sign(null, Buffer.from(signingBytes(envelope)), pair.privateKey).toString('hex') },
    display: { summary: 's', reason: input.decision.reason, risk_tier: 'high', target_server: input.target_server, arg_keys: Object.keys(input.args ?? {}).sort(), viewer_url: '' },
  };
}
