import { createHash } from 'node:crypto';
import stableStringify from 'fast-json-stable-stringify';
import type { Decision } from './engine.js';

/**
 * LEGACY: the mcp-guard 0.2 receipt ("receipt v2"). 0.3 issues the org receipt standard
 * (src/issuer.ts) and only verifies these, when a gate passes --accept-legacy.
 *
 * A receipt is a small signed ENVELOPE — the fields a verifier decides on — plus an
 * unsigned DISPLAY block generated from it for humans. The signature covers
 * `SIGNING_DOMAIN + canonical JSON(envelope)`, so every authority-relevant field is
 * bound and no field boundary can be re-interpreted. Verifiers never read `display`.
 *
 * Receipts never carry raw tool arguments: only their sha256 (`args_sha256`) and the
 * argument names. Raw arguments are shown only in the authenticated approval queue.
 */

export const RECEIPT_VERSION = 2;
export const SIGNING_DOMAIN = 'pp-mcp-guard-receipt-v2\n';

export type ApprovalKind = 'human' | 'policy';

/** Who or what authorized the action. `via` names the channel or mechanism. */
export interface Approval {
  kind: ApprovalKind;
  id: string;
  via: string;
}

/** Scope binding for code/infra actions, as derived from a request. */
export interface ScopeBinding {
  scope?: string;
  scope_ref?: string;
  scope_sha?: string;
}

export interface ReceiptScope {
  scope: string;
  ref: string | null;
  sha: string | null;
}

export interface ReceiptEnvelope {
  v: 2;
  receipt_id: string;
  method: string;
  tool: string | null;
  args_sha256: string;
  scope: ReceiptScope | null;
  decision: Decision['decision'];
  approval: Approval | null;
  actor: string;
  rule_id: string | null;
  policy_sha256: string;
  mode: 'enforce' | 'observe';
  issued_at: string;
  expires_at: string;
  nonce: string;
  key_id: string;
}

export interface ReceiptDisplay {
  summary: string;
  reason: string;
  risk_tier: 'low' | 'medium' | 'high' | 'critical';
  target_server: string;
  arg_keys: string[];
  viewer_url: string;
}

export interface Receipt {
  envelope: ReceiptEnvelope;
  signature: { alg: 'ed25519'; key_id: string; value: string };
  display: ReceiptDisplay;
}

export function signingBytes(envelope: ReceiptEnvelope): string {
  return SIGNING_DOMAIN + stableStringify(envelope);
}

/** sha256 of the canonical JSON of the arguments the server receives. */
export function hashArgs(args: Record<string, unknown> | undefined): string {
  return createHash('sha256').update(stableStringify(args ?? {})).digest('hex');
}
