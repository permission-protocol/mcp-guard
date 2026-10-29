import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import stableStringify from 'fast-json-stable-stringify';
import type { Decision } from './engine.js';
import { currentKeyId, signBytes, SIGN_ALGORITHM } from './signer.js';

/**
 * Receipt v2.
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

export interface ReceiptInput {
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

export function signingBytes(envelope: ReceiptEnvelope): string {
  return SIGNING_DOMAIN + stableStringify(envelope);
}

/** sha256 of the canonical JSON of the arguments the server receives. */
export function hashArgs(args: Record<string, unknown> | undefined): string {
  return createHash('sha256').update(stableStringify(args ?? {})).digest('hex');
}

function toScope(binding: ScopeBinding | undefined): ReceiptScope | null {
  if (!binding?.scope) return null;
  return { scope: binding.scope, ref: binding.scope_ref ?? null, sha: binding.scope_sha ?? null };
}

function classifyRisk(tool: string, argKeys: string[]): ReceiptDisplay['risk_tier'] {
  const text = `${tool} ${argKeys.join(' ')}`.toLowerCase();
  if (/(delete|destroy|drop|truncate|wipe|remove)/.test(text)) return 'critical';
  if (/(prod|deploy|release|publish|billing|payment|spend|merge|migrat|auth|admin|secret|token|password|key)/.test(text)) return 'high';
  if (/(write|update|create|patch|modify|sync|email|post|notify)/.test(text)) return 'medium';
  return 'low';
}

/** Build and sign a receipt. */
export function issueReceipt(input: ReceiptInput): Receipt {
  const now = input.now ?? new Date();
  const receiptId = `rcpt_mg_${now.getTime().toString(36)}_${randomBytes(6).toString('hex')}`;
  const argKeys = Object.keys(input.args ?? {}).sort();
  const label = input.tool ?? input.method;

  const unsigned: Omit<ReceiptEnvelope, 'key_id'> = {
    v: RECEIPT_VERSION,
    receipt_id: receiptId,
    method: input.method,
    tool: input.tool,
    args_sha256: hashArgs(input.args),
    scope: toScope(input.scope),
    decision: input.decision.decision,
    approval: input.approval,
    actor: input.actor,
    rule_id: input.decision.rule_id,
    policy_sha256: input.policy_sha256,
    mode: input.mode,
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + input.ttl_seconds * 1000).toISOString(),
    nonce: randomBytes(16).toString('hex'),
  };
  // The key id is part of the signed envelope, so resolve it before signing.
  const envelope: ReceiptEnvelope = { ...unsigned, key_id: currentKeyId() };
  const sig = signBytes(signingBytes(envelope));

  const viewerBase = (process.env.PP_VIEWER_BASE_URL || 'https://app.permissionprotocol.com/r').replace(/\/$/, '');
  const by = input.approval ? ` by ${input.approval.kind} ${input.approval.id}` : '';
  return {
    envelope,
    signature: { alg: SIGN_ALGORITHM, key_id: sig.keyId, value: sig.value },
    display: {
      summary: `MCP Guard ${input.decision.decision.replace(/_/g, ' ')} "${label}"${by}`,
      reason: input.decision.reason,
      risk_tier: classifyRisk(label, argKeys),
      target_server: input.target_server,
      arg_keys: argKeys,
      viewer_url: `${viewerBase}/${receiptId}`,
    },
  };
}

export function defaultReceiptsPath(): string {
  return process.env.PP_SHARED_RECEIPTS_PATH || 'pp-receipts.jsonl';
}

/** Log, persist and (optionally) publish a receipt. Receipts never hold raw arguments. */
export function emitReceipt(receipt: Receipt, receiptsPath: string = defaultReceiptsPath()): void {
  const e = receipt.envelope;
  const json = JSON.stringify(receipt);
  process.stderr.write(`[mcp-guard] receipt ${e.receipt_id} ${e.decision} "${e.tool ?? e.method}"${e.approval ? ` (${e.approval.kind}:${e.approval.id})` : ''}\n`);
  try {
    appendFileSync(receiptsPath, json + '\n');
  } catch {
    // Best effort — don't crash the proxy if file write fails
  }

  const endpoint = process.env.PP_RECEIPT_ENDPOINT;
  if (!endpoint) return;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (process.env.PP_RECEIPT_TOKEN) headers.Authorization = `Bearer ${process.env.PP_RECEIPT_TOKEN}`;
  void fetch(endpoint, { method: 'POST', headers, body: json }).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`[mcp-guard] receipt publish failed: ${message}\n`);
  });
}
