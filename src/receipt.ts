import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import type { Decision } from './engine.js';
import { signReceiptPayload } from './signer.js';

const DEFAULT_RECEIPTS_PATH = process.env.PP_SHARED_RECEIPTS_PATH || 'pp-receipts.jsonl';
const DEFAULT_VIEWER_BASE_URL = process.env.PP_VIEWER_BASE_URL || 'https://app.permissionprotocol.com/r';

export interface ReceiptRiskSignal {
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  reason: string;
  files: string[];
}

export interface ReceiptVerificationStep {
  step: string;
  riskTier: 'low' | 'medium' | 'high';
}

export interface ReceiptEnrichmentSnapshot {
  summary: string;
  riskSignals: Array<{ category: string; severity: string; reason: string }>;
  verificationSteps: ReceiptVerificationStep[];
  confidenceWarnings: string[];
  linkedIssueTitle: string | null;
  generatedAt: string;
}

export interface ReceiptDiffFile {
  filename: string;
  status: 'modified';
  additions: number;
  deletions: number;
  changes: number;
  patch: string;
  previousFilename: null;
}

/**
 * Permission Deck Slice 2 — scope binding for code/infra receipts.
 *
 * Optional. Comms/spend receipts (Slice 1) carry no scope and remain back-compatible.
 * When present, scope is folded into the signed payload so the Ed25519 signature
 * covers it — a receipt for the wrong `scope_sha` cannot be replayed against a
 * different merge/migration/deploy.
 *
 *  - `scope`     — the action class, e.g. `github:merge`, `sql:migrate:production`, `deploy:staging`.
 *  - `scope_ref` — the git/logical ref, e.g. `refs/pull/16/merge`.
 *  - `scope_sha` — the exact commit/merge SHA the authority is bound to.
 */
export interface ScopeBinding {
  scope?: string;
  scope_ref?: string;
  scope_sha?: string;
}

export interface Receipt {
  receipt_id: string;
  status: 'AUTHORIZED' | 'DENIED' | 'AWAITING_APPROVAL';
  action: string;
  resource: string;
  scope: string | null;
  scope_ref: string | null;
  scope_sha: string | null;
  actor: string;
  approved_by: string | null;
  approved_by_avatar: string | null;
  approved_by_url: string | null;
  policy: string;
  risk_tier: 'low' | 'medium' | 'high' | 'critical';
  summary: string;
  timestamp: string;
  expires_at: string | null;
  signature: {
    algorithm: string | null;
    key_id: string | null;
    value: string | null;
    verified: boolean;
  };
  issuer: string;
  receipt_version: number;
  url: string;
  enrichmentSnapshot: ReceiptEnrichmentSnapshot;
  diff: {
    files: ReceiptDiffFile[];
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  };
  policy_details: {
    matched_rule_id: string | null;
    decision_reason: string;
    enforcement_mode: 'enforce' | 'observe';
    policy_name: string;
    outcome: Decision['decision'];
  };
  request_json: string;
  viewer_url: string;
  agent_id: string;
  tool_name: string;
  decision: Decision['decision'];
  reason: string;
  rule_id: string | null;
  request_payload_hash: string;
  target_server: string;
  mode: 'enforce' | 'observe';
}

function generateReceiptId(): string {
  return `rcpt_dg_${Date.now().toString(36)}_${randomBytes(6).toString('hex')}`;
}

function classifyRisk(toolName: string, requestPayload: unknown, decision: Decision): {
  tier: 'low' | 'medium' | 'high' | 'critical';
  signals: ReceiptRiskSignal[];
} {
  const text = JSON.stringify({ toolName, requestPayload, decision }).toLowerCase();
  const signals: ReceiptRiskSignal[] = [];

  const maybePush = (
    matches: boolean,
    signal: ReceiptRiskSignal,
  ): void => {
    if (matches) signals.push(signal);
  };

  maybePush(
    /(delete|destroy|drop|truncate|wipe|remove_user|removeaccount)/.test(text),
    {
      category: 'Data',
      severity: 'critical',
      reason: 'The request appears to delete, wipe, or irreversibly remove data.',
      files: ['arguments.json'],
    },
  );
  maybePush(
    /(prod|production|deploy|release|publish|billing|payment|invoice|auth|admin|secret|token|password|key)/.test(text),
    {
      category: 'Access',
      severity: 'high',
      reason: 'The request touches production, credentials, billing, auth, or privileged execution paths.',
      files: ['arguments.json'],
    },
  );
  maybePush(
    /(write|update|create|patch|modify|sync|email|notify)/.test(text),
    {
      category: 'Change',
      severity: 'medium',
      reason: 'The request mutates system state or external side effects.',
      files: ['arguments.json'],
    },
  );

  const tier = signals.some((signal) => signal.severity === 'critical')
    ? 'critical'
    : signals.some((signal) => signal.severity === 'high')
      ? 'high'
      : signals.some((signal) => signal.severity === 'medium')
        ? 'medium'
        : decision.decision === 'allowed'
          ? 'low'
          : 'medium';

  if (signals.length === 0) {
    signals.push({
      category: 'Tool',
      severity: tier,
      reason: 'The request was evaluated as a standard MCP tool invocation.',
      files: ['arguments.json'],
    });
  }

  return { tier, signals };
}

function buildArgsPatch(toolName: string, requestPayload: unknown): string {
  const rendered = JSON.stringify(requestPayload ?? {}, null, 2) || '{}';
  return `diff --git a/arguments.json b/arguments.json\n--- a/arguments.json\n+++ b/arguments.json\n@@ -0,0 +1,${rendered.split('\n').length} @@\n+${JSON.stringify({ tool: toolName, request: requestPayload ?? {} }, null, 2).split('\n').join('\n+')}`;
}

/**
 * Permission Deck Slice 2 — the canonical signing bytes for a receipt.
 *
 * Binds the receipt to its id, its request payload hash, AND (when present) its scope.
 * The scope fields are encoded as a versioned JSON envelope so the same input always
 * produces the same bytes, and so the offline verifier can reconstruct them from the
 * receipt alone without delimiter ambiguity.
 * Slice-1 (no-scope) receipts produce the original `<id>.<hash>` bytes unchanged, keeping
 * old signatures valid and back-compatible.
 */
export function buildSigningBytes(receipt: Pick<Receipt, 'receipt_id' | 'request_payload_hash' | 'scope' | 'scope_ref' | 'scope_sha'>): string {
  const hasScope = receipt.scope || receipt.scope_ref || receipt.scope_sha;
  if (!hasScope) {
    return `${receipt.receipt_id}.${receipt.request_payload_hash}`;
  }
  return `pp-receipt-scope-v2:${JSON.stringify({
    receipt_id: receipt.receipt_id,
    request_payload_hash: receipt.request_payload_hash,
    scope: receipt.scope ?? '',
    scope_ref: receipt.scope_ref ?? '',
    scope_sha: receipt.scope_sha ?? '',
  })}`;
}

export function createReceipt(
  agentId: string,
  toolName: string,
  decision: Decision,
  requestPayload: unknown,
  targetServer: string = 'unknown',
  mode: 'enforce' | 'observe' = 'enforce',
  scopeBinding?: ScopeBinding,
): Receipt {
  const payloadStr = JSON.stringify(requestPayload ?? {});
  const hash = createHash('sha256').update(payloadStr).digest('hex');
  const timestamp = new Date().toISOString();
  const receiptId = generateReceiptId();
  const viewerUrl = `${DEFAULT_VIEWER_BASE_URL.replace(/\/$/, '')}/${receiptId}`;
  const policyName = decision.rule_id ?? 'mcp-guard-default-policy';
  const risk = classifyRisk(toolName, requestPayload, decision);
  const summary = `AI summary: MCP Guard ${decision.decision.replace(/_/g, ' ')} for "${toolName}" because ${decision.reason.toLowerCase()}.`;
  const verificationSteps: ReceiptVerificationStep[] = [
    { step: `Matched policy rule ${decision.rule_id ?? 'default action'}`, riskTier: risk.tier === 'critical' ? 'high' : risk.tier === 'high' ? 'high' : 'medium' },
    { step: 'Hashed MCP request payload for audit integrity', riskTier: 'low' },
    { step: `Recorded ${decision.decision.replace(/_/g, ' ')} decision before forwarding`, riskTier: decision.decision === 'allowed' ? 'low' : 'high' },
  ];
  const diffPatch = buildArgsPatch(toolName, requestPayload);
  const requestJson = JSON.stringify({
    intent: {
      name: 'mcp_guard_decision',
      summary,
      category: 'mcp_tool_call',
    },
    action: {
      tool: toolName,
      operation: decision.decision,
      resource: targetServer,
    },
    context: {
      environment: targetServer,
      mode,
      agentId,
      transport: 'stdio',
      reversibility: risk.tier === 'critical' ? 'IRREVERSIBLE' : 'UNKNOWN',
    },
    scope: {
      tool: toolName,
      argsHash: hash,
      argumentKeys: Object.keys((requestPayload as Record<string, unknown> | null) ?? {}),
    },
    scopeBinding: {
      scope: scopeBinding?.scope ?? null,
      scope_ref: scopeBinding?.scope_ref ?? null,
      scope_sha: scopeBinding?.scope_sha ?? null,
    },
    metadata: {
      receiptKind: 'mcp_guard',
      receiptId,
      ruleId: decision.rule_id,
      reason: decision.reason,
    },
    policy: {
      version: 'mcp-guard-v1',
      mode,
      matchedRuleId: decision.rule_id,
      outcome: decision.decision,
    },
    enrichmentSnapshot: {
      summary,
      riskSignals: risk.signals.map((signal) => ({
        category: signal.category,
        severity: signal.severity,
        reason: signal.reason,
      })),
      verificationSteps,
      confidenceWarnings: mode === 'observe'
        ? ['Observe mode logs the decision but still forwards the tool call.']
        : [],
      linkedIssueTitle: null,
      generatedAt: timestamp,
    },
    diff: {
      files: [
        {
          filename: 'arguments.json',
          status: 'modified',
          additions: diffPatch.split('\n').filter((line) => line.startsWith('+') && !line.startsWith('+++')).length,
          deletions: 0,
          changes: diffPatch.split('\n').filter((line) => line.startsWith('+') && !line.startsWith('+++')).length,
          patch: diffPatch,
          previousFilename: null,
        },
      ],
      riskLevel: risk.tier,
    },
  });
  const publicStatus = decision.decision === 'allowed'
    ? 'AUTHORIZED'
    : decision.decision === 'blocked'
      ? 'DENIED'
      : 'AWAITING_APPROVAL';

  return {
    receipt_id: receiptId,
    status: publicStatus,
    action: toolName,
    resource: targetServer,
    scope: scopeBinding?.scope ?? null,
    scope_ref: scopeBinding?.scope_ref ?? null,
    scope_sha: scopeBinding?.scope_sha ?? null,
    actor: agentId,
    approved_by: null,
    approved_by_avatar: null,
    approved_by_url: null,
    policy: policyName,
    risk_tier: risk.tier,
    summary,
    timestamp,
    expires_at: null,
    signature: {
      algorithm: null,
      key_id: null,
      value: null,
      verified: false,
    },
    issuer: 'permissionprotocol.com',
    receipt_version: 1,
    url: viewerUrl,
    enrichmentSnapshot: {
      summary,
      riskSignals: risk.signals.map((signal) => ({
        category: signal.category,
        severity: signal.severity,
        reason: signal.reason,
      })),
      verificationSteps,
      confidenceWarnings: mode === 'observe'
        ? ['Observe mode logs the decision but still forwards the tool call.']
        : [],
      linkedIssueTitle: null,
      generatedAt: timestamp,
    },
    diff: {
      files: [
        {
          filename: 'arguments.json',
          status: 'modified',
          additions: diffPatch.split('\n').filter((line) => line.startsWith('+') && !line.startsWith('+++')).length,
          deletions: 0,
          changes: diffPatch.split('\n').filter((line) => line.startsWith('+') && !line.startsWith('+++')).length,
          patch: diffPatch,
          previousFilename: null,
        },
      ],
      riskLevel: risk.tier,
    },
    policy_details: {
      matched_rule_id: decision.rule_id,
      decision_reason: decision.reason,
      enforcement_mode: mode,
      policy_name: policyName,
      outcome: decision.decision,
    },
    request_json: requestJson,
    viewer_url: viewerUrl,
    agent_id: agentId,
    tool_name: toolName,
    decision: decision.decision,
    reason: decision.reason,
    rule_id: decision.rule_id,
    request_payload_hash: hash,
    target_server: targetServer,
    mode,
  };
}

/**
 * Permission Deck Slice 1 — sign an issued receipt with the local Ed25519 dev key.
 *
 * Mutates the receipt in place: marks it AUTHORIZED, records who approved it, and
 * populates the `signature` block (algorithm `ed25519`, key_id `pp-dev-1`, a real hex
 * signature value, verified:true). The signature binds the receipt_id + the request
 * payload hash so it is bound to this exact action. Returns the same receipt.
 *
 * This is the "issue signed receipt on approval" step of the loop — the proxy's
 * `verifyAuthorization()` gate remains the no-receipt-no-execution enforcement point.
 */
export function signReceipt(
  receipt: Receipt,
  approvedBy: string = 'permission-deck',
): Receipt {
  const signingBytes = buildSigningBytes(receipt);
  const sig = signReceiptPayload(signingBytes);
  receipt.signature = {
    algorithm: sig.algorithm,
    key_id: sig.key_id,
    value: sig.value,
    verified: sig.verified,
  };
  receipt.status = 'AUTHORIZED';
  receipt.approved_by = approvedBy;
  receipt.policy_details = {
    ...receipt.policy_details,
    outcome: 'allowed',
  };
  receipt.decision = 'allowed';
  return receipt;
}

export function emitReceipt(receipt: Receipt, receiptsPath: string = DEFAULT_RECEIPTS_PATH): void {
  const json = JSON.stringify(receipt);
  process.stderr.write(`[mcp-guard] receipt: ${json}\n`);
  process.stderr.write(`[mcp-guard] receipt viewer: ${receipt.viewer_url}\n`);
  try {
    appendFileSync(receiptsPath, json + '\n');
  } catch {
    // Best effort — don't crash the proxy if file write fails
  }

  const endpoint = process.env.PP_RECEIPT_ENDPOINT;
  if (!endpoint) {
    return;
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (process.env.PP_RECEIPT_TOKEN) {
    headers.Authorization = `Bearer ${process.env.PP_RECEIPT_TOKEN}`;
  }

  void fetch(endpoint, {
    method: 'POST',
    headers,
    body: json,
  }).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`[mcp-guard] receipt publish failed: ${message}\n`);
  });
}
