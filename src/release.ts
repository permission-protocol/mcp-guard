import { TOOLS_CALL } from './config.js';
import type { Issuer, Decider, IssuedReceipt, ReasonCode } from './issuer.js';
import { ruleReason } from './issuer.js';
import { transition, type PendingAction } from './pending.js';
import { verifyArtifactReceipt, type CallInput, type ExpectedScope } from './receipt-verify.js';
import type { ReplayCache } from './verify-core.js';
import { emitReceipt } from './receipt-log.js';
import { errorLine, serverInput, RELEASE_FAILED, type JsonRpcMessage } from './frame.js';

/**
 * The single release path for held calls (console approve, countdown, webhook PR).
 *
 * `signHeld` builds the receipt first and throws SigningError without side effects, so a
 * caller can sign BEFORE moving the item to a final state and leave it held on failure.
 * `forwardReleased` then verifies that receipt the way a gate would (own key set, pinned
 * by fingerprint, scope exact, single use), bound to this queue item and to the exact
 * call it forwards, and forwards only if it passes.
 */

export function heldInput(action: PendingAction): { method: string; tool: string | null } {
  // A webhook PR has no MCP call behind it: it is the `merge_pr` tool under `github/merge`.
  return { method: action.method, tool: action.method === TOOLS_CALL || action.kind === 'external' ? action.tool_name : null };
}

export function signHeld(issuer: Issuer, action: PendingAction, decider: Decider, outcome: 'APPROVED' | 'DENIED', reason: ReasonCode): IssuedReceipt {
  const { method, tool } = heldInput(action);
  return issuer.issue({
    decisionId: action.id,
    method,
    tool,
    input: action.tool_args,
    status: outcome,
    ruleId: action.rule_id,
    reasonCodes: [ruleReason(action.rule_id), reason],
    decider,
    reversibility: action.reversibility,
    argKeys: Object.keys(action.tool_args ?? {}).sort(),
    ...(action.scope ? { scope: { scope: action.scope, scope_ref: action.scope_ref, scope_sha: action.scope_sha } } : {}),
    ...(action.kind === 'external' ? { resource: 'github-webhook' } : {}),
  });
}

/** The call the server will receive, read back from the line that is forwarded. */
export function forwardedCall(action: PendingAction, resource: string): CallInput | null {
  let msg: JsonRpcMessage;
  try { msg = JSON.parse(action.forwardLine); } catch { return null; }
  if (!msg || typeof msg.method !== 'string') return null;
  const isToolCall = msg.method === TOOLS_CALL;
  const tool = isToolCall ? (msg.params as { name?: unknown } | undefined)?.name : msg.method;
  if (typeof tool !== 'string') return null;
  return { tool, operation: msg.method, resource, input: serverInput(msg, isToolCall) };
}

/** Verify the release receipt against the guard's own pinned key; null when it passes. */
export function checkRelease(issuer: Issuer, action: PendingAction, issued: IssuedReceipt, replayCache: ReplayCache): string | null {
  if (!issued.artifact) return issued.unsigned ? null : `receipt was not signed (${issued.signingFailed ?? 'no signature'})`;
  let key;
  try {
    key = issuer.key();
  } catch (err) {
    return (err as Error).message;
  }
  const call = forwardedCall(action, action.kind === 'external' ? 'github-webhook' : issuer.serverLabel);
  if (!call) return 'the held call cannot be read back from its forwarded line';
  const expected: ExpectedScope | undefined = action.scope
    ? { scope: action.scope, ...(action.scope_ref ? { scope_ref: action.scope_ref } : {}), ...(action.scope_sha ? { scope_sha: action.scope_sha } : {}) }
    : undefined;
  const check = verifyArtifactReceipt({ artifact: issued.artifact }, key.keySet, {
    trust: new Map([[key.keyId, key.fingerprint]]),
    allowPolicyApproval: true,
    // The guard's own demo key may release demo calls; only external gates refuse demo receipts.
    allowDemo: true,
    replayCache,
    expected,
    // Checked before the receipt is consumed: this decision, and the exact call forwarded.
    call,
    idemKey: `mcp-guard:${action.id}`,
  });
  return check.valid ? null : check.reasons.join(' ');
}

/**
 * Forward a released held call only if its receipt verifies. On failure the waiting
 * client gets RELEASE_FAILED and nothing reaches the server.
 */
export function forwardReleased(
  issuer: Issuer,
  action: PendingAction,
  issued: IssuedReceipt,
  replayCache: ReplayCache,
  forward: (line: string) => void,
): void {
  const problem = checkRelease(issuer, action, issued, replayCache);
  if (problem) {
    action.resolve(errorLine(action.jsonrpcId, RELEASE_FAILED, `Release refused: ${problem}`));
    throw new Error(`release refused for ${action.id}: ${problem}`);
  }
  action.receipt_id = issued.record.id;
  forward(action.forwardLine);
}

/**
 * A countdown fired on a pending held call. Sign first; only then make it final. When it
 * cannot sign, the countdown stops and the call stays held for an operator or expiry.
 * Returns 'auto_released', 'pending' when it stayed held, or null when the countdown no
 * longer applies (already decided, or put on hold).
 */
export function releaseOnCountdown(
  issuer: Issuer,
  action: PendingAction,
  replayCache: ReplayCache,
  forward: (line: string) => void,
): 'auto_released' | 'pending' | null {
  if (action.status !== 'pending' || action.releaseAt === undefined) return null;
  let issued: IssuedReceipt;
  try {
    issued = signHeld(issuer, action, { kind: 'policy' }, 'APPROVED', 'COUNTDOWN_AUTO_RELEASE');
  } catch (err) {
    transition(action.id, 'hold');
    process.stderr.write(`[mcp-guard] Countdown release of "${action.tool_name}" (${action.id}) refused, still held: ${(err as Error).message}\n`);
    return 'pending';
  }
  const r = transition(action.id, 'auto_release');
  if (!r.ok) return null;
  process.stderr.write(`[mcp-guard] Auto-released (countdown) "${action.tool_name}" (${action.id})\n`);
  emitReceipt(issued);
  try {
    forwardReleased(issuer, r.action, issued, replayCache, forward);
  } catch (err) {
    process.stderr.write(`[mcp-guard] ${(err as Error).message}\n`);
  }
  return 'auto_released';
}
