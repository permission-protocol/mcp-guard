import { TOOLS_CALL } from './config.js';
import type { Issuer, Decider, IssuedReceipt, ReasonCode } from './issuer.js';
import { ruleReason } from './issuer.js';
import type { PendingAction } from './pending.js';
import { verifyArtifactReceipt, type ExpectedScope } from './receipt-verify.js';
import type { ReplayCache } from './verify-core.js';
import { errorLine, RELEASE_FAILED } from './frame.js';

/**
 * The single release path for held calls (console approve, countdown, webhook PR).
 *
 * `signHeld` builds the receipt first and throws SigningError without side effects, so a
 * caller can sign BEFORE moving the item to a final state and leave it held on failure.
 * `forwardReleased` then verifies that receipt the way a gate would (own key set, pinned
 * by fingerprint, scope exact, single use) and forwards only if it passes.
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

/** Verify the release receipt against the guard's own pinned key; null when it passes. */
export function checkRelease(issuer: Issuer, action: PendingAction, issued: IssuedReceipt, replayCache: ReplayCache): string | null {
  if (!issued.artifact) return issued.unsigned ? null : `receipt was not signed (${issued.signingFailed ?? 'no signature'})`;
  let key;
  try {
    key = issuer.key();
  } catch (err) {
    return (err as Error).message;
  }
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
