import { dirname, join, resolve } from 'node:path';
import { loadConfig, TOOLS_CALL, type Config } from '../config.js';
import { evaluate, type Decision } from '../engine.js';
import { Issuer, ruleReason, hashablePayloadInputHash } from '../issuer.js';
import { SigningError } from '../keystore.js';
import { emitReceipt, emitHold, emitCloudDecision } from '../receipt-log.js';
import { ReplayCache } from '../verify-core.js';
import { createCloudClient } from '../cloud/client.js';
import { decideInCloud, type CloudOutcome } from '../cloud/hold.js';
import { fingerprintOfCall } from '../cloud/fingerprint.js';
import { PRODUCTION_API_URL, PRODUCTION_KEY_SET, pinsFor } from '../cloud/pinned-keys.js';
import { loadInstallToken } from '../cloud/token.js';
import { LOCAL_ONLY_LABEL } from '../proxy.js';
import type { KeySet } from '../signing/keys.js';
import { HookInputError, type HookAdapter, type HookCall, type HookVerdict } from './adapter.js';
import { ResumeStore, resumingClient } from './resume.js';

/**
 * The decision path for every hook adapter: the same policy, the same `evaluate`, the
 * same receipts and the same cloud hold-and-verify (`decideInCloud`, which verifies the
 * receipt offline with cloud/verify.ts) as the proxy.
 *
 * FAIL CLOSED. Every path that is not a policy `allowed` (or observe mode) and not a
 * verified, redeemed APPROVED receipt ends in `deny`. A policy-allowed call touches no
 * network.
 */

export const DEFAULT_HOOK_WAIT_SECONDS = 240;
/** Added to the wait for the install step's hook `timeout`: room for the last status read and the redeem. */
export const HOOK_TIMEOUT_MARGIN_SECONDS = 60;
export const MAX_HOOK_WAIT_SECONDS = 3600;

export interface HookOptions {
  adapter: HookAdapter;
  configPath: string;
  /** How long a held call waits for a signature inside this hook run. */
  waitSeconds: number;
  modeOverride?: 'enforce' | 'observe';
  resumeStore?: ResumeStore;
  /** Receipt log. Default: PP_SHARED_RECEIPTS_PATH, else pp-receipts.jsonl beside the policy file. */
  receiptsPath?: string;
}

/**
 * The hook's working directory is wherever Claude Code is, so a cwd-relative log would
 * scatter across subdirectories. The hook anchors it beside the policy instead. The
 * proxy keeps receipt-log.ts's own default.
 */
export function hookReceiptsPath(configPath: string, env: NodeJS.ProcessEnv = process.env): string {
  return env.PP_SHARED_RECEIPTS_PATH || join(dirname(resolve(configPath)), 'pp-receipts.jsonl');
}

const PREFIX = 'mcp-guard:';

/** Rule id, detector and kind only. Never `effect.target` or any argument text. */
export function ruleLabel(decision: Decision, defaultAction: string): string {
  if (!decision.rule_id) return `default_action "${defaultAction}" (no rule matched)`;
  const e = decision.effect;
  if (!e) return `rule "${decision.rule_id}"`;
  return `rule "${decision.rule_id}" (${e.detector}: ${e.parsed ? e.kind : 'unreadable argument, fail-safe'})`;
}

const deny = (reason: string): HookVerdict => ({ kind: 'deny', reason: `${PREFIX} ${reason}` });

export async function decideHook(raw: string, opts: HookOptions): Promise<HookVerdict> {
  const { adapter } = opts;
  const receipts = opts.receiptsPath ?? hookReceiptsPath(opts.configPath);

  let config: Config;
  try {
    config = loadConfig(opts.configPath);
  } catch (err: any) {
    return deny(`denied: the policy could not be loaded (${err?.message ?? err}). Fix the policy file; every call is refused until it loads.`);
  }
  if (opts.modeOverride) config.mode = opts.modeOverride;

  let call: HookCall;
  try {
    call = adapter.parse(raw);
  } catch (err) {
    const code = err instanceof HookInputError ? err.code : 'HOOK_INPUT_MALFORMED';
    const message = err instanceof HookInputError ? err.message : 'the hook event could not be read';
    return deny(`denied: ${code}: ${message}.`);
  }

  // Receipts name the agent, not an MCP server.
  const hookConfig: Config = { ...config, server_label: adapter.serverLabel };
  const issuer = new Issuer({ config: hookConfig, agentId: adapter.agentId });
  if (config.signing === 'required') {
    try {
      issuer.key();
    } catch (err) {
      if (!(err instanceof SigningError) || config.mode === 'enforce') {
        const message = err instanceof Error ? err.message : String(err);
        return deny(`denied: no receipt can be signed (${message}). Fix: npx @permission-protocol/mcp-guard keys init`);
      }
      process.stderr.write(`[mcp-guard] WARNING: ${err.message}. Observe mode lets calls through; their receipts are marked signingFailed.\n`);
    }
  }

  const decision = evaluate(call.tool, call.args, config, TOOLS_CALL);
  const label = ruleLabel(decision, config.default_action);

  const hold = (): void => emitHold({
    id: null, method: TOOLS_CALL, tool: call.tool, agentId: adapter.agentId, ruleId: decision.rule_id,
    inputHash: hashablePayloadInputHash(call.tool, TOOLS_CALL, call.args), createdAt: new Date().toISOString(),
  }, receipts);

  // Allow and block are final policy decisions: signed now, as the proxy does.
  if (decision.decision !== 'held_for_approval') {
    try {
      emitReceipt(issuer.issue({
        method: TOOLS_CALL,
        tool: call.tool,
        input: call.args,
        status: decision.decision === 'allowed' ? 'APPROVED' : 'DENIED',
        ruleId: decision.rule_id,
        reasonCodes: [ruleReason(decision.rule_id)],
        decider: { kind: 'policy' },
        reversibility: decision.reversibility,
        argKeys: Object.keys(call.args).sort(),
      }), receipts);
    } catch (err: any) {
      // Enforce mode: no receipt, no call. A blocked call stays blocked either way.
      if (decision.decision === 'allowed') return deny(`denied: the decision could not be signed (${err?.message ?? err}).`);
      return deny(`blocked by ${label}.`);
    }
  } else if (config.mode === 'observe') {
    hold();
  }

  if (config.mode === 'observe') {
    if (decision.decision !== 'allowed') {
      process.stderr.write(`[mcp-guard] OBSERVE: would ${decision.decision === 'blocked' ? 'block' : 'hold'} "${call.tool}" (${label}) but letting it through (observe mode)\n`);
    }
    return { kind: 'pass' };
  }

  if (decision.decision === 'allowed') return { kind: 'pass' };
  if (decision.decision === 'blocked') return deny(`blocked by ${label}.`);

  // held_for_approval
  const cloud = config.cloud;
  if (!cloud) {
    hold();
    return deny(`held by ${label} for approval (${LOCAL_ONLY_LABEL}). A hook cannot wait for the local approval UI: add a "cloud:" section to the policy so a named person can sign it in Permission Protocol.`);
  }

  let token: string;
  try {
    token = loadInstallToken();
  } catch (err: any) {
    hold();
    return deny(`held by ${label}, but cloud approvals are not available (${err?.code ?? 'INSTALL_TOKEN_ERROR'}): ${err?.message ?? err}`);
  }

  const keySet: KeySet = cloud.api_url === PRODUCTION_API_URL ? PRODUCTION_KEY_SET : { issuer: cloud.api_url, keys: cloud.trust_keys ?? [] };
  const store = opts.resumeStore ?? new ResumeStore();
  const client = resumingClient(createCloudClient({ apiUrl: cloud.api_url, token }), store, cloud.approval_timeout_seconds);
  const waitSeconds = Math.max(0, Math.min(opts.waitSeconds, cloud.approval_timeout_seconds));
  const server = adapter.serverLabel;
  let approvalUrl: string | null = null;
  let pendingId: string | null = null;

  let outcome: CloudOutcome;
  try {
    outcome = await decideInCloud({
      client,
      keySet,
      trust: pinsFor(keySet),
      replayCache: new ReplayCache(),
      server,
      tool: call.tool,
      args: call.args,
      agentId: adapter.agentId,
      environment: cloud.environment,
      timeoutSeconds: waitSeconds,
      onPending: ({ requestId, approvalUrl: url }) => {
        pendingId = requestId;
        approvalUrl = url;
        process.stderr.write(`[mcp-guard] Held "${call.tool}" for signature (${requestId})${client.resumed ? ' [resumed]' : ''}. Sign or reject: ${url ?? 'no approval URL returned'}\n`);
      },
    });
  } catch (err: any) {
    // decideInCloud does not throw; if it ever does, that is a block.
    outcome = { kind: 'blocked', requestId: null, fingerprint: fingerprintOfCall(server, call.tool, call.args), code: 'INTERNAL', reason: String(err?.message ?? err) };
  }

  // The agent runs the input it sent; the receipt must cover exactly that.
  if (outcome.kind === 'released' && fingerprintOfCall(server, call.tool, call.args) !== outcome.receipt.fingerprint) {
    outcome = { kind: 'blocked', requestId: outcome.requestId, fingerprint: outcome.fingerprint, code: 'RECEIPT_FINGERPRINT_MISMATCH', reason: 'The call changed after it was signed' };
  }

  emitCloudDecision({
    decision: outcome.kind,
    requestId: outcome.requestId,
    receiptId: outcome.kind === 'released' ? outcome.receipt.receiptId : outcome.kind === 'denied' ? outcome.receipt?.receiptId ?? null : null,
    receiptUrl: outcome.kind === 'released' || outcome.kind === 'denied' ? outcome.receiptUrl : null,
    fingerprint: outcome.fingerprint,
    method: TOOLS_CALL,
    tool: call.tool,
    server,
    agentId: adapter.agentId,
    ruleId: decision.rule_id,
    decider: outcome.kind === 'released' ? outcome.receipt.decider : outcome.kind === 'denied' ? outcome.receipt?.decider ?? null : null,
    reason: outcome.kind === 'released' ? null : outcome.reason,
    code: outcome.kind === 'blocked' ? outcome.code : null,
    at: new Date().toISOString(),
    artifact: outcome.kind === 'released' || outcome.kind === 'denied' ? outcome.artifact : null,
  }, receipts);

  // Only a request still pending after this run's wait is worth resuming.
  const waitRanOut = outcome.kind === 'expired' && client.lastStatus === 'pending';
  if (!waitRanOut) store.remove(outcome.fingerprint);

  switch (outcome.kind) {
    case 'released': {
      const who = outcome.receipt.decider.display ?? outcome.receipt.decider.id;
      return { kind: 'allow', reason: `${PREFIX} released by receipt ${outcome.receipt.receiptId}, signed by ${who} in Permission Protocol (${label}).` };
    }
    case 'denied':
      return deny(`denied in Permission Protocol (${label}): ${outcome.reason}${outcome.receipt ? ` [receipt ${outcome.receipt.receiptId}]` : ''}. Do not retry this call unchanged.`);
    case 'expired':
      if (waitRanOut) {
        return deny(
          `held by ${label} for a Permission Protocol signature; nobody signed within the hook's ${waitSeconds}-second wait. ` +
          `Request ${pendingId ?? outcome.requestId ?? 'unknown'} stays open for up to ${cloud.approval_timeout_seconds} seconds` +
          `${approvalUrl ? `: sign it at ${approvalUrl}` : ''}. After it is signed, run exactly the same call again; the guard resumes that request instead of opening a new one.`,
        );
      }
      return deny(`held by ${label}; the approval request expired without a signature (${outcome.reason}). Running the same call again opens a new request.`);
    case 'blocked':
      return deny(`held by ${label} and not released (${outcome.code}): ${outcome.reason}.`);
  }
}
