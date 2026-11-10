import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import { TOOLS_CALL, type Config, type Rule } from './config.js';
import { evaluate, type Decision } from './engine.js';
import { Issuer, ruleReason, hashablePayloadInputHash, type IssuedReceipt, type ScopeBinding } from './issuer.js';
import { SigningError } from './keystore.js';
import { emitReceipt, emitHold, emitCloudDecision } from './receipt-log.js';
import { signHeld, forwardReleased, releaseOnCountdown } from './release.js';
import { ReplayCache } from './verify-core.js';
import { createCloudClient, type CloudClient } from './cloud/client.js';
import { decideInCloud, type CloudOutcome } from './cloud/hold.js';
import { fingerprintOfCall } from './cloud/fingerprint.js';
import { PRODUCTION_API_URL, PRODUCTION_KEY_SET, pinsFor } from './cloud/pinned-keys.js';
import { loadInstallToken } from './cloud/token.js';
import type { KeySet } from './signing/keys.js';
import {
  addPending,
  surfaceActed,
  setAutoReleaseHandler,
  setExpireHandler,
  type PendingAction,
  type PendingEnrichment,
} from './pending.js';
import { startApprovalServer, notifyQueueChange } from './approval-server.js';
import {
  parseFrame,
  errorLine,
  isPassthrough,
  toolCallTarget,
  stripAgentMetadata,
  serverInput,
  BLOCKED,
  HELD,
  EXPIRED,
  DENIED,
  RELEASE_FAILED,
  APPROVAL_UNAVAILABLE,
  INVALID_PARAMS,
  SIGNING_FAILED,
  type JsonRpcMessage,
} from './frame.js';

/**
 * Derive a one-line summary + the literal artifact preview from the tool name and args,
 * so the console can render a human-readable card. For capped spends the amount shown is
 * the argument the rule caps (`amountArg`), the same one the classifier read.
 */
export function derivePreview(
  toolName: string,
  toolArgs: Record<string, unknown> | undefined,
  amountArg?: string,
): { summary: string; args_preview: string } {
  const args = (toolArgs ?? {}) as Record<string, any>;
  const str = (v: unknown): string => (v === undefined || v === null ? '' : String(v));

  switch (toolName) {
    case 'send_email': {
      const to = str(args.to ?? args.recipient);
      const subject = str(args.subject);
      const body = str(args.body ?? args.text ?? args.message);
      const summary = `Send email${to ? ` to ${to}` : ''}${subject ? `: ${subject}` : ''}`.trim();
      return { summary, args_preview: body || subject || JSON.stringify(args) };
    }
    case 'post_x':
    case 'post_tweet': {
      const text = str(args.text ?? args.body ?? args.message ?? args.content);
      return { summary: 'Post to X', args_preview: text || JSON.stringify(args) };
    }
    case 'spend': {
      const amount = amountArg ? args[amountArg] : (args.amount_usd ?? args.amount);
      const payee = str(args.payee ?? args.to ?? args.recipient ?? args.vendor);
      const amountStr = amount !== undefined ? `$${amount}` : '';
      const preview = `${amountStr}${payee ? ` → ${payee}` : ''}`.trim();
      return { summary: `Spend ${preview || JSON.stringify(args)}`, args_preview: preview || JSON.stringify(args) };
    }
    default:
      return { summary: `Call ${toolName}`, args_preview: JSON.stringify(args) };
  }
}

/** Build the enrichment record for the queue from a classified Decision + args. */
export function buildEnrichment(
  decision: Decision,
  toolName: string,
  toolArgs: Record<string, unknown> | undefined,
  rule?: Rule | null,
): PendingEnrichment {
  const { summary, args_preview } = derivePreview(toolName, toolArgs, rule?.amount_arg);
  return {
    lane: decision.lane ?? 'decide',
    reversibility: decision.reversibility ?? 'irreversible',
    ...(decision.countdown_seconds !== undefined ? { countdown_seconds: decision.countdown_seconds } : {}),
    ...(decision.confidence !== undefined ? { confidence: decision.confidence } : {}),
    summary,
    args_preview,
  };
}

/**
 * Derive a receipt scope binding from the tool + args, for the code/infra tools the
 * offline receipt gate verifies:
 *   - merge_pr           -> `github:merge`, ref `refs/pull/<n>/merge`
 *   - run_sql_migration  -> `sql:migrate:<env>`
 *   - deploy             -> `deploy:<env>`
 * Other tools carry no scope.
 */
export function deriveScope(toolName: string, toolArgs: Record<string, unknown> | undefined): ScopeBinding | undefined {
  const args = (toolArgs ?? {}) as Record<string, any>;
  const str = (v: unknown): string | undefined => (v === undefined || v === null ? undefined : String(v));

  switch (toolName) {
    case 'merge_pr': {
      const prNumber = str(args.pr_number ?? args.pr ?? args.number);
      return {
        scope: 'github:merge',
        scope_ref: prNumber !== undefined ? `refs/pull/${prNumber}/merge` : undefined,
        scope_sha: str(args.scope_sha ?? args.head_sha ?? args.sha),
      };
    }
    case 'run_sql_migration':
      return {
        scope: `sql:migrate:${str(args.env ?? args.environment) ?? 'unknown'}`,
        scope_ref: str(args.scope_ref ?? args.migration ?? args.migration_id),
        scope_sha: str(args.scope_sha ?? args.sha),
      };
    case 'deploy':
      return {
        scope: `deploy:${str(args.env ?? args.environment) ?? 'unknown'}`,
        scope_ref: str(args.scope_ref ?? args.ref),
        scope_sha: str(args.scope_sha ?? args.sha),
      };
    default:
      return undefined;
  }
}

export interface ProxyOptions {
  approvalPort?: number;
  operator?: string;
}

/** What local-only mode prints wherever it holds a call: no person signed through Permission Protocol. */
export const LOCAL_ONLY_LABEL = 'local-only, unsigned by Permission Protocol';

export function startProxy(config: Config, agentId: string, serverCommand: string[], opts: ProxyOptions = {}): void {
  if (serverCommand.length === 0) {
    process.stderr.write('[mcp-guard] Error: no server command provided after --\n');
    process.exit(1);
  }

  const issuer = new Issuer({ config, agentId });
  if (config.signing === 'off') {
    process.stderr.write('[mcp-guard] WARNING: signing is off. Receipts are written unsigned and no gate accepts them.\n');
  } else {
    // Load the signing key up front: in enforce mode a missing, exposed or revoked key
    // stops the guard here instead of failing later. The signer never creates a key.
    try {
      const key = issuer.key();
      process.stderr.write(`[mcp-guard] Signing receipts with ${key.keyId} (${key.fingerprint})${key.demo ? ' [demo key: receipts are scope demo]' : ''}\n`);
    } catch (err) {
      if (!(err instanceof SigningError) || config.mode === 'enforce') throw err;
      process.stderr.write(`[mcp-guard] WARNING: ${err.message}. Observe mode forwards calls; their receipts are marked signingFailed.\n`);
    }
  }
  const replayCache = new ReplayCache();
  const approvalEnabled = opts.approvalPort !== undefined;

  // Cloud approvals: a held call is released only by a receipt a named human signed
  // through Permission Protocol, verified here against the pinned key. Configured in
  // the policy file; the token is the only thing read from the environment, and
  // nothing in the environment can turn verification off.
  const cloud = config.cloud;
  let cloudClient: CloudClient | null = null;
  let cloudKeySet: KeySet = PRODUCTION_KEY_SET;
  if (cloud) {
    cloudKeySet = cloud.api_url === PRODUCTION_API_URL ? PRODUCTION_KEY_SET : { issuer: cloud.api_url, keys: cloud.trust_keys ?? [] };
    try {
      cloudClient = createCloudClient({ apiUrl: cloud.api_url, token: loadInstallToken() });
      process.stderr.write(
        `[mcp-guard] Cloud approvals on: held calls need a signature at ${cloud.api_url} (pinned keys: ${cloudKeySet.keys.map((k) => k.key_id).join(', ')})\n`,
      );
    } catch (err: any) {
      // Enforce mode never runs without a way to get a signature. Observe mode forwards
      // everything anyway, so it says so and carries on.
      if (config.mode === 'enforce') throw err;
      process.stderr.write(`[mcp-guard] WARNING: ${err.message}. Observe mode forwards calls; held calls are recorded, not sent for signature.\n`);
    }
  } else {
    process.stderr.write(`[mcp-guard] Mode: ${LOCAL_ONLY_LABEL}. Holds are decided on this machine and no named approver is recorded. Add a "cloud:" section to the policy for signed approvals.\n`);
  }
  const cloudTrust = pinsFor(cloudKeySet);

  // The server (and anything the agent can make it echo) never sees the guard's own
  // secrets: approval token, webhook secret, receipt token, key location.
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('PP_')));
  const child: ChildProcess = spawn(serverCommand[0], serverCommand.slice(1), { stdio: ['pipe', 'pipe', 'inherit'], env: childEnv });
  child.on('error', (err) => {
    process.stderr.write(`[mcp-guard] Failed to start server: ${err.message}\n`);
    process.exit(1);
  });
  child.on('exit', (code) => {
    process.stderr.write(`[mcp-guard] Server exited with code ${code}\n`);
    process.exit(code ?? 1);
  });

  const toClient = (line: string): void => { process.stdout.write(line + '\n'); };
  const toServer = (msg: JsonRpcMessage): void => { child.stdin!.write(JSON.stringify(msg) + '\n'); };
  const forwardLine = (line: string): void => { child.stdin!.write(line + '\n'); };

  // Server → client traffic is passed through unchanged.
  createInterface({ input: child.stdout! }).on('line', toClient);

  /** Sign a policy decision for a gated call. Throws SigningError when it cannot sign. */
  function signPolicy(method: string, tool: string | null, input: Record<string, unknown> | undefined, decision: Decision): IssuedReceipt {
    return issuer.issue({
      method,
      tool,
      input,
      status: decision.decision === 'allowed' ? 'APPROVED' : 'DENIED',
      ruleId: decision.rule_id,
      reasonCodes: [ruleReason(decision.rule_id)],
      decider: { kind: 'policy' },
      reversibility: decision.reversibility,
      argKeys: Object.keys(input ?? {}).sort(),
      scope: tool ? deriveScope(tool, input) : undefined,
    });
  }

  if (approvalEnabled) {
    const server = startApprovalServer({
      port: opts.approvalPort!,
      issuer,
      operator: opts.operator,
      hooks: { release: (action, issued) => forwardReleased(issuer, action, issued, replayCache, forwardLine) },
    });
    server.ready.catch((err) => {
      process.stderr.write(`[mcp-guard] Approval server failed to start: ${err.message}\n`);
      process.exit(1);
    });

    // A countdown is a policy decision: signed as policy, never as a person. If it
    // cannot sign, the call stays held.
    setAutoReleaseHandler((action) => {
      releaseOnCountdown(issuer, action, replayCache, forwardLine);
      notifyQueueChange();
    });

    setExpireHandler((action) => {
      process.stderr.write(`[mcp-guard] Expired without a decision: "${action.tool_name}" (${action.id})\n`);
      if (action.kind === 'held') {
        try {
          const issued = signHeld(issuer, action, { kind: 'policy' }, 'DENIED', 'APPROVAL_EXPIRED');
          action.receipt_id = issued.record.id;
          emitReceipt(issued);
        } catch (err: any) {
          process.stderr.write(`[mcp-guard] Expiry of ${action.id} was not signed: ${err.message}\n`);
        }
        action.resolve(errorLine(action.jsonrpcId, EXPIRED, 'Approval request expired without a decision'));
      }
      notifyQueueChange();
    });
  }

  function gate(msg: JsonRpcMessage & { method: string }, isRequest: boolean): void {
    const id = msg.id ?? null;
    let allowedReceiptId: string | undefined;
    const reply = (line: string): void => { if (isRequest) toClient(line); };

    let tool: string | null = null;
    let args: Record<string, unknown> | undefined;
    if (msg.method === TOOLS_CALL) {
      const target = toolCallTarget(msg.params);
      if ('error' in target) { reply(errorLine(id, INVALID_PARAMS, target.error)); return; }
      tool = target.name;
      args = target.args;
    }

    const decision = evaluate(tool, args, config, msg.method);
    const rule = decision.rule_id ? config.rules.find((r) => r.id === decision.rule_id) ?? null : null;
    const forward = stripAgentMetadata(msg);
    // What the server will act on: tool arguments for tools/call, the params otherwise.
    // This is what the approver sees and what the receipt hashes.
    const forwardArgs = serverInput(forward, tool !== null);
    const label = tool ?? msg.method;

    const hold = (holdId: string | null): void => emitHold({
      id: holdId, method: msg.method, tool, agentId, ruleId: decision.rule_id,
      inputHash: hashablePayloadInputHash(tool ?? msg.method, msg.method, forwardArgs), createdAt: new Date().toISOString(),
    });

    // Allow and block are final policy decisions: signed now. A hold is not a decision:
    // it is recorded unsigned, and whatever resolves it is signed then.
    if (decision.decision !== 'held_for_approval') {
      let receipt: IssuedReceipt;
      try {
        receipt = signPolicy(msg.method, tool, forwardArgs, decision);
      } catch (err: any) {
        process.stderr.write(`[mcp-guard] ${err.message}\n`);
        if (decision.decision === 'allowed') {
          // Enforce mode: no receipt, no forward.
          if (isRequest) toClient(errorLine(id, SIGNING_FAILED, `Refused: ${err.message}`));
          else process.stderr.write(`[mcp-guard] Dropped notification "${label}": not signed\n`);
          return;
        }
        // A blocked call stays blocked whether or not its denial could be signed.
        if (isRequest) toClient(errorLine(id, BLOCKED, `Blocked: ${decision.reason}`));
        return;
      }
      emitReceipt(receipt);
      allowedReceiptId = receipt.record.id;
    }

    if (decision.decision === 'held_for_approval' && (!isRequest || config.mode === 'observe' || !approvalEnabled)) hold(null);

    if (!isRequest) {
      // A notification gets no response, so it can neither be held nor told it was blocked.
      if (decision.decision === 'allowed' || config.mode === 'observe') toServer(forward);
      else process.stderr.write(`[mcp-guard] Dropped ${decision.decision} notification "${label}"\n`);
      return;
    }

    if (config.mode === 'observe') {
      if (decision.decision !== 'allowed') {
        process.stderr.write(`[mcp-guard] OBSERVE: would ${decision.decision === 'blocked' ? 'block' : 'hold'} "${label}" but forwarding (observe mode)\n`);
      }
      toServer(forward);
      return;
    }

    if (decision.decision === 'allowed') {
      toServer(forward);
      if (approvalEnabled && decision.lane === 'verify') {
        const surfaced = surfaceActed({
          method: msg.method,
          toolName: label,
          toolArgs: forwardArgs,
          agentId,
          ruleId: decision.rule_id,
          enrichment: buildEnrichment(decision, label, forwardArgs, rule),
          receiptId: allowedReceiptId,
          ttlSeconds: config.approval_ttl_seconds,
        });
        notifyQueueChange();
        process.stderr.write(`[mcp-guard] Surfaced acted "${label}" in Verify (${surfaced.id})\n`);
      }
      return;
    }

    if (decision.decision === 'blocked') {
      toClient(errorLine(id, BLOCKED, `Blocked: ${decision.reason}`));
      return;
    }

    // held_for_approval
    if (cloud) {
      if (!cloudClient) {
        toClient(errorLine(id, APPROVAL_UNAVAILABLE, 'Blocked: cloud approvals are configured but not available'));
        return;
      }
      void holdInCloud(cloudClient, msg.method, tool, label, forward, forwardArgs, decision, id);
      return;
    }
    if (!approvalEnabled) {
      toClient(errorLine(id, HELD, `Held for approval (${LOCAL_ONLY_LABEL}): ${decision.reason}`));
      return;
    }
    const pending = addPending({
      method: msg.method,
      toolName: label,
      toolArgs: forwardArgs,
      agentId,
      ruleId: decision.rule_id,
      forwardLine: JSON.stringify(forward),
      jsonrpcId: id,
      resolve: toClient,
      enrichment: buildEnrichment(decision, label, forwardArgs, rule),
      ttlSeconds: config.approval_ttl_seconds,
      ...(tool ? deriveScope(tool, forwardArgs) : {}),
    });
    hold(pending.id);
    notifyQueueChange();
    process.stderr.write(`[mcp-guard] Held "${label}" for approval (${pending.id}) [${LOCAL_ONLY_LABEL}]\n`);
  }

  /**
   * A held call in cloud mode. The call is forwarded in exactly one place, below, and
   * only for a `released` outcome whose receipt fingerprint still equals the
   * fingerprint of the line about to be written to the server. Every other path
   * answers the client with an error and forwards nothing.
   */
  async function holdInCloud(
    client: CloudClient,
    method: string,
    tool: string | null,
    label: string,
    forward: JsonRpcMessage,
    forwardArgs: Record<string, unknown> | undefined,
    decision: Decision,
    id: JsonRpcMessage['id'] | null,
  ): Promise<void> {
    const rpcId = id ?? null;
    const line = JSON.stringify(forward);
    const server = config.server_label;
    const record = (outcome: CloudOutcome): void => emitCloudDecision({
      decision: outcome.kind,
      requestId: outcome.requestId,
      receiptId: outcome.kind === 'released' ? outcome.receipt.receiptId : outcome.kind === 'denied' ? outcome.receipt?.receiptId ?? null : null,
      receiptUrl: outcome.kind === 'released' || outcome.kind === 'denied' ? outcome.receiptUrl : null,
      fingerprint: outcome.fingerprint,
      method,
      tool,
      server,
      agentId,
      ruleId: decision.rule_id,
      decider: outcome.kind === 'released' ? outcome.receipt.decider : outcome.kind === 'denied' ? outcome.receipt?.decider ?? null : null,
      reason: outcome.kind === 'released' ? null : outcome.reason,
      code: outcome.kind === 'blocked' ? outcome.code : null,
      at: new Date().toISOString(),
      artifact: outcome.kind === 'released' || outcome.kind === 'denied' ? outcome.artifact : null,
    });

    let outcome: CloudOutcome;
    try {
      outcome = await decideInCloud({
        client,
        keySet: cloudKeySet,
        trust: cloudTrust,
        replayCache,
        server,
        tool: label,
        args: forwardArgs,
        agentId,
        environment: cloud!.environment,
        timeoutSeconds: cloud!.approval_timeout_seconds,
        onPending: ({ requestId, approvalUrl }) => {
          process.stderr.write(`[mcp-guard] Held "${label}" for signature (${requestId}). Sign or reject: ${approvalUrl ?? 'no approval URL returned'}\n`);
        },
      });
    } catch (err: any) {
      // decideInCloud does not throw; if it ever does, that is a block.
      outcome = { kind: 'blocked', requestId: null, fingerprint: fingerprintOfCall(server, label, forwardArgs), code: 'INTERNAL', reason: String(err?.message ?? err) };
    }

    if (outcome.kind === 'released') {
      // Last check, on the bytes about to be written: the receipt covers THIS line.
      const frame = parseFrame(line);
      const sending = frame.kind === 'request' ? serverInput(frame.msg, tool !== null) : undefined;
      if (frame.kind !== 'request' || fingerprintOfCall(server, label, sending) !== outcome.receipt.fingerprint) {
        outcome = { kind: 'blocked', requestId: outcome.requestId, fingerprint: outcome.fingerprint, code: 'RECEIPT_FINGERPRINT_MISMATCH', reason: 'The call changed after it was signed' };
      }
    }

    record(outcome);
    switch (outcome.kind) {
      case 'released':
        forwardLine(line);
        return;
      case 'denied':
        toClient(errorLine(rpcId, DENIED, `Denied: ${outcome.reason}`));
        return;
      case 'expired':
        toClient(errorLine(rpcId, EXPIRED, `Approval request expired without a signature: ${outcome.reason}`));
        return;
      case 'blocked':
        toClient(errorLine(rpcId, outcome.code.startsWith('RECEIPT_') || outcome.code.startsWith('REDEEM_') ? RELEASE_FAILED : APPROVAL_UNAVAILABLE, `Blocked: ${outcome.reason}`));
        return;
    }
  }

  // Client → server: parse, gate, and forward only what was evaluated.
  const stdinRL = createInterface({ input: process.stdin });
  stdinRL.on('line', (line) => {
    if (!line.trim()) return;
    const frame = parseFrame(line);
    switch (frame.kind) {
      case 'invalid':
        toClient(errorLine(frame.id, frame.code, frame.message));
        return;
      case 'response':
        toServer(frame.msg);
        return;
      case 'notification':
        if (isPassthrough(frame.msg.method)) toServer(frame.msg);
        else gate(frame.msg, false);
        return;
      case 'request':
        if (isPassthrough(frame.msg.method)) toServer(frame.msg);
        else gate(frame.msg, true);
        return;
    }
  });

  stdinRL.on('close', () => {
    child.stdin!.end();
  });

  process.on('SIGINT', () => child.kill('SIGINT'));
  process.on('SIGTERM', () => child.kill('SIGTERM'));
}
