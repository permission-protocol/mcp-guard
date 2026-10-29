import { spawn, type ChildProcess } from 'node:child_process';
import { basename } from 'node:path';
import { createInterface } from 'node:readline';
import { TOOLS_CALL, type Config, type Rule } from './config.js';
import { evaluate, type Decision } from './engine.js';
import { issueReceipt, emitReceipt, type Approval, type Receipt, type ScopeBinding } from './receipt.js';
import { verifyReceipt } from './receipt-verify.js';
import { currentKeyId, getPublicKeyPem } from './signer.js';
import { ReplayCache, type PinnedKeys } from './verify-core.js';
import {
  addPending,
  surfaceActed,
  setAutoReleaseHandler,
  setExpireHandler,
  type PendingAction,
  type PendingEnrichment,
} from './pending.js';
import { startApprovalServer, pushReceipt, notifyQueueChange } from './approval-server.js';
import {
  parseFrame,
  errorLine,
  isPassthrough,
  toolCallTarget,
  stripAgentMetadata,
  BLOCKED,
  HELD,
  EXPIRED,
  INVALID_PARAMS,
  RELEASE_FAILED,
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
        scope_ref: str(args.scope_ref) ?? (prNumber !== undefined ? `refs/pull/${prNumber}/merge` : undefined),
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

export function startProxy(config: Config, agentId: string, serverCommand: string[], opts: ProxyOptions = {}): void {
  if (serverCommand.length === 0) {
    process.stderr.write('[mcp-guard] Error: no server command provided after --\n');
    process.exit(1);
  }

  // Load the signing key up front: a missing or exposed key stops the guard here
  // instead of failing open later.
  const pinnedKeys: PinnedKeys = { [currentKeyId()]: getPublicKeyPem() };
  const replayCache = new ReplayCache();
  const targetServer = serverCommand.slice(0, 2).map((p) => basename(p)).join(' ');
  const approvalEnabled = opts.approvalPort !== undefined;

  const child: ChildProcess = spawn(serverCommand[0], serverCommand.slice(1), { stdio: ['pipe', 'pipe', 'inherit'] });
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

  // Server → client traffic is passed through unchanged.
  createInterface({ input: child.stdout! }).on('line', toClient);

  function record(
    method: string,
    tool: string | null,
    args: Record<string, unknown> | undefined,
    decision: Decision,
    approval: Approval | null,
    actor: string,
  ): Receipt {
    const receipt = issueReceipt({
      method,
      tool,
      args,
      decision,
      approval,
      actor,
      mode: config.mode,
      policy_sha256: config.policy_sha256,
      ttl_seconds: config.receipt_ttl_seconds,
      target_server: targetServer,
      scope: tool ? deriveScope(tool, args) : undefined,
    });
    emitReceipt(receipt);
    if (approvalEnabled) pushReceipt(receipt);
    return receipt;
  }

  /**
   * The single release path for held requests (manual approve and countdown): issue the
   * signed receipt, verify it against the pinned key, and only then forward.
   */
  function release(action: PendingAction, approval: Approval): Receipt {
    const tool = action.method === TOOLS_CALL ? action.tool_name : null;
    const decision: Decision = {
      decision: 'allowed',
      rule_id: action.rule_id,
      reason: `Released by ${approval.kind} "${approval.id}" (${approval.via})`,
    };
    const receipt = record(action.method, tool, action.tool_args, decision, approval, action.agent_id);
    const check = verifyReceipt(receipt, pinnedKeys, { replayCache, allowPolicyApproval: true });
    if (!check.valid) {
      action.resolve(errorLine(action.jsonrpcId, RELEASE_FAILED, `Release refused: ${check.reasons.join(' ')}`));
      throw new Error(`release refused for ${action.id}: ${check.reasons.join(' ')}`);
    }
    action.receipt_id = receipt.envelope.receipt_id;
    child.stdin!.write(action.forwardLine + '\n');
    return receipt;
  }

  if (approvalEnabled) {
    const server = startApprovalServer({
      port: opts.approvalPort!,
      operator: opts.operator,
      hooks: { release },
      receiptTtlSeconds: config.receipt_ttl_seconds,
      policySha256: config.policy_sha256,
    });
    server.ready.catch((err) => {
      process.stderr.write(`[mcp-guard] Approval server failed to start: ${err.message}\n`);
      process.exit(1);
    });

    setAutoReleaseHandler((action) => {
      process.stderr.write(`[mcp-guard] Auto-released (countdown) "${action.tool_name}" (${action.id})\n`);
      try {
        release(action, { kind: 'policy', id: action.rule_id ?? 'default_action', via: 'countdown' });
      } catch (err: any) {
        process.stderr.write(`[mcp-guard] ${err.message}\n`);
      }
      notifyQueueChange();
    });

    setExpireHandler((action) => {
      process.stderr.write(`[mcp-guard] Expired without a decision: "${action.tool_name}" (${action.id})\n`);
      if (action.kind === 'held') action.resolve(errorLine(action.jsonrpcId, EXPIRED, 'Approval request expired without a decision'));
      notifyQueueChange();
    });
  }

  function gate(msg: JsonRpcMessage & { method: string }, isRequest: boolean): void {
    const id = msg.id ?? null;
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
    const forwardArgs = tool ? (forward.params as { arguments?: Record<string, unknown> }).arguments : undefined;
    const label = tool ?? msg.method;
    const policyApproval: Approval | null =
      decision.decision === 'allowed'
        ? { kind: 'policy', id: decision.rule_id ?? 'default_action', via: decision.lane === 'verify' ? 'standing_rule' : 'rule' }
        : null;
    const receipt = record(msg.method, tool, forwardArgs, decision, policyApproval, agentId);

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
          receiptId: receipt.envelope.receipt_id,
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
    if (!approvalEnabled) {
      toClient(errorLine(id, HELD, `Held for approval: ${decision.reason}`));
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
    });
    notifyQueueChange();
    process.stderr.write(`[mcp-guard] Held "${label}" for approval (${pending.id})\n`);
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
