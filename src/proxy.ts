import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { Config } from './config.js';
import { evaluate, type Decision } from './engine.js';
import { createReceipt, emitReceipt, signReceipt } from './receipt.js';
import {
  addPending,
  surfaceActed,
  getAction,
  resolveAction,
  setAutoReleaseHandler,
  setUndoHandler,
  type PendingAction,
  type PendingEnrichment,
} from './pending.js';
import { startApprovalServer, setOnApprove, pushReceipt, notifyQueueChange } from './approval-server.js';

/**
 * Permission Deck Slice 1 — derive a one-line summary + the literal artifact preview
 * from the tool name and args, so the console can render a human-readable card without
 * re-parsing raw JSON-RPC. e.g. send_email -> the body, spend -> "$N → payee".
 */
export function derivePreview(
  toolName: string,
  toolArgs: Record<string, unknown> | undefined,
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
      const amount = args.amount_usd ?? args.amount;
      const payee = str(args.payee ?? args.to ?? args.recipient ?? args.vendor);
      const amountStr = amount !== undefined ? `$${amount}` : '';
      const preview = `${amountStr}${payee ? ` → ${payee}` : ''}`.trim();
      return { summary: `Spend ${preview || JSON.stringify(args)}`, args_preview: preview || JSON.stringify(args) };
    }
    default: {
      const preview = JSON.stringify(args);
      return { summary: `Call ${toolName}`, args_preview: preview };
    }
  }
}

/** Build the enrichment record for addPending from a classified Decision + args. */
export function buildEnrichment(
  decision: Decision,
  toolName: string,
  toolArgs: Record<string, unknown> | undefined,
): PendingEnrichment {
  const { summary, args_preview } = derivePreview(toolName, toolArgs);
  return {
    lane: decision.lane ?? 'decide',
    reversibility: decision.reversibility ?? 'irreversible',
    ...(decision.countdown_seconds !== undefined ? { countdown_seconds: decision.countdown_seconds } : {}),
    ...(decision.confidence !== undefined ? { confidence: decision.confidence } : {}),
    summary,
    args_preview,
  };
}

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: any;
}

interface JsonRpcError {
  jsonrpc: '2.0';
  id: string | number | null;
  error: {
    code: number;
    message: string;
  };
}

export function startProxy(config: Config, agentId: string, serverCommand: string[], approvalPort?: number): void {
  if (serverCommand.length === 0) {
    process.stderr.write('[mcp-guard] Error: no server command provided after --\n');
    process.exit(1);
  }

  const approvalEnabled = approvalPort !== undefined;

  // Start approval server if enabled
  if (approvalEnabled) {
    startApprovalServer(approvalPort);
  }

  const child: ChildProcess = spawn(serverCommand[0], serverCommand.slice(1), {
    stdio: ['pipe', 'pipe', 'inherit'],
  });

  child.on('error', (err) => {
    process.stderr.write(`[mcp-guard] Failed to start server: ${err.message}\n`);
    process.exit(1);
  });

  child.on('exit', (code) => {
    process.stderr.write(`[mcp-guard] Server exited with code ${code}\n`);
    process.exit(code ?? 1);
  });

  // Track pending approval responses waiting for child stdout
  const pendingChildResponses: Map<string | number, (line: string) => void> = new Map();

  // Forward child stdout → our stdout (or to pending resolver)
  const childOut = createInterface({ input: child.stdout! });
  childOut.on('line', (line) => {
    // Check if this is a response to a forwarded approval
    try {
      const parsed = JSON.parse(line);
      const id = parsed.id;
      if (id != null && pendingChildResponses.has(id)) {
        const resolver = pendingChildResponses.get(id)!;
        pendingChildResponses.delete(id);
        resolver(line);
        return;
      }
    } catch {
      // not JSON, pass through
    }
    process.stdout.write(line + '\n');
  });

  /**
   * Release an authorized action: issue a signed Ed25519 receipt, forward the original
   * request to the child server, and stamp the receipt_id on the pending item. This is
   * the single release path shared by manual approve and countdown auto-release.
   */
  function releaseAction(action: PendingAction, approvedBy: string): void {
    const serverName = serverCommand.join(' ');
    // Re-evaluate to get a Decision for the receipt; force outcome to allowed via sign.
    const decision = evaluate(action.tool_name, action.tool_args, config);
    const receipt = createReceipt(action.agent_id, action.tool_name, decision, action.tool_args, serverName, config.mode);
    signReceipt(receipt, approvedBy);
    action.receipt_id = receipt.receipt_id;
    emitReceipt(receipt);
    if (approvalEnabled) pushReceipt(receipt);

    // Register a listener for the child's response, then forward the original request.
    if (action.jsonrpcId != null) {
      pendingChildResponses.set(action.jsonrpcId, (responseLine: string) => {
        action.resolve(responseLine);
      });
    }
    child.stdin!.write(action.originalLine + '\n');
  }

  // Set up approval callback — when UI approves, forward original request to child
  if (approvalEnabled) {
    setOnApprove((actionId: string) => {
      const action = getAction(actionId);
      if (!action) return;
      releaseAction(action, 'permission-deck-operator');
    });

    // Countdown auto-release: classifier-marked reversible holds self-clear unless held.
    setAutoReleaseHandler((actionId: string) => {
      const action = resolveAction(actionId, 'auto_released');
      if (!action) return;
      process.stderr.write(`[mcp-guard] Auto-released (countdown) "${action.tool_name}" (${actionId})\n`);
      releaseAction(action, 'auto-release-countdown');
      notifyQueueChange();
    });

    // Undo: best-effort cancel of the forwarded stub (Slice 1 logs; real adapter no-op).
    setUndoHandler((action: PendingAction) => {
      process.stderr.write(`[mcp-guard] Undo requested for "${action.tool_name}" (${action.id}) — best-effort cancel\n`);
    });
  }

  // Read our stdin, inspect, and forward or reject
  const stdinRL = createInterface({ input: process.stdin });
  stdinRL.on('line', (line) => {
    if (!line.trim()) return;

    let msg: JsonRpcRequest;
    try {
      msg = JSON.parse(line);
    } catch {
      // Not valid JSON — forward as-is
      child.stdin!.write(line + '\n');
      return;
    }

    if (msg.method === 'tools/call') {
      const toolName: string = msg.params?.name ?? 'unknown';
      const toolArgs: Record<string, unknown> | undefined = msg.params?.arguments;
      const decision = evaluate(toolName, toolArgs, config);
      const serverName = serverCommand.join(' ');
      const receipt = createReceipt(agentId, toolName, decision, msg.params, serverName, config.mode);
      emitReceipt(receipt);
      if (approvalEnabled) pushReceipt(receipt);

      // In observe mode, always forward (log only, don't block)
      if (config.mode === 'observe') {
        if (decision.decision !== 'allowed') {
          process.stderr.write(`[mcp-guard] OBSERVE: would ${decision.decision === 'blocked' ? 'block' : 'hold'} "${toolName}" but forwarding (observe mode)\n`);
        }
        child.stdin!.write(line + '\n');
      } else if (decision.decision === 'allowed') {
        child.stdin!.write(line + '\n');
        // Verify lane: the action acted under a standing rule (e.g. spend under cap).
        // Surface it for post-hoc confirmation without holding or re-forwarding.
        if (approvalEnabled && decision.lane === 'verify') {
          const surfaced = surfaceActed(
            toolName,
            toolArgs,
            agentId,
            decision.rule_id ?? 'unknown',
            buildEnrichment(decision, toolName, toolArgs),
            receipt.receipt_id,
          );
          notifyQueueChange();
          process.stderr.write(`[mcp-guard] Surfaced acted "${toolName}" in Verify (${surfaced.id})\n`);
        }
      } else if (decision.decision === 'blocked') {
        const errResp: JsonRpcError = {
          jsonrpc: '2.0',
          id: msg.id ?? null,
          error: {
            code: -32001,
            message: `Blocked: ${decision.reason}`,
          },
        };
        process.stdout.write(JSON.stringify(errResp) + '\n');
      } else {
        // held_for_approval
        if (approvalEnabled) {
          // Hold the response — add to pending queue with classifier enrichment.
          const pending = addPending(
            toolName,
            toolArgs,
            agentId,
            decision.rule_id ?? 'unknown',
            line,
            msg.id ?? null,
            (responseLine: string) => {
              process.stdout.write(responseLine + '\n');
            },
            buildEnrichment(decision, toolName, toolArgs),
          );
          process.stderr.write(`[mcp-guard] Held "${toolName}" for approval (${pending.id}) — approve at UI\n`);
        } else {
          // No approval server — return error immediately (original behavior)
          const errResp: JsonRpcError = {
            jsonrpc: '2.0',
            id: msg.id ?? null,
            error: {
              code: -32002,
              message: `Held for approval: ${decision.reason}`,
            },
          };
          process.stdout.write(JSON.stringify(errResp) + '\n');
        }
      }
    } else {
      // Pass through all non-tools/call methods
      child.stdin!.write(line + '\n');
    }
  });

  stdinRL.on('close', () => {
    child.stdin!.end();
  });

  // Handle signals gracefully
  process.on('SIGINT', () => child.kill('SIGINT'));
  process.on('SIGTERM', () => child.kill('SIGTERM'));
}
