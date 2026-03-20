import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { Config } from './config.js';
import { evaluate } from './engine.js';
import { createReceipt, emitReceipt } from './receipt.js';
import { addPending, getAction } from './pending.js';
import { startApprovalServer, setOnApprove, pushReceipt } from './approval-server.js';

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

  // Set up approval callback — when UI approves, forward original request to child
  if (approvalEnabled) {
    setOnApprove((actionId: string) => {
      const action = getAction(actionId);
      if (!action) return;
      // Register a listener for the child's response
      if (action.jsonrpcId != null) {
        pendingChildResponses.set(action.jsonrpcId, (responseLine: string) => {
          action.resolve(responseLine);
        });
      }
      // Forward the original request to the child server
      child.stdin!.write(action.originalLine + '\n');
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
          // Hold the response — add to pending queue
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
