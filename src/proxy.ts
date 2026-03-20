import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { Config } from './config.js';
import { evaluate } from './engine.js';
import { createReceipt, emitReceipt } from './receipt.js';

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

export function startProxy(config: Config, agentId: string, serverCommand: string[]): void {
  if (serverCommand.length === 0) {
    process.stderr.write('[mcp-guard] Error: no server command provided after --\n');
    process.exit(1);
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

  // Forward child stdout → our stdout
  const childOut = createInterface({ input: child.stdout! });
  childOut.on('line', (line) => {
    process.stdout.write(line + '\n');
  });

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
