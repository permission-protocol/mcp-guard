import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { getPending, getAction, resolveAction, recentResolved } from './pending.js';
import { getApprovalHTML } from './approval-ui.js';
import type { Receipt } from './receipt.js';

/** Recent receipts store (ring buffer) */
const recentReceipts: Receipt[] = [];
const MAX_RECEIPTS = 50;

export function pushReceipt(receipt: Receipt): void {
  recentReceipts.push(receipt);
  if (recentReceipts.length > MAX_RECEIPTS) recentReceipts.shift();
}

/** Callback invoked when an action is approved — proxy registers this */
let onApproveCallback: ((id: string) => void) | null = null;

export function setOnApprove(cb: (id: string) => void): void {
  onApproveCallback = cb;
}

function parseBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

function json(res: ServerResponse, status: number, data: unknown): void {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(body);
}

function text(res: ServerResponse, status: number, msg: string): void {
  res.writeHead(status, { 'Content-Type': 'text/plain' });
  res.end(msg);
}

export function startApprovalServer(port: number): void {
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? '/';
    const method = req.method ?? 'GET';

    // CORS preflight
    if (method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      });
      res.end();
      return;
    }

    try {
      // GET / — Approval UI
      if (method === 'GET' && url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(getApprovalHTML());
        return;
      }

      // GET /api/pending
      if (method === 'GET' && url === '/api/pending') {
        const pending = getPending().map(p => ({
          id: p.id,
          timestamp: p.timestamp,
          tool_name: p.tool_name,
          tool_args: p.tool_args,
          agent_id: p.agent_id,
          rule_id: p.rule_id,
          status: p.status,
        }));
        json(res, 200, pending);
        return;
      }

      // POST /api/approve/:id
      const approveMatch = url.match(/^\/api\/approve\/([a-f0-9-]+)$/);
      if (method === 'POST' && approveMatch) {
        const id = approveMatch[1];
        const action = resolveAction(id, 'approved');
        if (!action) {
          json(res, 404, { error: 'Not found or already resolved' });
          return;
        }
        process.stderr.write(`[mcp-guard] Approved: ${action.tool_name} (${id})\n`);
        // Notify proxy to forward the original request
        if (onApproveCallback) onApproveCallback(id);
        json(res, 200, { id, status: 'approved' });
        return;
      }

      // POST /api/deny/:id
      const denyMatch = url.match(/^\/api\/deny\/([a-f0-9-]+)$/);
      if (method === 'POST' && denyMatch) {
        const id = denyMatch[1];
        const action = resolveAction(id, 'denied');
        if (!action) {
          json(res, 404, { error: 'Not found or already resolved' });
          return;
        }
        process.stderr.write(`[mcp-guard] Denied: ${action.tool_name} (${id})\n`);
        // Return JSON-RPC error to the waiting caller
        const errResp = JSON.stringify({
          jsonrpc: '2.0',
          id: action.jsonrpcId,
          error: { code: -32002, message: 'Denied by administrator' },
        });
        action.resolve(errResp);
        json(res, 200, { id, status: 'denied' });
        return;
      }

      // GET /api/receipts
      if (method === 'GET' && url === '/api/receipts') {
        json(res, 200, recentReceipts.slice(-50).reverse());
        return;
      }

      text(res, 404, 'Not found');
    } catch (err: any) {
      text(res, 500, err.message ?? 'Internal error');
    }
  });

  server.listen(port, () => {
    process.stderr.write(`[mcp-guard] Approval UI: http://localhost:${port}\n`);
  });
}
