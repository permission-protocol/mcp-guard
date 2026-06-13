import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import {
  getPending,
  getAction,
  resolveAction,
  acknowledgeAction,
  holdAction,
  undoAction,
  countdownRemaining,
  type PendingAction,
} from './pending.js';
import type { Lane } from './engine.js';
import type { Reversibility } from './config.js';
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

/** The QueueItem shape from the API contract (backend ⇄ console). */
export interface QueueItem {
  id: string;
  tool_name: string;
  lane: Lane;
  reversibility: Reversibility;
  countdown_seconds?: number;
  countdown_remaining?: number;
  confidence?: number;
  summary: string;
  args_preview: string;
  agent_id: string;
  rule_id: string;
  status: PendingAction['status'];
  created_at: string;
  receipt_id?: string;
}

/** Project a PendingAction into the contract QueueItem, computing countdown_remaining. */
export function toQueueItem(p: PendingAction): QueueItem {
  const remaining = countdownRemaining(p);
  return {
    id: p.id,
    tool_name: p.tool_name,
    lane: p.lane,
    reversibility: p.reversibility,
    ...(p.countdown_seconds !== undefined ? { countdown_seconds: p.countdown_seconds } : {}),
    ...(remaining !== undefined ? { countdown_remaining: remaining } : {}),
    ...(p.confidence !== undefined ? { confidence: p.confidence } : {}),
    summary: p.summary,
    args_preview: p.args_preview,
    agent_id: p.agent_id,
    rule_id: p.rule_id,
    status: p.status,
    created_at: p.created_at,
    ...(p.receipt_id !== undefined ? { receipt_id: p.receipt_id } : {}),
  };
}

/** Current pending queue as contract QueueItems. */
export function pendingQueue(): QueueItem[] {
  return getPending().map(toQueueItem);
}

// --- SSE stream plumbing ------------------------------------------------------

const sseClients: Set<ServerResponse> = new Set();

function broadcastQueue(): void {
  if (sseClients.size === 0) return;
  const payload = `event: queue\ndata: ${JSON.stringify(pendingQueue())}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch {
      // drop on error; cleanup happens on 'close'
    }
  }
}

/** Call after any queue mutation so SSE subscribers see it immediately. */
export function notifyQueueChange(): void {
  broadcastQueue();
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

export interface ApprovalServerHandle {
  close: () => void;
}

export function startApprovalServer(port: number): ApprovalServerHandle {
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

      // GET /api/pending — QueueItem[]
      if (method === 'GET' && url === '/api/pending') {
        json(res, 200, pendingQueue());
        return;
      }

      // GET /api/stream — SSE; emits `event: queue` on change and on a ~1s tick.
      if (method === 'GET' && url === '/api/stream') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
          'Access-Control-Allow-Origin': '*',
        });
        // Prime the connection with the current queue.
        res.write(`event: queue\ndata: ${JSON.stringify(pendingQueue())}\n\n`);
        sseClients.add(res);
        req.on('close', () => {
          sseClients.delete(res);
        });
        return;
      }

      // POST /api/approve/:id
      const approveMatch = url.match(/^\/api\/approve\/([a-f0-9-]+)$/);
      if (method === 'POST' && approveMatch) {
        const id = approveMatch[1];
        // Verify lane: the action already executed — acknowledge, never re-forward.
        const existing = getAction(id);
        if (existing?.acted) {
          const ack = acknowledgeAction(id);
          if (!ack) {
            json(res, 404, { error: 'Not found or already resolved' });
            return;
          }
          process.stderr.write(`[mcp-guard] Acknowledged (verify): ${ack.tool_name} (${id})\n`);
          notifyQueueChange();
          json(res, 200, { id, status: 'approved', receipt_id: ack.receipt_id ?? null });
          return;
        }
        const action = resolveAction(id, 'approved');
        if (!action) {
          json(res, 404, { error: 'Not found or already resolved' });
          return;
        }
        process.stderr.write(`[mcp-guard] Approved: ${action.tool_name} (${id})\n`);
        // Proxy issues + signs the receipt and sets action.receipt_id synchronously.
        if (onApproveCallback) onApproveCallback(id);
        notifyQueueChange();
        json(res, 200, { id, status: 'approved', receipt_id: action.receipt_id ?? null });
        return;
      }

      // POST /api/hold/:id — cancel a reversible countdown, keep pending.
      const holdMatch = url.match(/^\/api\/hold\/([a-f0-9-]+)$/);
      if (method === 'POST' && holdMatch) {
        const id = holdMatch[1];
        const action = holdAction(id);
        if (!action) {
          json(res, 404, { error: 'Not found or already resolved' });
          return;
        }
        process.stderr.write(`[mcp-guard] Held (countdown cancelled): ${action.tool_name} (${id})\n`);
        notifyQueueChange();
        json(res, 200, { id, status: 'pending' });
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
        notifyQueueChange();
        json(res, 200, { id, status: 'denied' });
        return;
      }

      // POST /api/undo/:id — valid only within the undo window after release.
      const undoMatch = url.match(/^\/api\/undo\/([a-f0-9-]+)$/);
      if (method === 'POST' && undoMatch) {
        const id = undoMatch[1];
        const action = undoAction(id);
        if (!action) {
          json(res, 409, { error: 'Undo window expired or item not undoable' });
          return;
        }
        process.stderr.write(`[mcp-guard] Undone: ${action.tool_name} (${id})\n`);
        notifyQueueChange();
        json(res, 200, { id, status: 'undone' });
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

  // ~1s tick so countdown_remaining counts down live for SSE subscribers.
  const tick = setInterval(() => broadcastQueue(), 1000);
  if (typeof tick.unref === 'function') tick.unref();

  server.listen(port, () => {
    process.stderr.write(`[mcp-guard] Approval UI: http://localhost:${port}\n`);
  });

  return {
    close: () => {
      clearInterval(tick);
      for (const client of sseClients) {
        try {
          client.end();
        } catch {
          /* ignore */
        }
      }
      sseClients.clear();
      server.close();
    },
  };
}
