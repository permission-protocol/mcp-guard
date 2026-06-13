import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import {
  getPending,
  getAction,
  resolveAction,
  acknowledgeAction,
  addExternalDecision,
  holdAction,
  undoAction,
  countdownRemaining,
  type PendingAction,
} from './pending.js';
import type { Lane, Decision } from './engine.js';
import type { Reversibility } from './config.js';
import { getApprovalHTML } from './approval-ui.js';
import { createReceipt, signReceipt, emitReceipt, type Receipt } from './receipt.js';
import { verifyGithubSignature, parsePrEvent, shouldGate, scopeForPr } from './webhook.js';

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

/** Optional hook fired after an external (webhook) decision is approved + receipted.
 *  Real deployments use this to post the receipt id / a commit status back to GitHub. */
let onExternalApprove: ((action: PendingAction, receipt: Receipt) => void) | null = null;
export function setOnExternalApprove(cb: (action: PendingAction, receipt: Receipt) => void): void {
  onExternalApprove = cb;
}

/** Issue + sign a scoped receipt for an external (webhook-sourced) decision. No forward. */
function issueExternalReceipt(action: PendingAction, approvedBy: string): Receipt {
  const decision: Decision = {
    decision: 'allowed',
    rule_id: action.rule_id,
    reason: 'Approved by a human in the Permission Deck (GitHub webhook)',
    lane: action.lane,
    reversibility: action.reversibility,
  };
  const scopeBinding = { scope: action.scope, scope_ref: action.scope_ref, scope_sha: action.scope_sha };
  const receipt = createReceipt(action.agent_id, action.tool_name, decision, action.tool_args, 'github-webhook', 'enforce', scopeBinding);
  signReceipt(receipt, approvedBy);
  action.receipt_id = receipt.receipt_id;
  emitReceipt(receipt);
  pushReceipt(receipt);
  if (onExternalApprove) onExternalApprove(action, receipt);
  return receipt;
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
        // External (webhook) decision: issue a scoped receipt directly — no MCP forward.
        if (existing?.external) {
          const receipt = issueExternalReceipt(existing, 'permission-deck-operator');
          resolveAction(id, 'approved');
          process.stderr.write(`[mcp-guard] Approved (webhook): ${existing.tool_name} (${id}) → receipt ${receipt.receipt_id}\n`);
          notifyQueueChange();
          json(res, 200, { id, status: 'approved', receipt_id: receipt.receipt_id });
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

      // POST /api/github/webhook — Slice 2.5: enqueue a labeled PR as a Decide card.
      if (method === 'POST' && url === '/api/github/webhook') {
        const raw = await parseBody(req);
        const secret = process.env.PP_WEBHOOK_SECRET;
        const sig = (req.headers['x-hub-signature-256'] as string | undefined);
        if (!verifyGithubSignature(secret, raw, sig)) {
          process.stderr.write('[mcp-guard] Webhook REJECTED — bad/missing signature\n');
          json(res, 401, { error: 'invalid signature' });
          return;
        }
        let payload: any;
        try { payload = JSON.parse(raw); } catch { json(res, 400, { error: 'invalid JSON' }); return; }
        const ev = parsePrEvent(payload);
        if (!ev) { json(res, 200, { ignored: true, reason: 'not a pull_request event' }); return; }
        if (!shouldGate(ev)) { json(res, 200, { ignored: true, reason: `no ${'needs-authority'} label or irrelevant action` }); return; }
        const sc = scopeForPr(ev);
        const item = addExternalDecision({
          toolName: 'merge_pr',
          agentId: 'github-webhook',
          ruleId: 'pr-needs-authority',
          enrichment: {
            lane: 'decide',
            reversibility: 'reversible',
            summary: `Merge ${ev.repo} #${ev.pr_number} · ${ev.title}`,
            // args_preview is a string per the contract; the console JSON-parses structured blobs.
            args_preview: JSON.stringify({ repo: ev.repo, pr_number: ev.pr_number, title: ev.title, head_sha: ev.head_sha, html_url: ev.html_url }),
          },
          toolArgs: { repo: ev.repo, pr_number: ev.pr_number, scope_sha: ev.head_sha },
          ...sc,
        });
        process.stderr.write(`[mcp-guard] Webhook queued PR ${ev.repo}#${ev.pr_number} for authority (${item.id})\n`);
        notifyQueueChange();
        json(res, 202, { queued: true, id: item.id, scope_ref: sc.scope_ref });
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
