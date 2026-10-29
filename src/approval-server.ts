import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { userInfo } from 'node:os';
import {
  getPending,
  getAction,
  transition,
  addExternalDecision,
  countdownRemaining,
  type PendingAction,
  type TransitionResult,
} from './pending.js';
import type { Lane } from './engine.js';
import type { Reversibility } from './config.js';
import { getApprovalHTML } from './approval-ui.js';
import { SigningError } from './keystore.js';
import type { Decider, Issuer, IssuedReceipt } from './issuer.js';
import { emitReceipt, recentReceipts } from './receipt-log.js';
import { signHeld } from './release.js';
import { verifyGithubSignature, parsePrEvent, shouldGate, scopeForPr } from './webhook.js';
import { errorLine, DENIED } from './frame.js';

/**
 * The local approval channel.
 *
 * - Listens on 127.0.0.1 only and rejects any Host header but its own (DNS rebinding).
 * - Sends no CORS headers: other origins cannot read or drive it.
 * - Every /api route except the GitHub webhook needs `Authorization: Bearer <token>`.
 *   The token is generated per process (or supplied via PP_APPROVAL_TOKEN) and reaches
 *   the browser only in the URL fragment printed at startup; GET / holds no secret.
 * - Every decision goes through the pending-queue state machine, so final states hold.
 */

export const MIN_TOKEN_LENGTH = 32;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_DELIVERIES = 1000;

export interface ApprovalHooks {
  /**
   * Forward a held request after the operator approved it. The receipt is already signed
   * and the item already final; the hook verifies the receipt and forwards, or throws.
   */
  release?: (action: PendingAction, issued: IssuedReceipt) => void;
}

export interface ApprovalServerOptions {
  port: number;
  /** Signs every console decision. */
  issuer: Issuer;
  /** Bearer token; defaults to PP_APPROVAL_TOKEN, else 32 random bytes. */
  token?: string;
  /** Signed as the decider (`local:<operator>`); defaults to the OS username. */
  operator?: string;
  hooks?: ApprovalHooks;
}

export interface ApprovalServerHandle {
  token: string;
  operator: string | null;
  /** Resolves with the bound port once listening. */
  ready: Promise<number>;
  close: () => Promise<void>;
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
  /** Every argument the server will receive, so the approver sees all of it. */
  args_full: string;
  /** What an approval authorizes, when the receipt is scoped (merge, migration, deploy). */
  scope?: { scope: string; ref: string | null; sha: string | null };
  agent_id: string;
  rule_id: string | null;
  status: PendingAction['status'];
  acted: boolean;
  created_at: string;
  expires_at?: string;
  receipt_id?: string;
}

export function toQueueItem(p: PendingAction): QueueItem {
  const remaining = countdownRemaining(p);
  return {
    id: p.id,
    tool_name: p.tool_name,
    lane: p.lane,
    reversibility: p.reversibility,
    // Countdown fields appear only while a countdown is live (a held item has none).
    ...(remaining !== undefined ? { countdown_seconds: p.countdown_seconds, countdown_remaining: remaining } : {}),
    ...(p.confidence !== undefined ? { confidence: p.confidence } : {}),
    summary: p.summary,
    args_preview: p.args_preview,
    args_full: JSON.stringify(p.tool_args, null, 2),
    ...(p.scope ? { scope: { scope: p.scope, ref: p.scope_ref ?? null, sha: p.scope_sha ?? null } } : {}),
    agent_id: p.agent_id,
    rule_id: p.rule_id,
    status: p.status,
    acted: p.kind === 'acted',
    created_at: p.created_at,
    ...(p.expires_at !== undefined ? { expires_at: p.expires_at } : {}),
    ...(p.receipt_id !== undefined ? { receipt_id: p.receipt_id } : {}),
  };
}

export function pendingQueue(): QueueItem[] {
  return getPending().map(toQueueItem);
}

// --- SSE stream plumbing ------------------------------------------------------

const sseClients: Set<ServerResponse> = new Set();

function broadcastQueue(): void {
  if (sseClients.size === 0) return;
  const payload = `event: queue\ndata: ${JSON.stringify(pendingQueue())}\n\n`;
  for (const client of sseClients) {
    try { client.write(payload); } catch { /* cleanup happens on 'close' */ }
  }
}

/** Call after any queue mutation so SSE subscribers see it immediately. */
export function notifyQueueChange(): void {
  broadcastQueue();
}

// --- HTTP helpers -------------------------------------------------------------

const BASE_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
};

function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { ...BASE_HEADERS, 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

function digest(s: string): Buffer {
  return createHash('sha256').update(s).digest();
}

function transitionError(res: ServerResponse, r: Extract<TransitionResult, { ok: false }>): void {
  if (r.error === 'not_found') { json(res, 404, { error: 'not_found' }); return; }
  if (r.error === 'final') { json(res, 409, { error: 'already_resolved', status: r.action?.status }); return; }
  json(res, 409, { error: 'not_allowed', status: r.action?.status });
}

function resolveToken(explicit: string | undefined): { token: string; generated: boolean } {
  const supplied = explicit ?? process.env.PP_APPROVAL_TOKEN;
  if (supplied !== undefined) {
    if (supplied.length < MIN_TOKEN_LENGTH) {
      throw new Error(`Approval token must be at least ${MIN_TOKEN_LENGTH} characters`);
    }
    return { token: supplied, generated: false };
  }
  return { token: randomBytes(32).toString('base64url'), generated: true };
}

/** The OS user, or null when there is none: an unattributed operator cannot approve in production. */
function defaultOperator(): string | null {
  try { return userInfo().username || null; } catch { return null; }
}

export function startApprovalServer(opts: ApprovalServerOptions): ApprovalServerHandle {
  const { token, generated } = resolveToken(opts.token);
  const tokenDigest = digest(token);
  const operator = opts.operator || defaultOperator();
  const decider: Decider = { kind: 'operator', operator };
  const who = operator ?? 'an unattributed operator';
  const issuer = opts.issuer;
  const hooks = opts.hooks ?? {};
  const seenDeliveries = new Set<string>();
  let boundPort = opts.port;

  function hostAllowed(req: IncomingMessage): boolean {
    const host = req.headers.host;
    return host === `127.0.0.1:${boundPort}` || host === `localhost:${boundPort}`;
  }

  function authorized(req: IncomingMessage): boolean {
    const h = req.headers.authorization;
    if (typeof h !== 'string' || !h.startsWith('Bearer ')) return false;
    return timingSafeEqual(digest(h.slice(7)), tokenDigest);
  }

  async function handleApi(method: string, path: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (method === 'GET' && path === '/api/pending') { json(res, 200, pendingQueue()); return; }

    if (method === 'GET' && path === '/api/receipts') { json(res, 200, recentReceipts()); return; }

    if (method === 'GET' && path === '/api/stream') {
      res.writeHead(200, { ...BASE_HEADERS, 'Content-Type': 'text/event-stream', Connection: 'keep-alive' });
      res.write(`event: queue\ndata: ${JSON.stringify(pendingQueue())}\n\n`);
      sseClients.add(res);
      req.on('close', () => sseClients.delete(res));
      return;
    }

    const m = method === 'POST' ? path.match(/^\/api\/(approve|deny|hold)\/([a-f0-9-]{36})$/) : null;
    if (!m) { json(res, 404, { error: 'not_found' }); return; }
    const [, verb, id] = m;
    const existing = getAction(id);
    if (!existing) { json(res, 404, { error: 'not_found' }); return; }

    if (verb === 'hold') {
      const r = transition(id, 'hold');
      if (!r.ok) { transitionError(res, r); return; }
      process.stderr.write(`[mcp-guard] Held (countdown cancelled): ${r.action.tool_name} (${id})\n`);
      notifyQueueChange();
      json(res, 200, { id, status: 'pending' });
      return;
    }

    if (verb === 'deny') {
      // A denial always takes effect; its receipt is signed when the key allows it.
      let issued: IssuedReceipt | null = null;
      let signError: string | null = null;
      if (existing.status === 'pending' && existing.kind !== 'acted') {
        try { issued = signHeld(issuer, existing, decider, 'DENIED', 'OPERATOR_DENIED'); } catch (err) {
          if (!(err instanceof SigningError)) throw err;
          signError = err.code;
        }
      }
      const r = transition(id, 'deny');
      if (!r.ok) { transitionError(res, r); return; }
      if (issued) { r.action.receipt_id = issued.record.id; emitReceipt(issued); }
      if (signError) process.stderr.write(`[mcp-guard] Denial of ${r.action.tool_name} (${id}) took effect but was not signed: ${signError}\n`);
      process.stderr.write(`[mcp-guard] Denied by ${who}: ${r.action.tool_name} (${id})\n`);
      if (r.action.kind === 'held') r.action.resolve(errorLine(r.action.jsonrpcId, DENIED, `Denied by ${who}`));
      notifyQueueChange();
      json(res, 200, { id, status: 'denied', receipt_id: issued?.record.id ?? null, ...(signError ? { receipt_error: signError } : {}) });
      return;
    }

    // approve
    if (existing.kind === 'acted') {
      const r = transition(id, 'acknowledge');
      if (!r.ok) { transitionError(res, r); return; }
      process.stderr.write(`[mcp-guard] Acknowledged (verify): ${r.action.tool_name} (${id})\n`);
      notifyQueueChange();
      json(res, 200, { id, status: 'acknowledged', receipt_id: r.action.receipt_id ?? null });
      return;
    }

    // Sign BEFORE the item becomes final: if signing is refused, the call stays held.
    if (existing.status !== 'pending') { transitionError(res, { ok: false, error: 'final', action: existing }); return; }
    if (existing.kind === 'held' && !hooks.release) throw new Error('No release hook registered for held requests');
    let issued: IssuedReceipt;
    try {
      issued = signHeld(issuer, existing, decider, 'APPROVED', 'OPERATOR_APPROVED');
    } catch (err) {
      if (!(err instanceof SigningError)) throw err;
      process.stderr.write(`[mcp-guard] Approval of ${existing.tool_name} (${id}) refused, still held: ${err.message}\n`);
      json(res, 409, { error: err.code, message: err.message, status: 'pending' });
      return;
    }
    const r = transition(id, 'approve');
    if (!r.ok) { transitionError(res, r); return; }
    r.action.receipt_id = issued.record.id;
    emitReceipt(issued);
    if (r.action.kind === 'held') {
      try {
        hooks.release!(r.action, issued);
      } catch (err: any) {
        process.stderr.write(`[mcp-guard] ${err.message}\n`);
        notifyQueueChange();
        json(res, 502, { id, status: 'approved', error: 'release_failed', receipt_id: issued.record.id });
        return;
      }
    }
    process.stderr.write(`[mcp-guard] Approved by ${who}: ${r.action.tool_name} (${id}) → receipt ${issued.record.id}\n`);
    notifyQueueChange();
    json(res, 200, { id, status: 'approved', receipt_id: issued.record.id });
  }

  async function handleWebhook(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const raw = await readBody(req);
    const sig = req.headers['x-hub-signature-256'] as string | undefined;
    if (!verifyGithubSignature(process.env.PP_WEBHOOK_SECRET, raw, sig)) {
      process.stderr.write('[mcp-guard] Webhook REJECTED — bad/missing signature\n');
      json(res, 401, { error: 'invalid signature' });
      return;
    }
    const delivery = req.headers['x-github-delivery'];
    if (typeof delivery === 'string' && delivery) {
      if (seenDeliveries.has(delivery)) { json(res, 200, { ignored: true, reason: 'duplicate delivery' }); return; }
      seenDeliveries.add(delivery);
      if (seenDeliveries.size > MAX_DELIVERIES) {
        const oldest = seenDeliveries.values().next().value;
        if (oldest !== undefined) seenDeliveries.delete(oldest);
      }
    }
    let payload: any;
    try { payload = JSON.parse(raw); } catch { json(res, 400, { error: 'invalid JSON' }); return; }
    const ev = parsePrEvent(payload);
    if (!ev) { json(res, 200, { ignored: true, reason: 'not a pull_request event' }); return; }
    if (!shouldGate(ev)) { json(res, 200, { ignored: true, reason: 'no needs-authority label or irrelevant action' }); return; }
    const sc = scopeForPr(ev);
    const item = addExternalDecision({
      method: 'github/merge',
      toolName: 'merge_pr',
      agentId: 'github-webhook',
      ruleId: 'pr-needs-authority',
      enrichment: {
        lane: 'decide',
        reversibility: 'reversible',
        summary: `Merge ${ev.repo} #${ev.pr_number} · ${ev.title}`,
        args_preview: JSON.stringify({ repo: ev.repo, pr_number: ev.pr_number, title: ev.title, head_sha: ev.head_sha, html_url: ev.html_url }),
      },
      toolArgs: { repo: ev.repo, pr_number: ev.pr_number, scope_sha: ev.head_sha },
      ...sc,
    });
    process.stderr.write(`[mcp-guard] Webhook queued PR ${ev.repo}#${ev.pr_number} for authority (${item.id})\n`);
    notifyQueueChange();
    json(res, 202, { queued: true, id: item.id, scope_ref: sc.scope_ref });
  }

  const server = createServer(async (req, res) => {
    const method = req.method ?? 'GET';
    const path = (req.url ?? '/').split('?')[0];
    try {
      if (!hostAllowed(req)) { json(res, 421, { error: 'misdirected request' }); return; }

      if (method === 'GET' && path === '/') {
        res.writeHead(200, {
          ...BASE_HEADERS,
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
        });
        res.end(getApprovalHTML());
        return;
      }

      if (method === 'POST' && path === '/api/github/webhook') { await handleWebhook(req, res); return; }

      if (path.startsWith('/api/')) {
        if (!authorized(req)) { json(res, 401, { error: 'unauthorized' }); return; }
        await handleApi(method, path, req, res);
        return;
      }

      json(res, 404, { error: 'not_found' });
    } catch (err: any) {
      process.stderr.write(`[mcp-guard] Approval server error: ${err?.message ?? err}\n`);
      if (!res.headersSent) json(res, 500, { error: 'internal_error' });
      else res.end();
    }
  });

  // ~1s tick so countdown_remaining counts down live for SSE subscribers.
  const tick = setInterval(() => broadcastQueue(), 1000);
  tick.unref?.();

  const ready = new Promise<number>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port, '127.0.0.1', () => {
      boundPort = (server.address() as AddressInfo).port;
      const url = `http://127.0.0.1:${boundPort}/`;
      process.stderr.write(
        generated
          ? `[mcp-guard] Approval UI: ${url}#t=${token}\n`
          : `[mcp-guard] Approval UI: ${url} (token from PP_APPROVAL_TOKEN)\n`,
      );
      resolve(boundPort);
    });
  });

  return {
    token,
    operator,
    ready,
    close: () =>
      new Promise<void>((resolve) => {
        clearInterval(tick);
        for (const client of sseClients) { try { client.end(); } catch { /* ignore */ } }
        sseClients.clear();
        server.close(() => resolve());
        server.closeAllConnections?.();
      }),
  };
}
