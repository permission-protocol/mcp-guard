import { randomUUID } from 'node:crypto';
import type { Lane } from './engine.js';
import type { Reversibility } from './config.js';
import type { JsonRpcId } from './frame.js';

/**
 * The approval queue and its decision state machine.
 *
 * Every status change goes through `transition()`, driven by one table: an item starts
 * `pending` and moves exactly once to a final state. Final states never change, so a
 * denied item can never be approved, and an approval racing a countdown releases once.
 *
 * Item kinds:
 *   - held:     a request the proxy is holding; approve/auto-release forwards it.
 *   - acted:    a Verify-lane action that already ran under a standing rule; it can only
 *               be acknowledged (it cannot be denied or undone after the fact).
 *   - external: a decision with no MCP request behind it (GitHub webhook); approve
 *               issues a scoped receipt.
 */

export type PendingStatus = 'pending' | 'approved' | 'denied' | 'auto_released' | 'expired' | 'acknowledged';
export type PendingKind = 'held' | 'acted' | 'external';
export type PendingEvent = 'approve' | 'deny' | 'auto_release' | 'expire' | 'acknowledge' | 'hold';

const ALLOWED_EVENTS: Record<PendingKind, ReadonlySet<PendingEvent>> = {
  held: new Set(['approve', 'deny', 'auto_release', 'expire', 'hold']),
  acted: new Set(['acknowledge', 'expire']),
  external: new Set(['approve', 'deny']),
};

const FINAL_STATUS: Record<Exclude<PendingEvent, 'hold'>, PendingStatus> = {
  approve: 'approved',
  deny: 'denied',
  auto_release: 'auto_released',
  expire: 'expired',
  acknowledge: 'acknowledged',
};

/** Resolved items kept for display before the oldest are dropped. */
export const MAX_RESOLVED = 200;

export interface PendingEnrichment {
  lane: Lane;
  reversibility: Reversibility;
  countdown_seconds?: number;
  confidence?: number;
  summary: string;
  args_preview: string;
}

export interface PendingAction {
  id: string;
  kind: PendingKind;
  method: string;
  tool_name: string;
  tool_args: Record<string, unknown>;
  agent_id: string;
  rule_id: string | null;
  status: PendingStatus;
  created_at: string;
  resolved_at?: string;
  /** ISO time after which a pending item expires; absent = no expiry. */
  expires_at?: string;
  /** The JSON-RPC line to forward on release (held items only). */
  forwardLine: string;
  jsonrpcId: JsonRpcId;
  /** Deliver a response line to the waiting client (held items only). */
  resolve: (responseLine: string) => void;

  lane: Lane;
  reversibility: Reversibility;
  countdown_seconds?: number;
  confidence?: number;
  summary: string;
  args_preview: string;
  receipt_id?: string;
  scope?: string;
  scope_ref?: string;
  scope_sha?: string;

  /** epoch ms when the countdown auto-release fires; undefined = no countdown */
  releaseAt?: number;
  countdownTimer?: NodeJS.Timeout;
  expiryTimer?: NodeJS.Timeout;
}

export type TransitionResult =
  | { ok: true; action: PendingAction }
  | { ok: false; error: 'not_found' | 'final' | 'not_allowed'; action?: PendingAction };

const queue: Map<string, PendingAction> = new Map();

/** Called after a countdown has moved an item to `auto_released`; the proxy releases it. */
let autoReleaseHandler: ((action: PendingAction) => void) | null = null;
export function setAutoReleaseHandler(handler: ((action: PendingAction) => void) | null): void {
  autoReleaseHandler = handler;
}

/** Called after a TTL has moved an item to `expired`; the proxy answers the client. */
let expireHandler: ((action: PendingAction) => void) | null = null;
export function setExpireHandler(handler: ((action: PendingAction) => void) | null): void {
  expireHandler = handler;
}

function clearTimers(action: PendingAction, which: 'countdown' | 'all'): void {
  if (action.countdownTimer) clearTimeout(action.countdownTimer);
  action.countdownTimer = undefined;
  if (which === 'all') {
    if (action.expiryTimer) clearTimeout(action.expiryTimer);
    action.expiryTimer = undefined;
  }
}

function prune(): void {
  let resolved = 0;
  for (const a of queue.values()) if (a.status !== 'pending') resolved++;
  if (resolved <= MAX_RESOLVED) return;
  for (const [id, a] of queue) {
    if (resolved <= MAX_RESOLVED) break;
    if (a.status !== 'pending') {
      queue.delete(id);
      resolved--;
    }
  }
}

/** The only place an item's status changes. */
export function transition(id: string, event: PendingEvent): TransitionResult {
  const action = queue.get(id);
  if (!action) return { ok: false, error: 'not_found' };
  if (action.status !== 'pending') return { ok: false, error: 'final', action };
  if (!ALLOWED_EVENTS[action.kind].has(event)) return { ok: false, error: 'not_allowed', action };
  if ((event === 'auto_release' || event === 'hold') && action.releaseAt === undefined) {
    return { ok: false, error: 'not_allowed', action };
  }

  if (event === 'hold') {
    clearTimers(action, 'countdown');
    action.releaseAt = undefined;
    return { ok: true, action };
  }

  clearTimers(action, 'all');
  action.releaseAt = undefined;
  action.status = FINAL_STATUS[event];
  action.resolved_at = new Date().toISOString();
  prune();
  return { ok: true, action };
}

function startExpiry(action: PendingAction, ttlSeconds: number | undefined): void {
  if (!ttlSeconds || ttlSeconds <= 0) return;
  action.expires_at = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  action.expiryTimer = setTimeout(() => {
    const r = transition(action.id, 'expire');
    if (r.ok && expireHandler) expireHandler(r.action);
  }, ttlSeconds * 1000);
  action.expiryTimer.unref?.();
}

interface BaseInput {
  toolName: string;
  toolArgs?: Record<string, unknown>;
  agentId: string;
  ruleId: string | null;
  enrichment: PendingEnrichment;
  method?: string;
}

function baseAction(kind: PendingKind, input: BaseInput): PendingAction {
  return {
    id: randomUUID(),
    kind,
    method: input.method ?? 'tools/call',
    tool_name: input.toolName,
    tool_args: input.toolArgs ?? {},
    agent_id: input.agentId,
    rule_id: input.ruleId,
    status: 'pending',
    created_at: new Date().toISOString(),
    forwardLine: '',
    jsonrpcId: null,
    resolve: () => {},
    lane: input.enrichment.lane,
    reversibility: input.enrichment.reversibility,
    ...(input.enrichment.confidence !== undefined ? { confidence: input.enrichment.confidence } : {}),
    summary: input.enrichment.summary,
    args_preview: input.enrichment.args_preview,
  };
}

export interface HeldInput extends BaseInput {
  forwardLine: string;
  jsonrpcId: JsonRpcId;
  resolve: (responseLine: string) => void;
  ttlSeconds?: number;
}

/** Hold a request for a decision. Reversible holds with a countdown auto-release. */
export function addPending(input: HeldInput): PendingAction {
  const action = baseAction('held', input);
  action.forwardLine = input.forwardLine;
  action.jsonrpcId = input.jsonrpcId;
  action.resolve = input.resolve;
  const countdown = input.enrichment.countdown_seconds;
  if (countdown !== undefined) action.countdown_seconds = countdown;

  // Irreversible (or no countdown) NEVER auto-releases; it waits for a decision or expiry.
  if (action.reversibility === 'reversible' && countdown !== undefined && countdown > 0) {
    action.releaseAt = Date.now() + countdown * 1000;
    action.countdownTimer = setTimeout(() => {
      const r = transition(action.id, 'auto_release');
      if (r.ok && autoReleaseHandler) autoReleaseHandler(r.action);
    }, countdown * 1000);
    action.countdownTimer.unref?.();
  }
  startExpiry(action, input.ttlSeconds);

  queue.set(action.id, action);
  return action;
}

export interface ActedInput extends BaseInput {
  receiptId?: string;
  ttlSeconds?: number;
}

/** Surface an action that already ran under a standing rule, for acknowledgement. */
export function surfaceActed(input: ActedInput): PendingAction {
  const action = baseAction('acted', input);
  if (input.receiptId !== undefined) action.receipt_id = input.receiptId;
  startExpiry(action, input.ttlSeconds);
  queue.set(action.id, action);
  return action;
}

export interface ExternalInput extends BaseInput {
  scope?: string;
  scope_ref?: string;
  scope_sha?: string;
}

/** Enqueue a decision from an external source (GitHub webhook). Never auto-releases or expires. */
export function addExternalDecision(input: ExternalInput): PendingAction {
  const action = baseAction('external', input);
  if (input.scope) action.scope = input.scope;
  if (input.scope_ref) action.scope_ref = input.scope_ref;
  if (input.scope_sha) action.scope_sha = input.scope_sha;
  queue.set(action.id, action);
  return action;
}

export function getPending(): PendingAction[] {
  return Array.from(queue.values()).filter((a) => a.status === 'pending');
}

export function getAction(id: string): PendingAction | undefined {
  return queue.get(id);
}

export function queueSize(): number {
  return queue.size;
}

/** Seconds remaining until auto-release, server-computed. undefined if no countdown. */
export function countdownRemaining(action: PendingAction): number | undefined {
  if (action.releaseAt === undefined || action.status !== 'pending') return undefined;
  return Math.max(0, Math.ceil((action.releaseAt - Date.now()) / 1000));
}

/** Test/teardown helper: clear the queue and any live timers. */
export function _resetQueue(): void {
  for (const action of queue.values()) clearTimers(action, 'all');
  queue.clear();
}
