import { randomUUID } from 'node:crypto';
import type { Lane } from './engine.js';
import type { Reversibility } from './config.js';

/** Status lifecycle for a held action (Permission Deck Slice 1). */
export type PendingStatus =
  | 'pending'
  | 'approved'
  | 'denied'
  | 'auto_released'
  | 'undone';

/** Default undo window (seconds) after a reversible item is released. */
export const DEFAULT_UNDO_WINDOW_SECONDS = 10;

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
  timestamp: string;
  tool_name: string;
  tool_args: any;
  agent_id: string;
  rule_id: string;
  status: PendingStatus;
  /** The original JSON-RPC line to forward on approval */
  originalLine: string;
  /** The JSON-RPC request id for matching child responses */
  jsonrpcId: string | number | null;
  /** Resolver — call with the response line (or error JSON) to unblock the proxy */
  resolve: (responseLine: string) => void;

  // --- Permission Deck enrichment (threaded from the classifier) ---
  lane: Lane;
  reversibility: Reversibility;
  countdown_seconds?: number;
  confidence?: number;
  summary: string;
  args_preview: string;
  /** ISO creation time (alias of timestamp, surfaced as created_at in the API) */
  created_at: string;
  /** Set once a receipt is issued (approve / auto_release). */
  receipt_id?: string;
  /**
   * Verify lane: the action already executed (allowed under a standing rule) and is
   * surfaced for post-hoc review. Approve = acknowledge (no re-forward); Undo = roll back.
   */
  acted?: boolean;
  /**
   * External-source decision (e.g. a GitHub webhook): no MCP child to forward to.
   * Approve issues a scoped receipt directly; never re-forwards.
   */
  external?: boolean;
  scope?: string;
  scope_ref?: string;
  scope_sha?: string;

  // --- Internal countdown / undo bookkeeping (not serialized to the API) ---
  /** epoch ms when the countdown auto-release fires; undefined = no countdown */
  releaseAt?: number;
  /** epoch ms after which undo is no longer accepted; set once released */
  undoDeadline?: number;
  countdownTimer?: NodeJS.Timeout;
}

const queue: Map<string, PendingAction> = new Map();

/** Hook the proxy registers to auto-release an item when its countdown expires. */
let autoReleaseHandler: ((id: string) => void) | null = null;
export function setAutoReleaseHandler(handler: (id: string) => void): void {
  autoReleaseHandler = handler;
}

/** Hook the proxy registers to best-effort cancel a released stub on undo. */
let undoHandler: ((action: PendingAction) => void) | null = null;
export function setUndoHandler(handler: (action: PendingAction) => void): void {
  undoHandler = handler;
}

export function addPending(
  toolName: string,
  toolArgs: any,
  agentId: string,
  ruleId: string,
  originalLine: string,
  jsonrpcId: string | number | null,
  resolve: (responseLine: string) => void,
  enrichment: PendingEnrichment,
): PendingAction {
  const now = new Date().toISOString();
  const action: PendingAction = {
    id: randomUUID(),
    timestamp: now,
    created_at: now,
    tool_name: toolName,
    tool_args: toolArgs,
    agent_id: agentId,
    rule_id: ruleId,
    status: 'pending',
    originalLine,
    jsonrpcId,
    resolve,
    lane: enrichment.lane,
    reversibility: enrichment.reversibility,
    ...(enrichment.countdown_seconds !== undefined ? { countdown_seconds: enrichment.countdown_seconds } : {}),
    ...(enrichment.confidence !== undefined ? { confidence: enrichment.confidence } : {}),
    summary: enrichment.summary,
    args_preview: enrichment.args_preview,
  };

  // Reversible + countdown -> start the auto-release timer. Irreversible (no
  // countdown) NEVER auto-releases and stays pending until an explicit decision.
  if (
    action.reversibility === 'reversible' &&
    action.countdown_seconds !== undefined &&
    action.countdown_seconds > 0
  ) {
    action.releaseAt = Date.now() + action.countdown_seconds * 1000;
    action.countdownTimer = setTimeout(() => {
      // Fire only if still pending (a hold/deny may have arrived first).
      const current = queue.get(action.id);
      if (!current || current.status !== 'pending') return;
      if (autoReleaseHandler) autoReleaseHandler(action.id);
    }, action.countdown_seconds * 1000);
    // Don't keep the event loop alive solely for this timer.
    if (typeof action.countdownTimer.unref === 'function') action.countdownTimer.unref();
  }

  queue.set(action.id, action);
  return action;
}

/**
 * Surface an already-executed Verify-lane action (allowed under a standing rule) so the
 * operator can confirm or roll it back after the fact. It does NOT hold or re-forward:
 * status is 'pending' and `acted` is true, with no resolver/timer. Undo is available
 * immediately within the window for reversible items.
 */
export function surfaceActed(
  toolName: string,
  toolArgs: any,
  agentId: string,
  ruleId: string,
  enrichment: PendingEnrichment,
  receiptId?: string,
  undoWindowSeconds: number = DEFAULT_UNDO_WINDOW_SECONDS,
): PendingAction {
  const now = new Date().toISOString();
  const action: PendingAction = {
    id: randomUUID(),
    timestamp: now,
    created_at: now,
    tool_name: toolName,
    tool_args: toolArgs,
    agent_id: agentId,
    rule_id: ruleId,
    status: 'pending',
    originalLine: '',
    jsonrpcId: null,
    resolve: () => {}, // already executed; nothing to unblock
    lane: enrichment.lane,
    reversibility: enrichment.reversibility,
    ...(enrichment.confidence !== undefined ? { confidence: enrichment.confidence } : {}),
    summary: enrichment.summary,
    args_preview: enrichment.args_preview,
    acted: true,
    ...(receiptId !== undefined ? { receipt_id: receiptId } : {}),
  };
  if (enrichment.reversibility === 'reversible') {
    action.undoDeadline = Date.now() + undoWindowSeconds * 1000;
  }
  queue.set(action.id, action);
  return action;
}

export interface ExternalDecisionInput {
  toolName: string;             // e.g. 'merge_pr'
  agentId: string;             // e.g. 'github-webhook'
  ruleId: string;
  enrichment: PendingEnrichment; // lane (decide), reversibility, summary, args_preview
  toolArgs?: any;
  scope?: string;
  scope_ref?: string;
  scope_sha?: string;
}

/**
 * Enqueue a Decide item from an external source (a GitHub webhook). There is no MCP
 * child to forward to — approval issues a scoped receipt directly (handled by the
 * approval server). Status starts pending; never auto-releases.
 */
export function addExternalDecision(input: ExternalDecisionInput): PendingAction {
  const now = new Date().toISOString();
  const action: PendingAction = {
    id: randomUUID(),
    timestamp: now,
    created_at: now,
    tool_name: input.toolName,
    tool_args: input.toolArgs ?? {},
    agent_id: input.agentId,
    rule_id: input.ruleId,
    status: 'pending',
    originalLine: '',
    jsonrpcId: null,
    resolve: () => {}, // no caller blocked on this
    lane: input.enrichment.lane,
    reversibility: input.enrichment.reversibility,
    ...(input.enrichment.confidence !== undefined ? { confidence: input.enrichment.confidence } : {}),
    summary: input.enrichment.summary,
    args_preview: input.enrichment.args_preview,
    external: true,
    ...(input.scope ? { scope: input.scope } : {}),
    ...(input.scope_ref ? { scope_ref: input.scope_ref } : {}),
    ...(input.scope_sha ? { scope_sha: input.scope_sha } : {}),
  };
  queue.set(action.id, action);
  return action;
}

/** Acknowledge an already-acted Verify item without re-forwarding it. */
export function acknowledgeAction(id: string): PendingAction | undefined {
  const action = queue.get(id);
  if (!action || action.acted !== true || action.status !== 'pending') return undefined;
  action.status = 'approved';
  return action;
}

export function getPending(): PendingAction[] {
  return Array.from(queue.values()).filter(a => a.status === 'pending');
}

export function getAction(id: string): PendingAction | undefined {
  return queue.get(id);
}

/** Seconds remaining until auto-release, server-computed. undefined if no countdown. */
export function countdownRemaining(action: PendingAction): number | undefined {
  if (action.releaseAt === undefined) return undefined;
  if (action.status !== 'pending') return 0;
  return Math.max(0, Math.ceil((action.releaseAt - Date.now()) / 1000));
}

function clearCountdown(action: PendingAction): void {
  if (action.countdownTimer) {
    clearTimeout(action.countdownTimer);
    action.countdownTimer = undefined;
  }
}

/**
 * Resolve an item to approved / denied / auto_released. Clears any countdown timer.
 * For released statuses (approved/auto_released) on reversible items, opens the
 * undo window.
 */
export function resolveAction(
  id: string,
  status: 'approved' | 'denied' | 'auto_released',
  undoWindowSeconds: number = DEFAULT_UNDO_WINDOW_SECONDS,
): PendingAction | undefined {
  const action = queue.get(id);
  if (!action || action.status !== 'pending') return undefined;
  clearCountdown(action);
  action.status = status;
  if (
    (status === 'approved' || status === 'auto_released') &&
    action.reversibility === 'reversible'
  ) {
    action.undoDeadline = Date.now() + undoWindowSeconds * 1000;
  }
  return action;
}

/**
 * Cancel a reversible countdown but keep the item pending (a hard hold). Returns the
 * action if it was pending with an active countdown, else undefined.
 */
export function holdAction(id: string): PendingAction | undefined {
  const action = queue.get(id);
  if (!action || action.status !== 'pending') return undefined;
  clearCountdown(action);
  action.releaseAt = undefined;
  return action;
}

/**
 * Undo a released reversible item within its undo window. Best-effort cancels the
 * stub via the registered undo handler. Returns the action if undone, else undefined
 * (not found, not reversible, not released, or window expired).
 */
export function undoAction(id: string): PendingAction | undefined {
  const action = queue.get(id);
  if (!action) return undefined;
  // Undoable: a released hold (approved/auto_released) OR an already-acted Verify item
  // still in its window.
  const undoable =
    action.status === 'approved' ||
    action.status === 'auto_released' ||
    (action.status === 'pending' && action.acted === true);
  if (!undoable) return undefined;
  if (action.reversibility !== 'reversible') return undefined;
  if (action.undoDeadline === undefined || Date.now() >= action.undoDeadline) return undefined;
  action.status = 'undone';
  if (undoHandler) undoHandler(action);
  return action;
}

export function recentResolved(limit: number = 50): PendingAction[] {
  return Array.from(queue.values())
    .filter(a => a.status !== 'pending')
    .slice(-limit);
}

/** Test/teardown helper: clear the queue and any live timers. */
export function _resetQueue(): void {
  for (const action of queue.values()) clearCountdown(action);
  queue.clear();
}
