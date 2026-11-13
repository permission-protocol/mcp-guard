import { createHash } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadInstallToken } from '../cloud/token.js';
import { scanLog, totalsFor, type LogState } from './aggregate.js';
import { PAST_DAYS, addDays, buildBody, guardVersion, utcDay, validateBody, type ClientLabel, type HeartbeatBody, type HeartbeatMode } from './contract.js';
import { MAX_LOGS, acquireLock, defaultStatePath, isDue, loadState, saveState, type HeartbeatState } from './state.js';

/**
 * Compute and send heartbeats. Runs in its own process (a detached child of the hook, a
 * child of the proxy, or `mcp-guard heartbeat --send`), never on a decision path. One
 * request at a time, a timeout on each, no retries: a day that was not accepted is sent
 * again on a later run with its totals at that time.
 */

/** No more than one send attempt per install per 10 minutes (the contract allows 12 per minute). */
export const MIN_INTERVAL_MS = 10 * 60 * 1000;
export const REQUEST_TIMEOUT_MS = 5_000;
/** Days sent per run at most: today, plus earlier days whose totals changed since they were accepted. */
export const MAX_DAYS_PER_RUN = 3;
/** After 401, 400 or 413 nothing is sent for this long. */
export const REFUSED_BACKOFF_MS = 6 * 60 * 60 * 1000;
const MAX_RETRY_AFTER_MS = 60 * 60 * 1000;
const PATH = '/api/mcp/heartbeat';

export type SendOutcome = { ok: true } | { ok: false; code: string; retryAfterMs?: number };

export async function postHeartbeat(apiUrl: string, token: string, json: string, options: { timeoutMs?: number; fetchImpl?: typeof fetch } = {}): Promise<SendOutcome> {
  const doFetch = options.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await doFetch(`${apiUrl.replace(/\/+$/, '')}${PATH}`, {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(options.timeoutMs ?? REQUEST_TIMEOUT_MS),
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: json,
    });
  } catch (err: any) {
    return { ok: false, code: err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'TIMEOUT' : 'UNREACHABLE' };
  }
  try { await response.arrayBuffer(); } catch { /* the body is not needed */ }
  if (response.ok) return { ok: true };
  if (response.status === 429) {
    const seconds = Number(response.headers.get('retry-after'));
    return { ok: false, code: 'HTTP_429', retryAfterMs: Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds * 1000, MAX_RETRY_AFTER_MS) : MIN_INTERVAL_MS };
  }
  return { ok: false, code: `HTTP_${response.status}` };
}

export interface RunOptions {
  apiUrl: string;
  mode: HeartbeatMode;
  client: ClientLabel;
  receiptsPath: string;
  statePath?: string;
  /** Skip the 10-minute throttle (`mcp-guard heartbeat --send`). A 429 or refusal back-off still applies. */
  force?: boolean;
  now?: () => number;
  token?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxBytes?: number;
}

export type RunResult =
  | { status: 'skipped'; reason: 'no_token' | 'locked' | 'throttled' }
  | { status: 'done'; sent: string[]; failed: { day: string; code: string } | null };

const hashOf = (json: string): string => createHash('sha256').update(json).digest('hex');

/** The receipt log's stable path: resolved, and through symlinks when it exists. */
export function canonicalLogPath(path: string): string {
  const abs = resolve(path);
  try { return realpathSync(abs); } catch { return abs; }
}

/** Fold this log's fresh totals into the state; drop logs not seen for the whole window. */
export async function refresh(state: HeartbeatState, receiptsPath: string, client: ClientLabel, now: number, maxBytes?: number): Promise<LogState> {
  const path = canonicalLogPath(receiptsPath);
  const previous = state.logs.find((l) => l.path === path);
  const log = await scanLog(previous, path, client, { now, maxBytes });
  const others = state.logs.filter((l) => l !== previous && l.path !== path && !(log.ino !== 0 && l.dev === log.dev && l.ino === log.ino));
  const horizon = now - (PAST_DAYS + 1) * 86_400_000;
  state.logs = [log, ...others.filter((l) => l.seenAt >= horizon)].slice(0, MAX_LOGS);
  return log;
}

function labelFor(logs: LogState[], fallback: ClientLabel): ClientLabel {
  const kinds = new Set(logs.filter((l) => Object.keys(l.days).length).map((l) => l.client));
  if (kinds.size === 0) return fallback;
  return kinds.size === 1 ? [...kinds][0] : 'mcp-guard';
}

/** The body for one day from the state. Built from the allowlist in contract.ts. */
export function bodyFor(state: HeartbeatState, day: string, mode: HeartbeatMode, client: ClientLabel): HeartbeatBody {
  const totals = totalsFor(state.logs, day);
  return buildBody({ guardVersion: guardVersion(), clientLabel: labelFor(state.logs, client), mode, day, counts: totals.counts, rules: totals.rules });
}

/** Today, then earlier days in the window whose body differs from what was last accepted. */
export function daysToSend(state: HeartbeatState, now: number, mode: HeartbeatMode, client: ClientLabel): { day: string; json: string }[] {
  const today = utcDay(now);
  const out: { day: string; json: string }[] = [];
  for (let i = 0; i <= PAST_DAYS && out.length < MAX_DAYS_PER_RUN; i++) {
    const day = addDays(today, -i);
    if (i > 0 && !state.logs.some((l) => l.days[day])) continue;
    const checked = validateBody(bodyFor(state, day, mode, client), now);
    if (!checked.ok) continue;
    if (state.sent[day] === hashOf(checked.json)) continue;
    out.push({ day, json: checked.json });
  }
  return out;
}

/**
 * One heartbeat run: lock, throttle, recount this log from its offset, send what changed,
 * record the outcome. Never throws for a network or server error.
 */
export async function runHeartbeat(options: RunOptions): Promise<RunResult> {
  const now = options.now ?? Date.now;
  let token: string;
  try {
    token = options.token ?? loadInstallToken();
  } catch {
    return { status: 'skipped', reason: 'no_token' };
  }
  const statePath = options.statePath ?? defaultStatePath();
  const release = acquireLock(statePath, now);
  if (!release) return { status: 'skipped', reason: 'locked' };
  try {
    const state = loadState(statePath);
    const t = now();
    if (t < state.nextAllowedAt || (!options.force && !isDue(state, t, MIN_INTERVAL_MS))) return { status: 'skipped', reason: 'throttled' };
    state.lastAttemptAt = t;
    saveState(statePath, state);

    await refresh(state, options.receiptsPath, options.client, t, options.maxBytes);
    const oldest = addDays(utcDay(t), -PAST_DAYS);
    for (const day of Object.keys(state.sent)) if (day < oldest) delete state.sent[day];
    saveState(statePath, state);

    const sent: string[] = [];
    let failed: { day: string; code: string } | null = null;
    for (const { day, json } of daysToSend(state, t, options.mode, options.client)) {
      const outcome = await postHeartbeat(options.apiUrl, token, json, { timeoutMs: options.timeoutMs, fetchImpl: options.fetchImpl });
      if (outcome.ok) {
        state.sent[day] = hashOf(json);
        sent.push(day);
        continue;
      }
      failed = { day, code: outcome.code };
      if (outcome.code === 'HTTP_429') state.nextAllowedAt = now() + (outcome.retryAfterMs ?? MIN_INTERVAL_MS);
      else if (outcome.code === 'HTTP_401' || outcome.code === 'HTTP_403' || outcome.code === 'HTTP_400' || outcome.code === 'HTTP_413') state.nextAllowedAt = now() + REFUSED_BACKOFF_MS;
      break;
    }
    saveState(statePath, state);
    return { status: 'done', sent, failed };
  } finally {
    release();
  }
}
