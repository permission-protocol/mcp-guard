import { createHash } from 'node:crypto';
import { open, stat } from 'node:fs/promises';
import { ADAPTERS } from '../hook/adapter.js';
import { PAST_DAYS, addDays, isSendableRuleId, emptyCounts, utcDay, type ClientLabel, type CountName, type Counts } from './contract.js';

/**
 * Daily counts from the local receipt log (receipt-log.ts), the guard's source of truth.
 * Mapping, per line (docs/heartbeat.md has the same table):
 *
 *   {record} receipt, reason OPERATOR_APPROVED or COUNTDOWN_AUTO_RELEASE  -> approved
 *   {record} receipt, reason OPERATOR_DENIED                              -> denied
 *   {record} receipt, reason APPROVAL_EXPIRED                             -> expired
 *   {record} any other receipt, status APPROVED                           -> allowed
 *   {record} any other receipt, status DENIED                             -> blocked (+ rule*)
 *   {hold}                                                                -> held (+ rule)
 *   {cloud} released / denied / expired                                   -> approved / denied / expired
 *   {cloud} any decision, unless it closes an open proxy {hold} line      -> held (+ rule)
 *   {cloud} blocked                                                       -> no outcome
 *   {observed}, unparseable lines, lines older than the window            -> nothing
 *
 *   `mcp-guard report` reads {observed} lines too, through `onObserved` (never into the
 *   totals), and keeps every rule id, through `keepRule`: it prints locally and sends nothing.
 *
 *   (+ rule*): the rule's id is kept only if it is shipped with the guard (a built-in
 *   preset rule); any other id is not stored, so it is neither in the state file nor sent.
 *
 * The proxy writes a {hold} line and then a {cloud} line for one cloud-held call when it
 * runs without the local approval UI; elsewhere a cloud-held call has only its {cloud}
 * line. So a {cloud} line closes the oldest open {hold} line with `id: null` from a
 * non-hook agent with the same agent, method, tool and rule, written at most
 * PAIR_WINDOW_MS earlier, and that pair counts as one held call.
 *
 * Counts are totals derived from the lines alone, so scanning a log again from the start
 * gives the same totals: a resent day replaces the earlier one.
 */

export interface DayTotals {
  counts: Counts;
  /** Times each rule blocked or held a call. Only rule ids shipped with the guard; others are counted in the totals only. */
  rules: Record<string, number>;
}

interface OpenHold { key: string; at: number }

export interface LogState {
  /** Absolute path of the receipt log, for display; identity is dev + ino. */
  path: string;
  client: ClientLabel;
  dev: number;
  ino: number;
  /** Bytes consumed, always at a line boundary. */
  offset: number;
  /** sha256 of up to TAIL_BYTES bytes ending at `offset`: detects a rewritten log. */
  tail: string;
  days: Record<string, DayTotals>;
  holds: OpenHold[];
  seenAt: number;
}

/** The longest cloud approval wait (config MAX_CLOUD_APPROVAL_TIMEOUT_SECONDS) plus slack. */
export const PAIR_WINDOW_MS = (3600 + 300) * 1000;
export const MAX_RULES_PER_DAY = 200;
const MAX_OPEN_HOLDS = 1000;
const TAIL_BYTES = 256;
const CHUNK_BYTES = 1024 * 1024;
/** A receipt line is a few KB; anything longer than this is skipped, not parsed. */
const MAX_LINE_BYTES = 4 * 1024 * 1024;
/** At most this much new log is read per run; the rest is read on later runs. */
export const DEFAULT_MAX_BYTES_PER_RUN = 32 * 1024 * 1024;

const HOOK_AGENTS = new Set(Object.values(ADAPTERS).map((a) => a.agentId));

export type LogEvent =
  | { kind: 'count'; count: CountName; at: number; ruleId: string | null }
  | { kind: 'hold'; at: number; ruleId: string | null; pairKey: string | null }
  | { kind: 'cloud'; at: number; ruleId: string | null; pairKey: string; outcome: CountName | null };

/** An `observe: true` rule's would-be effect. Never part of the totals or the heartbeat. */
export interface ObservedEvent { kind: 'observed'; at: number; ruleId: string | null; would: 'blocked' | 'held' }

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const time = (v: unknown): number | null => {
  if (typeof v !== 'string') return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
};
const pairKey = (agentId: unknown, method: unknown, tool: unknown, ruleId: unknown): string =>
  createHash('sha256').update(JSON.stringify([str(agentId), str(method), str(tool), str(ruleId)])).digest('hex').slice(0, 32);

/** Classify one receipt-log line, for the totals. Reads only status, reason codes, rule id, agent, method, tool and times. */
export function eventOf(line: string): LogEvent | null {
  const e = lineEventOf(line);
  return e && e.kind !== 'observed' ? e : null;
}

/** As `eventOf`, and an {observed} line as an ObservedEvent (rule id, would-be effect and time only). */
export function lineEventOf(line: string): LogEvent | ObservedEvent | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isObj(parsed)) return null;

  if (isObj(parsed.record)) {
    const r = parsed.record;
    const at = time(r.createdAt);
    if (at === null) return null;
    let codes: unknown = [];
    try { codes = typeof r.reasonCodes === 'string' ? JSON.parse(r.reasonCodes) : r.reasonCodes; } catch { codes = []; }
    const list = Array.isArray(codes) ? codes.filter((c): c is string => typeof c === 'string') : [];
    const matched = list.find((c) => c.startsWith('RULE_MATCHED:'));
    const ruleId = matched ? matched.slice('RULE_MATCHED:'.length) : null;
    if (list.includes('OPERATOR_APPROVED') || list.includes('COUNTDOWN_AUTO_RELEASE')) return { kind: 'count', count: 'approved', at, ruleId };
    if (list.includes('OPERATOR_DENIED')) return { kind: 'count', count: 'denied', at, ruleId };
    if (list.includes('APPROVAL_EXPIRED')) return { kind: 'count', count: 'expired', at, ruleId };
    if (r.status === 'APPROVED') return { kind: 'count', count: 'allowed', at, ruleId };
    if (r.status === 'DENIED') return { kind: 'count', count: 'blocked', at, ruleId };
    return null;
  }

  if (isObj(parsed.hold)) {
    const h = parsed.hold;
    const at = time(h.createdAt);
    if (at === null) return null;
    const pairable = h.id === null && !HOOK_AGENTS.has(String(h.agentId));
    return { kind: 'hold', at, ruleId: str(h.ruleId), pairKey: pairable ? pairKey(h.agentId, h.method, h.tool, h.ruleId) : null };
  }

  if (isObj(parsed.cloud)) {
    const c = parsed.cloud;
    const at = time(c.at);
    if (at === null) return null;
    const outcome: CountName | null = c.decision === 'released' ? 'approved' : c.decision === 'denied' ? 'denied' : c.decision === 'expired' ? 'expired' : null;
    return { kind: 'cloud', at, ruleId: str(c.ruleId), pairKey: pairKey(c.agentId, c.method, c.tool, c.ruleId), outcome };
  }

  // {observed}: an observe-only rule's would-be effect. The call's real decision has its own line.
  if (isObj(parsed.observed)) {
    const o = parsed.observed;
    const at = time(o.at);
    if (at === null) return null;
    return { kind: 'observed', at, ruleId: str(o.ruleId), would: o.would === 'blocked' ? 'blocked' : 'held' };
  }
  return null;
}

export function emptyLog(path: string, client: ClientLabel, dev = 0, ino = 0): LogState {
  return { path, client, dev, ino, offset: 0, tail: '', days: {}, holds: [], seenAt: 0 };
}

function dayOf(log: LogState, at: number): DayTotals {
  const day = utcDay(at);
  return (log.days[day] ??= { counts: emptyCounts(), rules: {} });
}

/** Which rule ids are kept per day: by default only those shipped with the guard (all the heartbeat may send). */
export type KeepRule = (ruleId: string) => boolean;

function bump(totals: DayTotals, count: CountName, ruleId: string | null, keepRule: KeepRule): void {
  totals.counts[count] += 1;
  if ((count === 'blocked' || count === 'held') && ruleId && keepRule(ruleId)) {
    if (ruleId in totals.rules || Object.keys(totals.rules).length < MAX_RULES_PER_DAY) totals.rules[ruleId] = (totals.rules[ruleId] ?? 0) + 1;
  }
}

/** Apply one event to a log's totals. */
export function apply(log: LogState, e: LogEvent, keepRule: KeepRule = isSendableRuleId): void {
  if (e.kind === 'count') {
    bump(dayOf(log, e.at), e.count, e.ruleId, keepRule);
    return;
  }
  log.holds = log.holds.filter((h) => e.at - h.at <= PAIR_WINDOW_MS);
  if (e.kind === 'hold') {
    bump(dayOf(log, e.at), 'held', e.ruleId, keepRule);
    if (e.pairKey) {
      log.holds.push({ key: e.pairKey, at: e.at });
      if (log.holds.length > MAX_OPEN_HOLDS) log.holds.shift();
    }
    return;
  }
  const i = log.holds.findIndex((h) => h.key === e.pairKey && h.at <= e.at);
  if (i >= 0) log.holds.splice(i, 1);
  else bump(dayOf(log, e.at), 'held', e.ruleId, keepRule);
  if (e.outcome) bump(dayOf(log, e.at), e.outcome, null, keepRule);
}

/** Drop days the contract no longer accepts. */
export function prune(log: LogState, nowMs: number): void {
  const oldest = addDays(utcDay(nowMs), -PAST_DAYS);
  for (const day of Object.keys(log.days)) if (day < oldest) delete log.days[day];
}

const sha = (b: Buffer): string => createHash('sha256').update(b).digest('hex');

export interface ScanOptions {
  now?: number;
  maxBytes?: number;
  /** Rule ids to keep per day (default: shipped ones only). The heartbeat never sets this. */
  keepRule?: KeepRule;
  /** Called for each {observed} line read. The heartbeat never sets this. */
  onObserved?: (e: ObservedEvent) => void;
}

/**
 * Bring a log's totals up to date by reading only what was appended since `offset`. A
 * log that was replaced (other inode), truncated (shorter than `offset`) or rewritten
 * (bytes before `offset` changed) is recounted from the start. A missing log has no totals.
 * Only complete lines are consumed, so a line being written is read next time.
 */
export async function scanLog(previous: LogState | undefined, path: string, client: ClientLabel, options: ScanOptions = {}): Promise<LogState> {
  const now = options.now ?? Date.now();
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES_PER_RUN;
  let st;
  try {
    st = await stat(path);
  } catch {
    return { ...emptyLog(path, previous?.client ?? client), seenAt: now };
  }
  const fh = await open(path, 'r');
  try {
    let log: LogState = previous ? structuredClone(previous) : emptyLog(path, client, st.dev, st.ino);
    log.path = path;
    log.client = client;
    let fresh = !previous || previous.dev !== st.dev || previous.ino !== st.ino || st.size < previous.offset;
    if (!fresh && log.offset > 0) {
      const from = Math.max(0, log.offset - TAIL_BYTES);
      const buf = Buffer.alloc(log.offset - from);
      await fh.read(buf, 0, buf.length, from);
      if (sha(buf) !== log.tail) fresh = true;
    }
    if (fresh) log = emptyLog(path, client, st.dev, st.ino);

    const end = Math.min(st.size, log.offset + maxBytes);
    let pos = log.offset;
    let carry = Buffer.alloc(0);
    while (pos < end) {
      const chunk = Buffer.alloc(Math.min(CHUNK_BYTES, end - pos));
      const { bytesRead } = await fh.read(chunk, 0, chunk.length, pos);
      if (bytesRead === 0) break;
      pos += bytesRead;
      let data = carry.length ? Buffer.concat([carry, chunk.subarray(0, bytesRead)]) : chunk.subarray(0, bytesRead);
      let start = 0;
      for (let nl = data.indexOf(10, start); nl >= 0; nl = data.indexOf(10, start)) {
        const line = data.subarray(start, nl).toString('utf8').trim();
        if (line && nl - start <= MAX_LINE_BYTES) {
          const e = lineEventOf(line);
          if (e?.kind === 'observed') options.onObserved?.(e);
          else if (e) apply(log, e, options.keepRule);
        }
        start = nl + 1;
        log.offset = pos - (data.length - start);
      }
      carry = Buffer.from(data.subarray(start));
      if (carry.length > MAX_LINE_BYTES) {
        // An oversized line: skip what has been read of it; the rest is skipped up to its newline next time round.
        log.offset = pos;
        carry = Buffer.alloc(0);
        data = Buffer.alloc(0);
      }
    }

    const from = Math.max(0, log.offset - TAIL_BYTES);
    const tail = Buffer.alloc(log.offset - from);
    if (tail.length) await fh.read(tail, 0, tail.length, from);
    log.tail = log.offset > 0 ? sha(tail) : '';
    log.seenAt = now;
    prune(log, now);
    return log;
  } finally {
    await fh.close();
  }
}

/** One day's totals across every known log. */
export function totalsFor(logs: LogState[], day: string): DayTotals {
  const out: DayTotals = { counts: emptyCounts(), rules: {} };
  for (const log of logs) {
    const d = log.days[day];
    if (!d) continue;
    for (const k of Object.keys(out.counts) as CountName[]) out.counts[k] += d.counts[k] ?? 0;
    for (const [id, n] of Object.entries(d.rules)) out.rules[id] = (out.rules[id] ?? 0) + n;
  }
  return out;
}
