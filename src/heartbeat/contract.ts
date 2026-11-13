import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseConfig } from '../config.js';
import { PRESET_NAMES, presetPolicyBody } from '../presets/coding-agent.js';

/**
 * The usage heartbeat body (Permission Protocol's MCP Guard heartbeat contract v1):
 * counts and rule ids for one UTC day, nothing else. The body is built from an
 * allowlist of fields and checked against the contract's patterns before it is sent.
 * Nothing a person wrote is sent: `topRules` carries only rule ids shipped with the
 * guard (the built-in presets); any other id is dropped, never rewritten. See
 * docs/heartbeat.md.
 */

export const COUNT_NAMES = ['allowed', 'blocked', 'held', 'approved', 'denied', 'expired'] as const;
export type CountName = (typeof COUNT_NAMES)[number];
export type Counts = Record<CountName, number>;

export const GUARD_VERSION_PATTERN = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,31}$/;
export const CLIENT_LABEL_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;
export const RULE_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const DAY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
export const MAX_COUNT = 1_000_000;
export const MAX_TOP_RULES = 20;
export const MAX_BODY_BYTES = 8 * 1024;
/** The contract accepts a day from 7 days before today (UTC) to 1 day after. */
export const PAST_DAYS = 7;

let shipped: ReadonlySet<string> | null = null;
/**
 * The rule ids shipped with the guard: the rules of the built-in presets, read from the
 * presets themselves through the strict loader. Only these ids are ever sent; a rule id a
 * person wrote never leaves the machine. If a preset ever failed to load, the set is
 * empty and no rule id is sent.
 */
export function shippedRuleIds(): ReadonlySet<string> {
  if (shipped === null) {
    const ids = new Set<string>();
    for (const name of PRESET_NAMES) {
      try {
        for (const rule of parseConfig(presetPolicyBody(name)).rules) if (RULE_ID_PATTERN.test(rule.id)) ids.add(rule.id);
      } catch {
        // Fail safe: send no rule ids.
      }
    }
    shipped = ids;
  }
  return shipped;
}

/** A rule id that may be sent: it matches the contract and is shipped with the guard. */
export function isSendableRuleId(id: string): boolean {
  return RULE_ID_PATTERN.test(id) && shippedRuleIds().has(id);
}

/** The only client labels the guard sends: the kind of client, never a host, user or path. */
export const CLIENT_LABELS = ['mcp-proxy', 'claude-code', 'mcp-guard'] as const;
export type ClientLabel = (typeof CLIENT_LABELS)[number];

export type HeartbeatMode = 'enforce' | 'observe';

export interface HeartbeatBody {
  guardVersion: string;
  clientLabel?: ClientLabel;
  mode: HeartbeatMode;
  day: string;
  counts: Counts;
  topRules?: { ruleId: string; count: number }[];
}

const BODY_KEYS = new Set(['guardVersion', 'clientLabel', 'mode', 'day', 'counts', 'topRules']);
const RULE_KEYS = new Set(['ruleId', 'count']);

export function emptyCounts(): Counts {
  return { allowed: 0, blocked: 0, held: 0, approved: 0, denied: 0, expired: 0 };
}

export function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** `day` shifted by `delta` days. */
export function addDays(day: string, delta: number): string {
  return utcDay(Date.parse(`${day}T00:00:00.000Z`) + delta * 86_400_000);
}

let version: string | null = null;
export function guardVersion(): string {
  if (version === null) {
    try {
      version = String(JSON.parse(readFileSync(join(__dirname, '..', '..', '..', 'package.json'), 'utf8')).version);
    } catch {
      version = 'unknown';
    }
  }
  return version;
}

const clamp = (n: unknown): number => (typeof n === 'number' && Number.isFinite(n) ? Math.min(MAX_COUNT, Math.max(0, Math.floor(n))) : 0);

export interface BodyInput {
  guardVersion: string;
  clientLabel?: string;
  mode: string;
  day: string;
  counts: Partial<Record<string, number>>;
  rules?: Record<string, number>;
}

/**
 * Build a body from an allowlist: only the contract's fields are copied, counts are
 * clamped to the contract's range, and every rule id that is not shipped with the guard
 * (or does not match the contract's pattern) is dropped. The top 20 go in `topRules`.
 */
export function buildBody(input: BodyInput): HeartbeatBody {
  const counts = emptyCounts();
  for (const name of COUNT_NAMES) counts[name] = clamp(input.counts[name]);
  const rules = Object.entries(input.rules ?? {})
    .filter(([id, n]) => isSendableRuleId(id) && clamp(n) > 0)
    .map(([ruleId, n]) => ({ ruleId, count: clamp(n) }))
    .sort((a, b) => b.count - a.count || (a.ruleId < b.ruleId ? -1 : 1))
    .slice(0, MAX_TOP_RULES);
  const label = (CLIENT_LABELS as readonly string[]).includes(input.clientLabel ?? '') ? (input.clientLabel as ClientLabel) : undefined;
  return {
    guardVersion: input.guardVersion,
    ...(label ? { clientLabel: label } : {}),
    mode: input.mode === 'observe' ? 'observe' : 'enforce',
    day: input.day,
    counts,
    ...(rules.length ? { topRules: rules } : {}),
  };
}

export type Validated = { ok: true; json: string } | { ok: false; reason: string };

const isCount = (n: unknown): boolean => typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= MAX_COUNT;

/**
 * Check a body against the contract before it is sent: exact field set, patterns,
 * rule ids shipped with the guard only, the day window and the size cap. A body that
 * fails is not sent.
 */
export function validateBody(body: unknown, nowMs: number = Date.now()): Validated {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { ok: false, reason: 'not an object' };
  const b = body as Record<string, unknown>;
  for (const key of Object.keys(b)) if (!BODY_KEYS.has(key)) return { ok: false, reason: `unknown field ${key}` };
  if (typeof b.guardVersion !== 'string' || !GUARD_VERSION_PATTERN.test(b.guardVersion)) return { ok: false, reason: 'guardVersion' };
  if (b.clientLabel !== undefined && (typeof b.clientLabel !== 'string' || !CLIENT_LABEL_PATTERN.test(b.clientLabel) || !(CLIENT_LABELS as readonly string[]).includes(b.clientLabel))) {
    return { ok: false, reason: 'clientLabel' };
  }
  if (b.mode !== 'enforce' && b.mode !== 'observe') return { ok: false, reason: 'mode' };
  const today = utcDay(nowMs);
  if (typeof b.day !== 'string' || !DAY_PATTERN.test(b.day) || utcDay(Date.parse(`${b.day}T00:00:00.000Z`) || 0) !== b.day) return { ok: false, reason: 'day' };
  if (b.day < addDays(today, -PAST_DAYS) || b.day > addDays(today, 1)) return { ok: false, reason: 'day out of range' };
  const counts = b.counts as Record<string, unknown> | null;
  if (!counts || typeof counts !== 'object' || Array.isArray(counts)) return { ok: false, reason: 'counts' };
  if (Object.keys(counts).length !== COUNT_NAMES.length || !COUNT_NAMES.every((n) => isCount(counts[n]))) return { ok: false, reason: 'counts' };
  if (b.topRules !== undefined) {
    if (!Array.isArray(b.topRules) || b.topRules.length > MAX_TOP_RULES) return { ok: false, reason: 'topRules' };
    const seen = new Set<string>();
    for (const r of b.topRules as unknown[]) {
      if (!r || typeof r !== 'object' || Array.isArray(r)) return { ok: false, reason: 'topRules' };
      const rule = r as Record<string, unknown>;
      if (!Object.keys(rule).every((k) => RULE_KEYS.has(k))) return { ok: false, reason: 'topRules' };
      if (typeof rule.ruleId !== 'string' || !isSendableRuleId(rule.ruleId) || seen.has(rule.ruleId) || !isCount(rule.count)) return { ok: false, reason: 'topRules' };
      seen.add(rule.ruleId);
    }
  }
  const json = JSON.stringify(b);
  if (Buffer.byteLength(json, 'utf8') > MAX_BODY_BYTES) return { ok: false, reason: 'too large' };
  return { ok: true, json };
}
