import { ANY_TOOL, TOOLS_CALL, type Config, type MatchCondition, type Rule, type Reversibility } from './config.js';
import { classify, extractMeta } from './classify.js';
import { detectValue, sanitizeTarget, type DetectorName, type DetectorResult } from './detect/index.js';

// Permission Deck Slice 1: which human lane an attention-requiring action lands in.
export type Lane = 'decide' | 'unblock' | 'verify';

/**
 * What a detector found in the call's arguments. `kind` comes from a fixed set. `target`
 * is from the agent's arguments: sanitized and bounded, for showing an approver. It is
 * never written to a receipt, the receipt log or a decision line.
 */
export interface DetectedEffect {
  detector: DetectorName;
  kind: string;
  target?: string;
  /** False when the detector could not read the argument and matched to fail safe. */
  parsed: boolean;
  reason?: string;
}

export interface Decision {
  decision: 'allowed' | 'blocked' | 'held_for_approval';
  rule_id: string | null;
  reason: string;
  /** Present when the matching rule used `detect`. */
  effect?: DetectedEffect;
  // --- Permission Deck enrichment (present when human attention is or may be needed) ---
  lane?: Lane;
  reversibility?: Reversibility;
  countdown_seconds?: number;  // reversible Decide holds auto-release after this; absent = hard stop
  confidence?: number;         // agent self-reported confidence (0-100) if provided
}

const ACTION_TO_DECISION = {
  allow: 'allowed',
  block: 'blocked',
  require_approval: 'held_for_approval',
} as const;

/** Values longer than this are not tested against `match`: the condition is undecided. */
export const MAX_MATCH_INPUT = 64 * 1024;

type Verdict = 'yes' | 'no' | 'unknown';

function testCondition(cond: MatchCondition, value: unknown): Verdict {
  if (value === undefined) return 'no';
  if (typeof value !== 'string' || value.length > MAX_MATCH_INPUT) return 'unknown';
  const fold = (s: string): string => (cond.ignore_case ? s.toLowerCase() : s);
  if (cond.equals !== undefined) return fold(value) === fold(cond.equals) ? 'yes' : 'no';
  if (cond.contains !== undefined) return fold(value).includes(fold(cond.contains)) ? 'yes' : 'no';
  if (cond.regex) return cond.regex.test(value) ? 'yes' : 'no';
  return 'no';
}

/**
 * Whether a rule's argument conditions hold. When a condition cannot be decided (the
 * argument is not a string, or is too long), it resolves toward the stricter outcome:
 * it holds for block / require_approval rules and fails for allow rules.
 */
function conditionsHold(rule: Rule, args: Record<string, unknown> | undefined): { ok: boolean; effect?: DetectedEffect } {
  const strict = rule.action !== 'allow';
  if (rule.match) {
    for (const [name, cond] of Object.entries(rule.match)) {
      const v = testCondition(cond, args?.[name]);
      if (v === 'no' || (v === 'unknown' && !strict)) return { ok: false };
    }
  }
  if (!rule.detect) return { ok: true };
  let uncertain: DetectorResult | null = null;
  for (const name of rule.detect.args) {
    const r = detectValue(rule.detect.detector, args?.[name]);
    if (!r || !r.matched) continue;
    if (r.parsed) return { ok: true, effect: effectOf(rule.detect.detector, r) };
    uncertain ??= r;
  }
  return uncertain ? { ok: true, effect: effectOf(rule.detect.detector, uncertain) } : { ok: false };
}

function effectOf(detector: DetectorName, r: DetectorResult): DetectedEffect {
  const target = sanitizeTarget(r.target);
  return {
    detector,
    kind: r.kind,
    ...(target ? { target } : {}),
    parsed: r.parsed,
    ...(r.reason ? { reason: r.reason } : {}),
  };
}

/** Rule ids, detector names, kinds and reasons only: never argument text. */
function describe(rule: Rule, effect: DetectedEffect | undefined): string {
  if (!effect) return `Matched rule "${rule.id}"`;
  if (!effect.parsed) return `Matched rule "${rule.id}" (${effect.detector}: could not read the argument [${effect.reason ?? effect.kind}], fail-safe)`;
  return `Matched rule "${rule.id}" (${effect.detector}: ${effect.kind})`;
}

/**
 * Decide a gated request. `toolName` is the tool for `tools/call` and null for other
 * methods. Rules are tried in order and the first that matches wins: a rule matches on
 * method, tool (exact name or "*"), and its `match` / `detect` conditions if any.
 */
export function evaluate(
  toolName: string | null,
  toolArgs: Record<string, unknown> | undefined,
  config: Config,
  method: string = TOOLS_CALL,
): Decision {
  let matched: Rule | null = null;
  let effect: DetectedEffect | undefined;
  for (const rule of config.rules) {
    if ((rule.method ?? TOOLS_CALL) !== method) continue;
    if (method === TOOLS_CALL && rule.tool !== ANY_TOOL && rule.tool !== toolName) continue;
    const held = conditionsHold(rule, toolArgs);
    if (!held.ok) continue;
    matched = rule;
    effect = held.effect;
    break;
  }

  const base: Decision = matched
    ? {
        decision: ACTION_TO_DECISION[matched.action],
        rule_id: matched.id,
        reason: describe(matched, effect),
        ...(effect ? { effect } : {}),
      }
    : {
        decision: ACTION_TO_DECISION[config.default_action],
        rule_id: null,
        reason: `No matching rule; default action "${config.default_action}"`,
      };

  // Enrich with reversibility/confidence lane routing (Permission Deck).
  return classify(base, matched, extractMeta(toolArgs), toolArgs);
}
