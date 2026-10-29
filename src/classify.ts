import type { Rule, Reversibility } from './config.js';
import type { Decision } from './engine.js';

/**
 * Permission Deck Slice 1 — the reversibility/confidence classifier.
 *
 * The base engine produces allow | block | held_for_approval from a rule match. This
 * layer enriches an attention-requiring decision with:
 *   - which human lane it belongs in (decide | unblock | verify)
 *   - reversibility (the primary risk axis)
 *   - a countdown for reversible holds
 *
 * It can also DOWNGRADE a protected spend under its cap into an "act now, surface in
 * Verify" decision. The amount is read only from the argument the rule names
 * (`amount_arg`) — the argument the tool actually acts on — never from agent metadata.
 *
 * Agent metadata under `_pp` (confidence, requires_input) can only ADD human attention:
 * it routes lanes but never turns a held or blocked call into an allowed one.
 *
 * Pure function. No I/O. Fully unit-testable.
 */

export interface ActionMeta {
  confidence?: number;       // 0-100, agent self-report
  requires_input?: boolean;  // needs a credential/fact only the human has
}

/** Pull Permission Deck lane hints out of the tool-call args (under `_pp`). */
export function extractMeta(toolArgs: Record<string, unknown> | undefined): ActionMeta {
  const pp = toolArgs?._pp;
  const meta: ActionMeta = {};
  if (!pp || typeof pp !== 'object' || Array.isArray(pp)) return meta;
  const p = pp as Record<string, unknown>;
  if (typeof p.confidence === 'number' && Number.isFinite(p.confidence)) meta.confidence = clamp(p.confidence, 0, 100);
  if (typeof p.requires_input === 'boolean') meta.requires_input = p.requires_input;
  return meta;
}

/** The capped amount, or undefined when it is missing or not a finite non-negative number. */
export function readAmount(rule: Rule, toolArgs: Record<string, unknown> | undefined): number | undefined {
  if (!rule.amount_arg) return undefined;
  const v = toolArgs?.[rule.amount_arg];
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : undefined;
}

export function classify(
  base: Decision,
  rule: Rule | null,
  meta: ActionMeta,
  toolArgs?: Record<string, unknown>,
): Decision {
  // Explicit hard block or plain allow with no protected rule: pass through untouched.
  if (base.decision === 'blocked') return base;
  if (base.decision === 'allowed') {
    // Allowed actions can still be surfaced for Verify when confidence is low.
    return maybeVerify(base, rule, meta);
  }

  // From here: the action is held_for_approval. Resolve the lane.
  const reversibility: Reversibility = rule?.reversibility ?? 'irreversible'; // fail safe: unknown = irreversible
  const confidence = meta.confidence !== undefined ? { confidence: meta.confidence } : {};

  // 1) Needs an input only the human has -> Unblock. No countdown. An irreversible hold
  //    stays a Decide hard stop whatever the agent claims.
  if (meta.requires_input && reversibility === 'reversible') {
    return {
      ...base,
      lane: 'unblock',
      reversibility,
      ...confidence,
      reason: `${base.reason}; needs human-only input`,
    };
  }

  // 2) Spend with a cap -> act+verify under cap, hard-stop at/over cap or when unreadable.
  if (rule?.cap_usd !== undefined) {
    const amount = readAmount(rule, toolArgs);
    if (amount === undefined) {
      return {
        ...base,
        lane: 'decide',
        reversibility: 'irreversible',
        ...confidence,
        reason: `${base.reason}; "${rule.amount_arg}" missing or not a non-negative number — hard stop`,
      };
    }
    if (amount < rule.cap_usd) {
      return {
        ...base,
        decision: 'allowed', // under cap: act now under the standing rule...
        lane: 'verify',      // ...but surface for post-hoc confirmation
        reversibility,
        ...confidence,
        reason: `${base.reason}; under the $${rule.cap_usd} cap — acted, routed to Verify`,
      };
    }
    return {
      ...base,
      lane: 'decide',
      reversibility: 'irreversible', // over-cap spend is treated as a hard stop
      ...confidence,
      reason: `${base.reason}; at or over the $${rule.cap_usd} cap — hard stop`,
    };
  }

  // 3) General held action -> Decide. Reversible gets a countdown; irreversible is a hard stop.
  const decideCard: Decision = { ...base, lane: 'decide', reversibility, ...confidence };
  if (reversibility === 'reversible' && rule?.countdown_seconds) {
    decideCard.countdown_seconds = rule.countdown_seconds;
    decideCard.reason = `${base.reason}; reversible — auto-releases in ${rule.countdown_seconds}s unless held`;
  } else {
    decideCard.reason = `${base.reason}; ${reversibility} — hard stop until approved`;
  }
  return decideCard;
}

/** An allowed action routes to Verify when its self-reported confidence is below threshold. */
function maybeVerify(base: Decision, rule: Rule | null, meta: ActionMeta): Decision {
  if (rule?.verify_threshold === undefined || meta.confidence === undefined) return base;
  const threshold = rule.verify_threshold;
  if (meta.confidence < threshold) {
    return {
      ...base,
      lane: 'verify',
      confidence: meta.confidence,
      reason: `${base.reason}; confidence ${meta.confidence} < ${threshold} — routed to Verify`,
    };
  }
  return base;
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}
