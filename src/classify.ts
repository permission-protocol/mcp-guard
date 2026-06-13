import type { Rule, Reversibility } from './config.js';
import type { Decision } from './engine.js';

/**
 * Permission Deck Slice 1 — the reversibility/confidence classifier.
 *
 * The base engine produces allow | block | held_for_approval from a tool->action
 * match. This layer enriches an attention-requiring decision with:
 *   - which human lane it belongs in (decide | unblock | verify)
 *   - reversibility (the primary risk axis)
 *   - a countdown for reversible holds (silence is safe — auto-release w/ undo)
 *
 * It can also DOWNGRADE a protected-but-reversible spend under cap into an
 * "act now, surface in Verify" decision, so routine work clears itself while
 * the agent still raises its own low-confidence completions.
 *
 * Pure function. No I/O. Fully unit-testable.
 */

const DEFAULT_VERIFY_THRESHOLD = 70;

export interface ActionMeta {
  confidence?: number;       // 0-100, agent self-report
  amount_usd?: number;       // spend amount
  requires_input?: boolean;  // needs a credential/fact only the human has
}

/** Pull Permission Deck metadata out of the tool-call args (under `_pp`, with fallbacks). */
export function extractMeta(toolArgs: Record<string, unknown> | undefined): ActionMeta {
  const pp = (toolArgs?._pp ?? {}) as Record<string, unknown>;
  const meta: ActionMeta = {};

  if (typeof pp.confidence === 'number') meta.confidence = clamp(pp.confidence, 0, 100);

  if (typeof pp.amount_usd === 'number') meta.amount_usd = pp.amount_usd;
  else if (typeof toolArgs?.amount_usd === 'number') meta.amount_usd = toolArgs.amount_usd as number;
  else if (typeof toolArgs?.amount === 'number') meta.amount_usd = toolArgs.amount as number;

  if (typeof pp.requires_input === 'boolean') meta.requires_input = pp.requires_input;

  return meta;
}

export function classify(base: Decision, rule: Rule | null, meta: ActionMeta): Decision {
  // Explicit hard block or plain allow with no protected rule: pass through untouched.
  if (base.decision === 'blocked') return base;
  if (base.decision === 'allowed' && (!rule || rule.action === 'allow')) {
    // Allowed actions can still be surfaced for Verify when confidence is low.
    return maybeVerify(base, rule, meta);
  }

  // From here: the action is held_for_approval (or a protected allow). Resolve the lane.
  const reversibility: Reversibility = rule?.reversibility ?? 'irreversible'; // fail safe: unknown = irreversible

  // 1) Needs an input only the human has -> Unblock. No countdown.
  if (meta.requires_input) {
    return {
      ...base,
      decision: 'held_for_approval',
      lane: 'unblock',
      reversibility,
      ...(meta.confidence !== undefined ? { confidence: meta.confidence } : {}),
      reason: `${base.reason}; needs human-only input`,
    };
  }

  // 2) Spend with a cap -> act+verify under cap, hard-stop at/over cap.
  if (rule?.cap_usd !== undefined && meta.amount_usd !== undefined) {
    if (meta.amount_usd < rule.cap_usd) {
      return {
        ...base,
        decision: 'allowed', // under cap: act now under the standing rule...
        lane: 'verify',      // ...but surface for post-hoc confirmation
        reversibility,
        ...(meta.confidence !== undefined ? { confidence: meta.confidence } : {}),
        reason: `${base.reason}; $${meta.amount_usd} under $${rule.cap_usd} cap — acted, routed to Verify`,
      };
    }
    return {
      ...base,
      decision: 'held_for_approval',
      lane: 'decide',
      reversibility: 'irreversible', // over-cap spend is treated as a hard stop
      ...(meta.confidence !== undefined ? { confidence: meta.confidence } : {}),
      reason: `${base.reason}; $${meta.amount_usd} at/over $${rule.cap_usd} cap — hard stop`,
    };
  }

  // 3) General held action -> Decide. Reversible gets a countdown; irreversible is a hard stop.
  const decideCard: Decision = {
    ...base,
    decision: 'held_for_approval',
    lane: 'decide',
    reversibility,
    ...(meta.confidence !== undefined ? { confidence: meta.confidence } : {}),
    reason: base.reason,
  };

  if (reversibility === 'reversible' && rule?.countdown_seconds !== undefined) {
    decideCard.countdown_seconds = rule.countdown_seconds;
    decideCard.reason = `${base.reason}; reversible — auto-releases in ${rule.countdown_seconds}s unless held`;
  } else {
    decideCard.reason = `${base.reason}; ${reversibility} — hard stop until approved`;
  }

  return decideCard;
}

/** An allowed action routes to Verify when its self-reported confidence is below threshold. */
function maybeVerify(base: Decision, rule: Rule | null, meta: ActionMeta): Decision {
  const threshold = rule?.verify_threshold ?? DEFAULT_VERIFY_THRESHOLD;
  if (meta.confidence !== undefined && rule?.verify_threshold !== undefined && meta.confidence < threshold) {
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
