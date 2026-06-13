import type { Config, Rule, Reversibility } from './config.js';
import { classify, extractMeta } from './classify.js';

// Permission Deck Slice 1: which human lane an attention-requiring action lands in.
export type Lane = 'decide' | 'unblock' | 'verify';

export interface Decision {
  decision: 'allowed' | 'blocked' | 'held_for_approval';
  rule_id: string | null;
  reason: string;
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

export function evaluate(toolName: string, toolArgs: Record<string, unknown> | undefined, config: Config): Decision {
  let matched: Rule | null = null;
  for (const rule of config.rules) {
    if (rule.tool === toolName) {
      matched = rule;
      break;
    }
  }

  const base: Decision = matched
    ? {
        decision: ACTION_TO_DECISION[matched.action],
        rule_id: matched.id,
        reason: `Matched rule "${matched.id}"`,
      }
    : {
        decision: ACTION_TO_DECISION[config.default_action],
        rule_id: null,
        reason: `No matching rule; default action "${config.default_action}"`,
      };

  // Enrich with reversibility/confidence lane routing (Permission Deck).
  return classify(base, matched, extractMeta(toolArgs));
}
