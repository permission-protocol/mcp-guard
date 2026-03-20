import type { Config } from './config.js';

export interface Decision {
  decision: 'allowed' | 'blocked' | 'held_for_approval';
  rule_id: string | null;
  reason: string;
}

const ACTION_TO_DECISION = {
  allow: 'allowed',
  block: 'blocked',
  require_approval: 'held_for_approval',
} as const;

export function evaluate(toolName: string, _toolArgs: Record<string, unknown> | undefined, config: Config): Decision {
  for (const rule of config.rules) {
    if (rule.tool === toolName) {
      return {
        decision: ACTION_TO_DECISION[rule.action],
        rule_id: rule.id,
        reason: `Matched rule "${rule.id}"`,
      };
    }
  }

  return {
    decision: ACTION_TO_DECISION[config.default_action],
    rule_id: null,
    reason: `No matching rule; default action "${config.default_action}"`,
  };
}
