import { readFileSync } from 'node:fs';
import { parse } from 'yaml';

export type Action = 'allow' | 'block' | 'require_approval';

// Permission Deck Slice 1: reversibility is the primary risk axis.
export type Reversibility = 'reversible' | 'irreversible';

export interface Rule {
  id: string;
  tool: string;
  action: Action;
  // --- Permission Deck classifier axes (all optional, back-compat) ---
  reversibility?: Reversibility;  // reversible -> countdown auto-release; irreversible -> hard stop
  countdown_seconds?: number;     // reversible holds auto-release after this many seconds (undo window)
  cap_usd?: number;               // spend cap: under cap may act+verify, at/over cap hard-stops
  verify_threshold?: number;      // 0-100; auto-executed actions below this confidence route to Verify
}

export type Mode = 'enforce' | 'observe';

export interface Config {
  default_action: Action;
  mode: Mode;
  rules: Rule[];
}

const VALID_ACTIONS: Action[] = ['allow', 'block', 'require_approval'];

export function loadConfig(configPath: string): Config {
  let raw: string;
  try {
    raw = readFileSync(configPath, 'utf-8');
  } catch (err: any) {
    throw new Error(`Failed to read config file: ${configPath} (${err.code ?? err.message})`);
  }

  const parsed = parse(raw);

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Config must be a YAML object');
  }

  if (!VALID_ACTIONS.includes(parsed.default_action)) {
    throw new Error(`Invalid default_action: "${parsed.default_action}". Must be one of: ${VALID_ACTIONS.join(', ')}`);
  }

  const VALID_MODES: Mode[] = ['enforce', 'observe'];
  const mode: Mode = parsed.mode ?? 'enforce';
  if (!VALID_MODES.includes(mode)) {
    throw new Error(`Invalid mode: "${parsed.mode}". Must be one of: ${VALID_MODES.join(', ')}`);
  }

  if (!Array.isArray(parsed.rules)) {
    throw new Error('Config must include a "rules" array');
  }

  const VALID_REVERSIBILITY: Reversibility[] = ['reversible', 'irreversible'];

  const rules: Rule[] = parsed.rules.map((r: any, i: number) => {
    if (!r.id || typeof r.id !== 'string') {
      throw new Error(`Rule ${i} missing valid "id"`);
    }
    if (!r.tool || typeof r.tool !== 'string') {
      throw new Error(`Rule ${i} missing valid "tool"`);
    }
    if (!VALID_ACTIONS.includes(r.action)) {
      throw new Error(`Rule ${i} has invalid action: "${r.action}"`);
    }
    if (r.reversibility !== undefined && !VALID_REVERSIBILITY.includes(r.reversibility)) {
      throw new Error(`Rule ${i} has invalid reversibility: "${r.reversibility}". Must be one of: ${VALID_REVERSIBILITY.join(', ')}`);
    }
    for (const numField of ['countdown_seconds', 'cap_usd', 'verify_threshold'] as const) {
      if (r[numField] !== undefined && (typeof r[numField] !== 'number' || r[numField] < 0)) {
        throw new Error(`Rule ${i} has invalid ${numField}: must be a non-negative number`);
      }
    }
    if (r.verify_threshold !== undefined && r.verify_threshold > 100) {
      throw new Error(`Rule ${i} has invalid verify_threshold: must be 0-100`);
    }
    return {
      id: r.id,
      tool: r.tool,
      action: r.action as Action,
      ...(r.reversibility !== undefined ? { reversibility: r.reversibility as Reversibility } : {}),
      ...(r.countdown_seconds !== undefined ? { countdown_seconds: r.countdown_seconds } : {}),
      ...(r.cap_usd !== undefined ? { cap_usd: r.cap_usd } : {}),
      ...(r.verify_threshold !== undefined ? { verify_threshold: r.verify_threshold } : {}),
    };
  });

  return {
    default_action: parsed.default_action as Action,
    mode,
    rules,
  };
}
