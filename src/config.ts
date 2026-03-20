import { readFileSync } from 'node:fs';
import { parse } from 'yaml';

export type Action = 'allow' | 'block' | 'require_approval';

export interface Rule {
  id: string;
  tool: string;
  action: Action;
}

export interface Config {
  default_action: Action;
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

  if (!Array.isArray(parsed.rules)) {
    throw new Error('Config must include a "rules" array');
  }

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
    return { id: r.id, tool: r.tool, action: r.action as Action };
  });

  return {
    default_action: parsed.default_action as Action,
    rules,
  };
}
