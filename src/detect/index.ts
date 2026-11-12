/**
 * Argument detectors: heuristics that stop common destructive mistakes by an agent.
 * They are not a sandbox. See docs/detectors.md for what each catches and misses.
 */
import { cloudDelete } from './cloud.js';
import { secretRead } from './secrets.js';
import { shellDestructive } from './shell-destructive.js';
import { sqlDestructive } from './sql.js';
import { terraformDestroy } from './terraform.js';
import { unparseable, DETECTOR_NAMES, type DetectorName, type DetectorResult } from './types.js';

export { DETECTOR_NAMES, type DetectorName, type DetectorResult } from './types.js';

export const DETECTORS: Record<DetectorName, (text: string) => DetectorResult> = {
  sql_destructive: sqlDestructive,
  shell_destructive: shellDestructive,
  terraform_destroy: terraformDestroy,
  cloud_delete: cloudDelete,
  secret_read: secretRead,
};

export function isDetectorName(v: unknown): v is DetectorName {
  return typeof v === 'string' && (DETECTOR_NAMES as readonly string[]).includes(v);
}

const shellQuote = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

/**
 * Run a detector on one argument value. Returns null when the value carries no text
 * (absent, number, boolean, null). A list of strings is read as an argv (or, for SQL,
 * as statements). Any other shape cannot be read and fails safe.
 */
export function detectValue(name: DetectorName, value: unknown): DetectorResult | null {
  if (value === undefined || value === null || typeof value === 'number' || typeof value === 'boolean') return null;
  const fn = DETECTORS[name];
  if (typeof value === 'string') return fn(value);
  if (Array.isArray(value) && value.every((v) => typeof v === 'string')) {
    return fn(name === 'sql_destructive' ? value.join(';\n') : value.map(shellQuote).join(' '));
  }
  return unparseable('non_text_argument');
}

export const MAX_TARGET_LENGTH = 120;

/**
 * Make a detector target safe to show: placeholders for unknown values, no control or
 * format characters (including bidi overrides), collapsed whitespace, bounded length.
 */
export function sanitizeTarget(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const cleaned = raw
    .replace(/\u0000/g, '…')
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!cleaned) return undefined;
  const chars = Array.from(cleaned);
  return chars.length > MAX_TARGET_LENGTH ? chars.slice(0, MAX_TARGET_LENGTH - 1).join('') + '…' : cleaned;
}
