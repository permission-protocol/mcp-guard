/**
 * Argument detectors: heuristics that stop common destructive mistakes by an agent.
 * They are not a sandbox. See docs/detectors.md for what each catches and misses.
 */
import { cloudDelete } from './cloud.js';
import { guardTamper } from './guard-tamper.js';
import { secretRead } from './secrets.js';
import { shellDestructive, SHELL_DESTRUCTIVE_KINDS } from './shell-destructive.js';
import { sqlDestructive } from './sql.js';
import { terraformDestroy } from './terraform.js';
import { unparseable, DETECTOR_NAMES, type DetectorName, type DetectorResult, type KindFilter } from './types.js';

export { DETECTOR_NAMES, type DetectorName, type DetectorResult, type KindFilter } from './types.js';

export const DETECTORS: Record<DetectorName, (text: string, filter?: KindFilter) => DetectorResult> = {
  sql_destructive: sqlDestructive,
  shell_destructive: shellDestructive,
  terraform_destroy: terraformDestroy,
  cloud_delete: cloudDelete,
  secret_read: secretRead,
  guard_tamper: guardTamper,
};

/**
 * Detectors a rule can narrow by kind (`detect.kinds` / `detect.except_kinds`), with the
 * kinds they can report. Only these; the loader refuses a kind filter anywhere else.
 */
export const FILTERABLE_KINDS: Partial<Record<DetectorName, readonly string[]>> = {
  shell_destructive: SHELL_DESTRUCTIVE_KINDS,
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
export function detectValue(name: DetectorName, value: unknown, filter?: KindFilter): DetectorResult | null {
  if (value === undefined || value === null || typeof value === 'number' || typeof value === 'boolean') return null;
  const fn = DETECTORS[name];
  if (typeof value === 'string') return fn(value, filter);
  if (Array.isArray(value) && value.every((v) => typeof v === 'string')) {
    return fn(name === 'sql_destructive' ? value.join(';\n') : value.map(shellQuote).join(' '), filter);
  }
  return unparseable('non_text_argument');
}

export const MAX_TARGET_LENGTH = 120;

/** Blank-looking letters and symbols (Hangul fillers, the blank Braille pattern) and variation selectors: removed. */
const INVISIBLE = /[\u115F\u1160\u3164\uFFA0\u2800\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu;

function cleanTarget(text: string): string {
  return text
    .replace(/\u0000/g, '…')
    // Control and format characters (bidi overrides included), line and paragraph
    // separators, and every space separator other than U+0020 become a plain space.
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]|(?! )\p{Zs}/gu, ' ')
    .replace(INVISIBLE, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Make a detector target safe to show: placeholders for unknown values; no control or
 * format characters (including bidi overrides); no space but U+0020; no Hangul fillers,
 * blank Braille or variation selectors; whitespace runs collapsed to one space; then
 * `mask` (if given) before the cut, so a secret is never cut in half and left readable;
 * at most 120 code points. Combining marks are kept. Undefined when nothing is left.
 */
export function sanitizeTarget(raw: string | undefined, mask?: (text: string) => string): string | undefined {
  if (raw === undefined) return undefined;
  let cleaned = cleanTarget(raw);
  if (mask) cleaned = cleanTarget(mask(cleaned));
  if (!cleaned) return undefined;
  const chars = Array.from(cleaned);
  return chars.length > MAX_TARGET_LENGTH ? chars.slice(0, MAX_TARGET_LENGTH - 1).join('') + '…' : cleaned;
}
