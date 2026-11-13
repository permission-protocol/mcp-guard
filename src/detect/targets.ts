/**
 * Production targets: does an argument name one of the literal names a policy listed
 * under `targets:`? A name matches wherever it appears as a whole word (not preceded or
 * followed by a letter or digit), case-insensitively, in the text as written and in the
 * text with quotes and backslashes removed (`pr""od` reads as `prod`).
 *
 * Bounded: names are literals (no patterns), at most 64 per kind, and text over 64 KB is
 * not read. Fail safe: text that cannot be read matches, like a detector.
 *
 * Pure. No I/O.
 */
import type { TargetKind, Targets } from '../config.js';
import { unparseable, type DetectorResult } from './types.js';

/** Text longer than this is not read: it fails safe. Same bound as `match`. */
export const MAX_TARGET_INPUT = 64 * 1024;

const isWordChar = (c: string | undefined): boolean => c !== undefined && /[a-z0-9]/.test(c);

function mentions(text: string, name: string): boolean {
  let at = text.indexOf(name);
  while (at >= 0) {
    if (!isWordChar(text[at - 1]) && !isWordChar(text[at + name.length])) return true;
    at = text.indexOf(name, at + 1);
  }
  return false;
}

function textOf(value: unknown): string | null | DetectorResult {
  if (value === undefined || value === null || typeof value === 'boolean') return null;
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && value.every((v) => typeof v === 'string' || typeof v === 'number')) return value.join('\n');
  return unparseable('non_text_argument', 'production_target');
}

/** The first listed target the value names, a fail-safe match, or null. */
export function matchTargets(targets: Targets, kinds: readonly TargetKind[], value: unknown): DetectorResult | null {
  const text = textOf(value);
  if (text === null || typeof text === 'object') return text;
  if (text.length > MAX_TARGET_INPUT) return unparseable('too_long', 'production_target');
  const lower = text.toLowerCase();
  const variants = [lower];
  const stripped = lower.replace(/["'`\\]/g, '');
  if (stripped !== lower) variants.push(stripped);
  for (const kind of kinds) {
    for (const name of targets[kind]) {
      if (variants.some((v) => mentions(v, name))) return { matched: true, kind, target: name, parsed: true };
    }
  }
  return null;
}
