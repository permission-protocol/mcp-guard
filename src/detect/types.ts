/**
 * Shared types for argument detectors.
 *
 * A detector is a pure function over text an agent supplied. It never does I/O. Its
 * result names what it found by a `kind` from a fixed set (safe to show and log) and,
 * where it can, a `target` taken from the agent's text (untrusted: callers sanitize it
 * and never put it in a signed or logged field).
 */

export const DETECTOR_NAMES = [
  'sql_destructive',
  'shell_destructive',
  'terraform_destroy',
  'cloud_delete',
  'secret_read',
] as const;

export type DetectorName = (typeof DETECTOR_NAMES)[number];

/** Why a detector could not read the text. A fixed set: these appear in reasons. */
export type UnparseableReason =
  | 'too_long'
  | 'unbalanced_quote'
  | 'unterminated_substitution'
  | 'unterminated_comment'
  | 'ansi_c_quote'
  | 'dynamic_command'
  | 'glob_command'
  | 'dynamic_argument'
  | 'eval'
  | 'interpreter_stdin'
  | 'inline_code'
  | 'dynamic_sql'
  | 'nesting_too_deep'
  | 'non_text_argument';

export interface DetectorResult {
  /** True when the rule should apply: a destructive action was found, or the text could not be read. */
  matched: boolean;
  /** What was found, from a fixed per-detector set; `none` when nothing was. */
  kind: string;
  /** The object acted on (table, path, branch, resource), from the agent's text. Untrusted. */
  target?: string;
  /** False when the detector could not confidently read the text and matched to fail safe. */
  parsed: boolean;
  /** Present when `parsed` is false. */
  reason?: UnparseableReason;
}

export const NOT_MATCHED: DetectorResult = Object.freeze({ matched: false, kind: 'none', parsed: true }) as DetectorResult;

export function found(kind: string, target?: string): DetectorResult {
  return target ? { matched: true, kind, target, parsed: true } : { matched: true, kind, parsed: true };
}

export function unparseable(reason: UnparseableReason, kind = 'unparseable'): DetectorResult {
  return { matched: true, kind, parsed: false, reason };
}

/** Text longer than this is not read: it fails safe. */
export const MAX_DETECT_INPUT = 256 * 1024;
