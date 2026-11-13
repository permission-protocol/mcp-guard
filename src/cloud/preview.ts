/**
 * The argument preview sent with a held call, so the signer can read what it does.
 *
 * It is built on this machine and is the only argument text that leaves it:
 *
 *   1. mask: values under credential-like keys are replaced whole; in every string
 *      (and key), private key blocks, credentials in URLs, Bearer / Basic / Token
 *      values, known token formats, `password=` / `token=` / `.env`-style
 *      `SECRET_NAME=value` assignments and `--password value` flags, and long opaque
 *      runs (32 or more letters, digits, `_` or `-`) are replaced with MASK;
 *   2. order: in each object, the shortest fields first (`file_path` and `command`
 *      before file content), so the cap below removes long content, not the path;
 *   3. cap: at most MAX_PREVIEW_BYTES of UTF-8, cut on a character boundary, with
 *      CUT_MARK at the end when something was cut.
 *
 * Masking runs before the cap, so a secret is never cut in half and left readable.
 * Over-masking is the accepted direction: the signature covers the call's argsHash
 * (cloud/fingerprint.ts), never this preview, which changes nothing the guard decides.
 * Permission Protocol masks and caps it again on receipt.
 */

export const MAX_PREVIEW_BYTES = 2048;
export const MASK = '[masked]';
export const CUT_MARK = '…';
const MAX_DEPTH = 8;
const MAX_NODES = 2000;

/** Keys whose value is a credential, whatever it looks like. */
const SECRET_KEY = /pass(word|wd|phrase)?$|^pwd$|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|signature|^sig$|cookie|session|credential|auth|bearer|jwt|^key$|^code$|tenant|otp|mfa|connection[-_]?string|^dsn$/i;

/** A name in `NAME=value`, `name: value` or `--name value` that marks the value as secret. */
// Bounded on both sides so a long word cannot make the match quadratic.
const SECRET_NAME = String.raw`[A-Za-z0-9_.-]{0,40}(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|credential|auth|session|cookie|signature|jwt|dsn|conn(?:ection)?[-_]?str(?:ing)?|database[-_]?url)[A-Za-z0-9_.-]{0,40}`;

/** Text rules, applied in order to every string. Each replaces only the secret part. */
const TEXT_RULES: Array<[RegExp, string | ((...m: string[]) => string)]> = [
  // Long opaque runs first: random tokens, hex digests, base64 lines. Every later rule
  // then sees runs of at most 31 such characters.
  [/[A-Za-z0-9_-]{32,}/g, MASK],
  // PEM private keys (also an unterminated block at the end of the text).
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)/g, `${MASK} private key`],
  // user:password@ or token@ in a URL.
  [/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@'"<>]+@/gi, `$1${MASK}@`],
  // Authorization schemes.
  [/\b(Bearer|Basic|Token|Digest)(\s+)[A-Za-z0-9\-._~+/]+=*/gi, `$1$2${MASK}`],
  // Known token formats.
  [/\b(?:pp_(?:live|test)_|ppi_)[A-Za-z0-9_-]+/g, MASK],
  [/\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}/g, MASK],
  [/\bglpat-[A-Za-z0-9_-]{16,}/g, MASK],
  [/\bnpm_[A-Za-z0-9]{30,}/g, MASK],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}/g, MASK],
  [/\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}/g, MASK],
  [/\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}/g, MASK],
  [/\bAIza[A-Za-z0-9_-]{30,}/g, MASK],
  [/\bxai-[A-Za-z0-9]{20,}/g, MASK],
  [/\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b/g, MASK],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, MASK],
  [/(https:\/\/hooks\.slack\.com\/services\/)\S+/g, `$1${MASK}`],
  [/(https:\/\/(?:discord(?:app)?\.com)\/api\/webhooks\/)\S+/g, `$1${MASK}`],
  // NAME=value, name: value, "name": "value" (quoted or bare value; .env lines, headers, config).
  [new RegExp(String.raw`(\b${SECRET_NAME}["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|\x60[^\x60\n]*\x60|[^\s"'\x60,;&|)]+)`, 'gi'), (_m, head) => `${head}${MASK}`],
  // --password value, -p is too short to tell; only named flags.
  [new RegExp(String.raw`(--${SECRET_NAME}\s+)("[^"\n]*"|'[^'\n]*'|[^\s"'-][^\s"']*)`, 'gi'), (_m, head) => `${head}${MASK}`],
  // Four groups of four, as application passwords are written.
  [/\b[A-Za-z0-9]{4}(?: [A-Za-z0-9]{4}){3,}\b/g, (m: string) => (/\d/.test(m) && /[A-Za-z]/.test(m) ? MASK : m)],
];

/** Mask secrets in free text. */
export function maskText(text: string): string {
  let out = text;
  for (const [pattern, replacement] of TEXT_RULES) out = out.replace(pattern, replacement as never);
  return out;
}

const size = (v: unknown): number => {
  try { return JSON.stringify(v)?.length ?? 0; } catch { return Number.MAX_SAFE_INTEGER; }
};

/** The masked copy of `value`: secret keys masked whole, strings masked, objects shortest field first. */
function maskValue(value: unknown, depth: number, seen: WeakSet<object>, budget: { nodes: number }): unknown {
  if (--budget.nodes < 0) return MASK;
  if (typeof value === 'string') return maskText(value);
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value !== 'object') return MASK; // bigint, function, symbol, undefined
  if (seen.has(value) || depth >= MAX_DEPTH) return MASK;
  seen.add(value);
  if (Array.isArray(value)) return value.map((v) => maskValue(v, depth + 1, seen, budget));
  const fields = Object.entries(value as Record<string, unknown>).map(([k, v]) => {
    const key = maskText(k);
    return [key, SECRET_KEY.test(k) && v !== null && v !== undefined && v !== '' ? MASK : maskValue(v, depth + 1, seen, budget)] as const;
  });
  // Shortest first (stable): the path and the command survive the cap, long content is cut.
  const ordered = fields.map((f, i) => ({ f, i, n: size(f[1]) + f[0].length })).sort((a, b) => a.n - b.n || a.i - b.i);
  const out: Record<string, unknown> = {};
  for (const { f } of ordered) out[f[0]] = f[1];
  return out;
}

/** Cut to at most `maxBytes` of UTF-8, on a code point boundary, ending in CUT_MARK when cut. */
export function capUtf8(text: string, maxBytes: number = MAX_PREVIEW_BYTES): string {
  if (Buffer.byteLength(text, 'utf8') <= maxBytes) return text;
  const room = maxBytes - Buffer.byteLength(CUT_MARK, 'utf8');
  let bytes = 0;
  let out = '';
  for (const ch of text) {
    const n = Buffer.byteLength(ch, 'utf8');
    if (bytes + n > room) break;
    bytes += n;
    out += ch;
  }
  return out + CUT_MARK;
}

/** The preview of a held call's arguments: masked, shortest fields first, capped. */
export function argsPreviewOf(args: unknown): string {
  let text: string;
  try {
    text = JSON.stringify(maskValue(args ?? {}, 0, new WeakSet(), { nodes: MAX_NODES })) ?? '';
  } catch {
    text = '';
  }
  return capUtf8(text);
}
