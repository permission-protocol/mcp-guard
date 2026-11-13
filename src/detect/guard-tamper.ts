/**
 * guard_tamper: an agent switching off the guard that watches it. Covers shell commands
 * and file-tool paths that would modify, move or delete
 *   - a policy file: `pp.config.yaml` / `.yml` anywhere, `mcp-guard/policies/*`;
 *   - a receipt log: any `*receipts.jsonl`;
 *   - the key store, install token and hook state: `mcp-guard/keys/*`, `mcp-guard/install-token`, `hook-requests.json`,
 *     and the `.config/mcp-guard` directory itself;
 *   - an MCP client configuration that routes a server through the guard: `.mcp.json`,
 *     `.claude.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`,
 *     `.claude/settings*.json`, `.codex/config.toml`, `.gemini/settings.json`,
 *     `.codeium/windsurf/mcp_config.json`, and the directories that hold them;
 * and that would kill the guard process (`pkill` / `killall` / `taskkill` naming
 * mcp-guard or node, `kill` fed by `pgrep` / `pidof` naming them, `kill -1`), or rotate,
 * revoke or re-create its keys through the `mcp-guard` CLI.
 *
 * Reading those files is not a match. Paths are matched by name, case-insensitively: the
 * guard does not know where a custom `--config` or `PP_KEYS_DIR` points. See
 * docs/presets.md for what this misses.
 *
 * Pure. No I/O.
 */
import { overShell } from './combine.js';
import { operands, positionals, DYN, type Cmd, type Word } from './shell.js';
import { found, unparseable, type DetectorResult } from './types.js';

type Kind = 'edit_policy' | 'edit_receipts' | 'edit_keys' | 'edit_hook_state' | 'edit_client_config' | 'kill_guard' | 'guard_cli';

/** Protected locations, as path segments from the end of a path. */
const PROTECTED: Array<[string[], Kind]> = [
  [['pp.config.yaml'], 'edit_policy'],
  [['pp.config.yml'], 'edit_policy'],
  [['mcp-guard', 'policies'], 'edit_policy'],
  [['pp-receipts.jsonl'], 'edit_receipts'],
  [['self-test-receipts.jsonl'], 'edit_receipts'],
  [['mcp-guard', 'keys'], 'edit_keys'],
  [['mcp-guard', 'install-token'], 'edit_keys'],
  [['hook-requests.json'], 'edit_hook_state'],
  [['.mcp.json'], 'edit_client_config'],
  [['.claude.json'], 'edit_client_config'],
  [['claude_desktop_config.json'], 'edit_client_config'],
  [['.cursor', 'mcp.json'], 'edit_client_config'],
  [['.vscode', 'mcp.json'], 'edit_client_config'],
  [['.claude', 'settings.json'], 'edit_client_config'],
  [['.claude', 'settings.local.json'], 'edit_client_config'],
  [['.codex', 'config.toml'], 'edit_client_config'],
  [['.gemini', 'settings.json'], 'edit_client_config'],
  [['.codeium', 'windsurf', 'mcp_config.json'], 'edit_client_config'],
  [['.config', 'mcp-guard'], 'edit_keys'],
];

/** One-segment directories whose removal or move takes a protected file with it. */
const PROTECTED_DIRS = new Set(['.cursor', '.claude', '.codex', '.gemini', '.codeium', '.vscode']);

/**
 * Lexical normalisation, no I/O: lower case (over-matches on case-sensitive file systems,
 * never under-matches on case-insensitive ones), `\\` as `/`, `~` / `~user` dropped,
 * empty and `.` segments dropped (`./x`, `x//y`, trailing `/`), `a/../b` resolved to `b`.
 * A `..` that climbs above the start of the path is kept: the suffix after it still
 * matches. Symlinks, bind mounts and the working directory are not resolved.
 */
function segments(text: string): string[] {
  const out: string[] = [];
  for (const seg of text.toLowerCase().replace(/\\/g, '/').replace(/^~[^/]*/, '').split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..' && out.length && out[out.length - 1] !== '..') { out.pop(); continue; }
    out.push(seg);
  }
  return out;
}

function globSegment(seg: string): RegExp {
  let re = '';
  for (const c of seg) {
    if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '[' || c === ']') re += '.';
    else re += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

function segMatches(pattern: string, seg: string, glob: boolean): boolean {
  if (!glob || !/[*?[]/.test(pattern)) return pattern === seg;
  // A leading wildcard does not match a leading dot, as in the shell.
  if (seg.startsWith('.') && !pattern.startsWith('.')) return false;
  return globSegment(pattern).test(seg);
}

/** The protected kind a path names, the path being the file itself, inside it, or a directory holding it. */
export function guardPathKind(word: Pick<Word, 'text' | 'home' | 'glob'>): Kind | null {
  if (!word.text || word.text.includes(DYN)) return null;
  const segs = segments(word.text);
  if (!segs.length) return null;
  const last = segs[segs.length - 1];
  if (!word.glob && /receipts\.jsonl$/.test(last)) return 'edit_receipts';
  const homeRooted = (word.home && segs.length === 1) || /^\/(home\/[^/]+|users\/[^/]+|root)\/\.config$/i.test(word.text.replace(/\/+$/, ''));
  // Most specific entry first: `.config/mcp-guard` (the whole directory) is last.
  for (const [prot, kind] of PROTECTED) {
    for (let k = 0; k < segs.length; k++) {
      const tail = segs.slice(k);
      // The path is the protected entry, or inside it.
      if (tail.length >= prot.length && prot.every((p, j) => segMatches(tail[j], p, word.glob))) return kind;
      // The path is a directory that holds the protected entry.
      if (tail.length < prot.length && tail.every((t, j) => segMatches(t, prot[j], word.glob))) {
        if (tail.length > 1) return kind;
        if (PROTECTED_DIRS.has(prot[0])) return kind;
        if (prot[0] === '.config' && homeRooted && k === segs.length - 1) return kind;
      }
    }
  }
  return null;
}

const word = (text: string, from?: Word): Word => ({ text, dynamic: false, vars: [], home: from?.home ?? false, glob: from?.glob ?? false, quoted: false });

/** Basenames a file inside a protected directory can have (keys.json, *.private.pem, policies/*.yaml). */
const PROTECTED_CHILD = /\.(json|pem|ya?ml|toml|jsonl)$/;
const PROTECTED_PARENTS = new Set(['keys', 'policies', 'mcp-guard', '.claude', '.cursor', '.vscode', '.codex', '.gemini', 'windsurf', '.config']);

/**
 * A written path with an unknown part (`"$CFG"`, `$DIR/settings.json`): could it be a
 * protected one? Only the static segments after the last unknown one can be read. When
 * they name a protected entry, that is a finding; when they rule one out (a static parent
 * and name that no protected entry has), no match; otherwise it fails safe.
 */
function unresolved(w: Word): DetectorResult | null {
  const raw = w.text.toLowerCase().replace(/\\/g, '/').split('/');
  const lastDyn = raw.map((x) => x.includes(DYN)).lastIndexOf(true);
  const tail = raw.slice(lastDyn + 1).filter((x) => x && x !== '.');
  if (tail.includes('..')) return unparseable('dynamic_argument', 'guard_tamper');
  if (tail.length) {
    const kind = guardPathKind({ text: tail.join('/'), home: false, glob: w.glob });
    if (kind) return found(kind, w.text);
    const name = tail[tail.length - 1];
    const parent = tail.length > 1 ? tail[tail.length - 2] : null;
    if (parent !== null && !PROTECTED_PARENTS.has(parent)) return null;
    if (!PROTECTED_CHILD.test(name) && !PROTECTED_PARENTS.has(name)) return null;
  }
  return unparseable('dynamic_argument', 'guard_tamper');
}

/** The first protected path among the written words: a definite finding wins over an unresolved path. */
function hit(words: Word[]): DetectorResult | null {
  let uncertain: DetectorResult | null = null;
  for (const w of words) {
    if (w.text.includes(DYN)) { uncertain ??= unresolved(w); continue; }
    const kind = guardPathKind(w);
    if (kind) return found(kind, w.text);
  }
  return uncertain;
}

/** Commands whose every operand is modified, moved or deleted. */
const MODIFY_ALL = new Set([
  'rm', 'rmdir', 'unlink', 'shred', 'truncate', 'chmod', 'chown', 'chgrp', 'chattr', 'setfacl', 'tee', 'sponge',
  // PowerShell (the reader is POSIX: write paths with `/`; a `\\` is read as an escape).
  'remove-item', 'ri', 'del', 'erase', 'rd', 'set-content', 'add-content', 'clear-content', 'out-file', 'move-item', 'mi', 'rename-item', 'ren',
  'vi', 'vim', 'nvim', 'nano', 'emacs', 'micro', 'hx', 'helix', 'ed', 'ex', 'code', 'cursor', 'subl', 'gedit', 'patch',
]);
/** Commands that write to their last operand (or `-t DIR`). */
const COPY_TO = new Set(['cp', 'install', 'ln', 'rsync', 'scp', 'ditto', 'copy-item', 'cpi']);

function destination(cmd: Cmd): { dest: Word | undefined; sources: Word[] } {
  const ops = operands(cmd.args);
  const t = cmd.args.findIndex((w) => w.text === '-t' || w.text === '--target-directory');
  if (t >= 0 && cmd.args[t + 1]) return { dest: cmd.args[t + 1], sources: ops.filter((w) => w !== cmd.args[t + 1]) };
  const long = cmd.args.find((w) => w.text.startsWith('--target-directory='));
  if (long) return { dest: word(long.text.slice('--target-directory='.length), long), sources: ops };
  return { dest: ops[ops.length - 1], sources: ops.slice(0, -1) };
}

/**
 * The destination itself and, when it is plainly a directory (a trailing `/`, `.`, `..`,
 * `~`, `-t DIR`, or more than one source), each source's name inside it
 * (`cp x/.mcp.json ~/`).
 */
function destinations(cmd: Cmd): Word[] {
  const { dest, sources } = destination(cmd);
  if (!dest) return [];
  const out = [dest];
  const t = dest.text;
  const isDir = t.endsWith('/') || t === '.' || t === '..' || t === '~' || sources.length > 1 || cmd.args.some((w) => w.text === '-t' || w.text.startsWith('--target-directory'));
  if (!isDir) return out;
  for (const s of sources) {
    const base = s.text.replace(/\/+$/, '').split('/').pop();
    if (base && !base.includes(DYN)) out.push(word(`${t.replace(/\/+$/, '')}/${base}`, dest));
  }
  return out;
}

function inPlace(cmd: Cmd): boolean {
  const a = cmd.args;
  switch (cmd.name) {
    case 'sed': case 'gsed': return a.some((w) => /^-[A-Za-z]*i/.test(w.text) || w.text.startsWith('--in-place'));
    case 'perl': return a.some((w) => /^-[A-Za-z]*i/.test(w.text));
    case 'awk': case 'gawk': return a.some((w, i) => (w.text === '-i' && a[i + 1]?.text === 'inplace') || w.text === '-iinplace');
    case 'yq': return a.some((w) => w.text === '-i' || w.text === '--inplace');
    default: return false;
  }
}

function writeRedirect(cmd: Cmd): DetectorResult | null {
  for (const r of cmd.redirects) {
    if (!r.target || !(r.op.includes('>') || r.op === '<>') || r.op === '>&') continue;
    const h = hit([r.target]);
    if (h) return h;
  }
  return null;
}

const GUARD_PROCESS = /mcp-guard|mcp_guard/;
const NODE = /^(node|nodejs|node\.exe)$/;

/** A process name or pattern that covers the guard. */
function namesGuard(text: string): boolean {
  const t = text.toLowerCase();
  return GUARD_PROCESS.test(t) || NODE.test(t) || /^[.^$*+?()|\\]+$/.test(t);
}

function killGuard(cmd: Cmd, all: Cmd[]): DetectorResult | null {
  const pos = positionals(cmd.args);
  switch (cmd.name) {
    case 'pkill':
    case 'killall': {
      const target = pos.find((w) => !w.dynamic && namesGuard(w.text));
      return target ? found('kill_guard', target.text) : null;
    }
    case 'stop-process':
    case 'spps': {
      const target = cmd.args.find((w) => !w.dynamic && !w.text.startsWith('-') && (GUARD_PROCESS.test(w.text.toLowerCase()) || NODE.test(w.text.toLowerCase())));
      return target ? found('kill_guard', target.text) : null;
    }
    case 'taskkill': {
      const target = cmd.args.find((w) => !w.dynamic && (GUARD_PROCESS.test(w.text.toLowerCase()) || NODE.test(w.text.toLowerCase())));
      return target ? found('kill_guard', target.text) : null;
    }
    case 'kill': {
      // `kill -9 -1` / `kill -- -1`: every process the user owns. (`kill -1 <pid>` is SIGHUP.)
      if (cmd.args.length > 1 && cmd.args[cmd.args.length - 1].text === '-1') return found('kill_guard', '-1');
      if (!cmd.args.some((w) => w.dynamic)) return null;
      // `kill $(pgrep -f mcp-guard)`: the substitution is read as its own command.
      const finder = all.find((c) => (c.name === 'pgrep' || c.name === 'pidof') && positionals(c.args).some((w) => !w.dynamic && namesGuard(w.text)));
      return finder ? found('kill_guard', positionals(finder.args).find((w) => namesGuard(w.text))!.text) : null;
    }
    default:
      return null;
  }
}

/** `mcp-guard keys init|rotate|revoke`, `mcp-guard init`, also through npx / bunx / pnpm dlx. */
function guardCli(cmd: Cmd): DetectorResult | null {
  let words = cmd.args.map((w) => w.text.toLowerCase());
  let name = cmd.name;
  if (name === 'npx' || name === 'bunx' || ((name === 'pnpm' || name === 'yarn') && words[0] === 'dlx')) {
    if (name === 'pnpm' || name === 'yarn') words = words.slice(1);
    const at = words.findIndex((w) => !w.startsWith('-'));
    if (at < 0) return null;
    name = words[at].replace(/@[^/@]*$/, '').split('/').pop() ?? '';
    words = words.slice(at + 1);
  }
  if (name !== 'mcp-guard') return null;
  const pos = words.filter((w) => !w.startsWith('-'));
  if (pos[0] === 'keys' && ['init', 'rotate', 'revoke'].includes(pos[1] ?? '')) return found('guard_cli', `keys ${pos[1]}`);
  if (pos[0] === 'init') return found('guard_cli', 'init');
  return null;
}

function check(cmd: Cmd, all: Cmd[]): DetectorResult | null {
  // A bare path (a file-tool argument, not a command).
  if (all.length === 1 && cmd.args.length === 0 && !cmd.redirects.length) {
    const kind = guardPathKind({ text: cmd.path, home: cmd.path.startsWith('~'), glob: false });
    if (kind) return found(kind, cmd.path);
  }
  const viaRedirect = writeRedirect(cmd);
  if (viaRedirect) return viaRedirect;
  const name = cmd.name;
  if (MODIFY_ALL.has(name)) return hit(operands(cmd.args));
  if (name === 'mv') return hit(operands(cmd.args)) ?? hit(destinations(cmd));
  if (COPY_TO.has(name)) {
    // `ln -s target link`: only the link is written.
    return hit(destinations(cmd));
  }
  if (name === 'dd') {
    const of = cmd.args.find((w) => w.text.startsWith('of='));
    return of ? hit([word(of.text.slice(3), of)]) : null;
  }
  if (inPlace(cmd)) return hit(operands(cmd.args));
  if (name === 'find') {
    const destructive = cmd.args.some((w) => w.text === '-delete') || cmd.args.some((w, i) => (w.text === '-exec' || w.text === '-execdir') && /^(rm|shred|unlink|mv|truncate|chmod|sed)$/.test((cmd.args[i + 1]?.text ?? '').split('/').pop() ?? ''));
    if (!destructive) return null;
    const roots: Word[] = [];
    for (const w of cmd.args) {
      if (w.text.startsWith('-') || w.text === '(' || w.text === '!') break;
      roots.push(w);
    }
    return hit(roots);
  }
  if (name === 'git') {
    const pos = positionals(cmd.args);
    if (['rm', 'mv', 'restore', 'checkout'].includes(pos[0]?.text ?? '')) return hit(pos.slice(1));
    return null;
  }
  return killGuard(cmd, all) ?? guardCli(cmd);
}

/**
 * A file-tool path read as a path, before the shell reader (which would take `\\` in
 * `C:\\Users\\x\\.claude.json` as escapes and split `Application Support`): text with no
 * shell syntax that is one token, or an absolute path with spaces inside segments.
 */
function rawPath(text: string): DetectorResult | null {
  const t = text.trim();
  if (!t || /[;&|<>$`'"\n]/.test(t)) return null;
  // Whitespace only inside a segment of an absolute path (`Application Support`), never
  // before something that looks like another argument (`-x`, `~/`, `/`, `.`).
  if (/\s/.test(t) && !(/^([a-zA-Z]:\\|\/|~\/)/.test(t) && !/\s[-~/.\s]|\s\/|\/\s/.test(t))) return null;
  const kind = guardPathKind({ text: t, home: t.startsWith('~'), glob: false });
  return kind ? found(kind, t) : null;
}

export function guardTamper(text: string): DetectorResult {
  return rawPath(text) ?? overShell(text, check);
}
