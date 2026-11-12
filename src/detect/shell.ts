/**
 * A small POSIX-shell reader for detectors. It is not a shell: it reads enough of the
 * grammar (quoting, expansions, substitutions, operators, redirections, heredocs) to list
 * the simple commands a line would run, unwraps common wrappers (sudo, env, bash -c, ssh,
 * xargs, ...), and reports a fixed reason when it cannot tell what would run.
 *
 * Fail-safe contract: whenever the reader cannot be confident about which command runs
 * or what an interpreter is fed, it sets `problem`. Detectors treat a problem as a match.
 *
 * Pure. No I/O.
 */
import { MAX_DETECT_INPUT, type UnparseableReason } from './types.js';

/** A placeholder for text whose value is not known (an expansion). */
export const DYN = '\u0000';

export interface Word {
  /** Quote-removed text. Unknown expansions appear as DYN. */
  text: string;
  /** Contains an expansion whose value is unknown. */
  dynamic: boolean;
  /** Variable names referenced. */
  vars: string[];
  /** Starts with an unquoted `~` or with `$HOME`. */
  home: boolean;
  /** Contains an unquoted glob character. */
  glob: boolean;
  /** Some part was quoted or escaped. */
  quoted: boolean;
}

export interface Redirect {
  op: string;
  target: Word | null;
}

interface RawCommand {
  words: Word[];
  redirects: Redirect[];
  pipedIn: boolean;
  stdinText: boolean;
  heredocBodies: string[];
}

export interface Cmd {
  /** Lower-cased basename of the program. */
  name: string;
  /** The program word as written (quote-removed). */
  path: string;
  args: Word[];
  /** `NAME=value` words that prefixed the command. */
  assigns: Word[];
  redirects: Redirect[];
  pipedIn: boolean;
  stdinText: boolean;
  heredocBodies: string[];
  /** Arguments are also fed from stdin by xargs. */
  viaXargs: boolean;
  /** An earlier `cd` left the working tree, so relative paths are not inside it. */
  cwdUnknown: boolean;
  /** The command whose output this one reads through a pipe, when known. */
  upstream?: Cmd;
}

export interface ShellAnalysis {
  cmds: Cmd[];
  problem?: UnparseableReason;
}

const MAX_DEPTH = 6;

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

interface ParseResult {
  commands: RawCommand[];
  problem?: UnparseableReason;
}

function newCommand(pipedIn: boolean): RawCommand {
  return { words: [], redirects: [], pipedIn, stdinText: false, heredocBodies: [] };
}

function newWord(): Word {
  return { text: '', dynamic: false, vars: [], home: false, glob: false, quoted: false };
}

class Lexer {
  private i = 0;
  problem?: UnparseableReason;
  readonly commands: RawCommand[] = [];
  private cur: RawCommand = newCommand(false);
  private word: Word | null = null;
  private pendingRedirect: string | null = null;
  private heredocs: Array<{ delim: string; strip: boolean; cmd: RawCommand }> = [];

  constructor(private readonly s: string, private readonly depth: number) {}

  private fail(reason: UnparseableReason): void {
    if (!this.problem) this.problem = reason;
  }

  private start(): Word {
    if (!this.word) this.word = newWord();
    return this.word;
  }

  private endWord(): void {
    const w = this.word;
    this.word = null;
    if (!w) return;
    if (this.pendingRedirect) {
      const op = this.pendingRedirect;
      this.pendingRedirect = null;
      if (op === '<<' || op === '<<-') {
        this.heredocs.push({ delim: w.text, strip: op === '<<-', cmd: this.cur });
        this.cur.stdinText = true;
        return;
      }
      if (op === '<<<') this.cur.stdinText = true;
      this.cur.redirects.push({ op, target: w });
      return;
    }
    this.cur.words.push(w);
  }

  private endCommand(pipeNext: boolean): void {
    this.endWord();
    this.pendingRedirect = null;
    if (this.cur.words.length || this.cur.redirects.length || this.cur.stdinText) this.commands.push(this.cur);
    this.cur = newCommand(pipeNext);
  }

  private sub(inner: string): void {
    if (this.depth + 1 > MAX_DEPTH) { this.fail('nesting_too_deep'); return; }
    const r = parseShell(inner, this.depth + 1);
    this.commands.push(...r.commands);
    if (r.problem) this.fail(r.problem);
  }

  private markDynamic(w: Word, name?: string): void {
    w.dynamic = true;
    w.text += DYN;
    if (name) w.vars.push(name);
  }

  private readHeredocBodies(i: number): number {
    const s = this.s;
    for (const h of this.heredocs) {
      let body = '';
      for (;;) {
        if (i >= s.length) break;
        const nl = s.indexOf('\n', i);
        const end = nl < 0 ? s.length : nl;
        const line = s.slice(i, end);
        i = end + 1;
        if ((h.strip ? line.replace(/^\t+/, '') : line) === h.delim) break;
        body += line + '\n';
      }
      h.cmd.heredocBodies.push(body);
    }
    this.heredocs = [];
    return Math.min(i, s.length);
  }

  /** `$...` at i. Returns the index after it. */
  private readDollar(i: number, inDouble: boolean): number {
    const s = this.s;
    const w = this.start();
    const next = s[i + 1];
    if (next === "'" && !inDouble) { this.fail('ansi_c_quote'); return s.length; }
    if (next === '"' && !inDouble) return this.readDouble(i + 2);
    if (next === '(') {
      const close = findClose(s, i + 1, '(', ')');
      if (close < 0) { this.fail('unterminated_substitution'); return s.length; }
      if (s[i + 2] === '(') {
        // Arithmetic. A substitution inside it is not followed.
        const inner = s.slice(i + 3, close);
        if (inner.includes('$(') || inner.includes('`')) this.fail('dynamic_argument');
        this.markDynamic(w);
        return close + 1;
      }
      this.sub(s.slice(i + 2, close));
      this.markDynamic(w);
      return close + 1;
    }
    if (next === '{') {
      const close = findClose(s, i + 1, '{', '}');
      if (close < 0) { this.fail('unterminated_substitution'); return s.length; }
      const inner = s.slice(i + 2, close);
      if (inner.includes('$(') || inner.includes('`')) this.fail('dynamic_argument');
      const name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(inner)?.[0];
      this.variable(w, name, name !== undefined && inner === name);
      return close + 1;
    }
    if (next !== undefined && /[A-Za-z_]/.test(next)) {
      const name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(s.slice(i + 1))![0];
      this.variable(w, name, true);
      return i + 1 + name.length;
    }
    if (next !== undefined && /[0-9@*#?$!-]/.test(next)) {
      this.markDynamic(w);
      return i + 2;
    }
    w.text += '$';
    return i + 1;
  }

  private variable(w: Word, name: string | undefined, plain: boolean): void {
    const atStart = w.text === '' && !w.dynamic;
    if (plain && atStart && name === 'HOME') { w.home = true; w.text += '~'; return; }
    if (plain && atStart && name === 'PWD') { w.text += '.'; return; }
    this.markDynamic(w, name);
  }

  private readDouble(i: number): number {
    const s = this.s;
    const w = this.start();
    w.quoted = true;
    while (i < s.length) {
      const c = s[i];
      if (c === '"') return i + 1;
      if (c === '\\') {
        const n = s[i + 1];
        if (n === '\n') { i += 2; continue; }
        if (n !== undefined && '$`"\\'.includes(n)) { w.text += n; i += 2; continue; }
        w.text += '\\';
        i += 1;
        continue;
      }
      if (c === '$') { i = this.readDollar(i, true); continue; }
      if (c === '`') { i = this.readBacktick(i); continue; }
      w.text += c;
      i += 1;
    }
    this.fail('unbalanced_quote');
    return s.length;
  }

  private readBacktick(i: number): number {
    const s = this.s;
    const w = this.start();
    let j = i + 1;
    let inner = '';
    while (j < s.length && s[j] !== '`') {
      if (s[j] === '\\' && j + 1 < s.length) { inner += s[j + 1] === '`' ? '`' : s[j] + s[j + 1]; j += 2; continue; }
      inner += s[j];
      j += 1;
    }
    if (j >= s.length) { this.fail('unterminated_substitution'); return s.length; }
    this.sub(inner);
    this.markDynamic(w);
    return j + 1;
  }

  run(): ParseResult {
    const s = this.s;
    const n = s.length;
    let i = 0;
    while (i < n && !this.problem) {
      const c = s[i];
      if (c === '\\') {
        if (s[i + 1] === '\n') { i += 2; continue; }
        const w = this.start();
        w.quoted = true;
        if (i + 1 < n) w.text += s[i + 1];
        i += 2;
        continue;
      }
      if (c === "'") {
        const w = this.start();
        w.quoted = true;
        const j = s.indexOf("'", i + 1);
        if (j < 0) { this.fail('unbalanced_quote'); break; }
        w.text += s.slice(i + 1, j);
        i = j + 1;
        continue;
      }
      if (c === '"') { this.start(); i = this.readDouble(i + 1); continue; }
      if (c === '`') { i = this.readBacktick(i); continue; }
      if (c === '$') { i = this.readDollar(i, false); continue; }
      if (c === ' ' || c === '\t' || c === '\r') { this.endWord(); i += 1; continue; }
      if (c === '\n') { this.endCommand(false); i = this.readHeredocBodies(i + 1); continue; }
      if (c === '#' && this.word === null) {
        const nl = s.indexOf('\n', i);
        i = nl < 0 ? n : nl;
        continue;
      }
      if (c === ';') {
        this.endCommand(false);
        i += 1;
        while (s[i] === ';' || s[i] === '&') i += 1;
        continue;
      }
      if (c === '&') {
        if (s[i + 1] === '>') {
          this.endWord();
          const op = s[i + 2] === '>' ? '&>>' : '&>';
          this.pendingRedirect = op;
          i += op.length;
          continue;
        }
        this.endCommand(false);
        i += s[i + 1] === '&' ? 2 : 1;
        continue;
      }
      if (c === '|') {
        if (s[i + 1] === '|') { this.endCommand(false); i += 2; continue; }
        this.endCommand(true);
        i += s[i + 1] === '&' ? 2 : 1;
        continue;
      }
      if (c === '(' || c === ')') { this.endCommand(false); i += 1; continue; }
      if (c === '<' || c === '>') {
        if (s[i + 1] === '(') {
          // Process substitution: runs a command, yields an unknown path.
          const close = findClose(s, i + 1, '(', ')');
          if (close < 0) { this.fail('unterminated_substitution'); break; }
          const w = this.start();
          this.sub(s.slice(i + 2, close));
          this.markDynamic(w);
          i = close + 1;
          continue;
        }
        if (this.word && /^\d+$/.test(this.word.text) && !this.word.quoted && !this.word.dynamic) this.word = null;
        else this.endWord();
        let op: string;
        if (c === '<') {
          op = s.startsWith('<<<', i) ? '<<<' : s.startsWith('<<-', i) ? '<<-' : s.startsWith('<<', i) ? '<<' : s.startsWith('<>', i) ? '<>' : s.startsWith('<&', i) ? '<&' : '<';
        } else {
          op = s.startsWith('>>', i) ? '>>' : s.startsWith('>&', i) ? '>&' : s.startsWith('>|', i) ? '>|' : '>';
        }
        this.pendingRedirect = op;
        i += op.length;
        continue;
      }
      const w = this.start();
      if (c === '~' && w.text === '' && !w.dynamic && !w.quoted) w.home = true;
      if (c === '*' || c === '?' || c === '[') w.glob = true;
      w.text += c;
      i += 1;
    }
    this.endCommand(false);
    return { commands: this.commands, ...(this.problem ? { problem: this.problem } : {}) };
  }
}

/** Index of the bracket closing the one at `open`, honouring quotes and nesting; -1 if none. */
function findClose(s: string, open: number, o: string, c: string): number {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    const ch = s[i];
    if (ch === '\\') { i += 1; continue; }
    if (ch === "'") {
      const j = s.indexOf("'", i + 1);
      if (j < 0) return -1;
      i = j;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') j += s[j] === '\\' ? 2 : 1;
      if (j >= s.length) return -1;
      i = j;
      continue;
    }
    if (ch === o) depth += 1;
    else if (ch === c) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function parseShell(text: string, depth: number): ParseResult {
  return new Lexer(text, depth).run();
}

// ---------------------------------------------------------------------------
// Normalizer: unwrap wrappers, follow `sh -c`, flag opaque interpreters
// ---------------------------------------------------------------------------

const RESERVED = new Set(['!', '{', '}', 'if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'while', 'until', 'time', 'esac', 'coproc']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'mksh', 'ash', 'fish', 'csh', 'tcsh', 'rbash', 'yash']);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;

/** How an interpreter (not a shell) is given code inline. */
const INLINE_CODE: Array<[RegExp, (opt: string) => boolean]> = [
  [/^(python|pypy)(\d+(\.\d+)*)?$/, (o) => /^-[A-Za-z]*c/.test(o)],
  [/^(node|nodejs|bun)$/, (o) => /^-[A-Za-z]*[ep]/.test(o) || o === '--eval' || o === '--print' || o.startsWith('--eval=') || o.startsWith('--print=')],
  [/^perl\d*$/, (o) => /^-[A-Za-z]*[eE]/.test(o)],
  [/^ruby\d*(\.\d+)*$/, (o) => /^-[A-Za-z]*e/.test(o)],
  [/^php\d*(\.\d+)*$/, (o) => /^-[A-Za-z]*[rR]/.test(o)],
  [/^(lua|luajit|lua\d+(\.\d+)?)$/, (o) => o === '-e'],
  [/^osascript$/, (o) => o === '-e'],
  [/^rscript$/, (o) => o === '-e'],
  [/^(pwsh|powershell|powershell\.exe|pwsh\.exe)$/, (o) => /^-(c|command|e|ec|encodedcommand)$/i.test(o)],
  [/^deno$/, (o) => o === 'eval'],
  [/^(awk|gawk|mawk|nawk)$/, () => false],
];

function interpreterRule(name: string): ((opt: string) => boolean) | null {
  for (const [re, fn] of INLINE_CODE) if (re.test(name)) return fn;
  return null;
}

function basename(p: string): string {
  const parts = p.split('/');
  return parts[parts.length - 1] ?? p;
}

/**
 * Index of the first operand after options. `withArg` lists short options that take a
 * value; `longWithArg` lists long ones. `--` ends options.
 */
function skipOptions(words: Word[], withArg: string, longWithArg: string[] = []): number {
  let i = 0;
  while (i < words.length) {
    const t = words[i].text;
    if (t === '--') return i + 1;
    if (!t.startsWith('-') || t === '-') return i;
    if (t.startsWith('--')) {
      i += !t.includes('=') && longWithArg.includes(t) ? 2 : 1;
      continue;
    }
    let consumesNext = false;
    for (let k = 1; k < t.length; k++) {
      if (withArg.includes(t[k])) { consumesNext = k === t.length - 1; break; }
    }
    i += consumesNext ? 2 : 1;
  }
  return i;
}

interface NormState {
  out: Cmd[];
  problem?: UnparseableReason;
}

function fail(st: NormState, r: UnparseableReason): void {
  if (!st.problem) st.problem = r;
}

function analyzeInto(text: string, depth: number, st: NormState): void {
  if (depth > MAX_DEPTH) { fail(st, 'nesting_too_deep'); return; }
  const parsed = parseShell(text, depth);
  if (parsed.problem) fail(st, parsed.problem);
  for (const raw of parsed.commands) normalize(raw, depth, st);
}

function normalize(raw: RawCommand, depth: number, st: NormState): void {
  let words = raw.words.slice();
  const assigns: Word[] = [];
  let viaXargs = false;
  const pipedIn = raw.pipedIn;
  const stdinText = raw.stdinText;
  const feedsStdin = pipedIn || stdinText;

  for (let guard = 0; guard < 16; guard++) {
    while (words.length && ((ASSIGNMENT.test(words[0].text) && !words[0].text.startsWith(DYN)) || (RESERVED.has(words[0].text) && !words[0].quoted))) {
      const w = words.shift()!;
      if (ASSIGNMENT.test(w.text)) assigns.push(w);
    }
    if (!words.length) {
      if (raw.redirects.length) st.out.push(mk('', '', [], assigns, raw, false));
      return;
    }
    const w0 = words[0];
    if (w0.dynamic) { fail(st, 'dynamic_command'); return; }
    if (w0.glob && w0.text !== '[' && w0.text !== '[[') { fail(st, 'glob_command'); return; }
    const name = basename(w0.text).toLowerCase();
    const rest = words.slice(1);

    switch (name) {
      case 'sudo': words = rest.slice(skipOptions(rest, 'ugCDhpRrtTU', ['--user', '--group', '--chdir', '--host', '--prompt', '--role', '--type', '--other-user', '--close-from'])); continue;
      case 'doas': words = rest.slice(skipOptions(rest, 'uC')); continue;
      case 'nohup': case 'builtin': case 'unbuffer': case 'busybox': case 'then': words = rest; continue;
      case 'caffeinate': words = rest.slice(skipOptions(rest, 'tw')); continue;
      case 'exec': words = rest.slice(skipOptions(rest, 'a')); continue;
      case 'nice': words = rest.slice(skipOptions(rest, 'n', ['--adjustment'])); continue;
      case 'ionice': words = rest.slice(skipOptions(rest, 'cnpPu')); continue;
      case 'stdbuf': words = rest.slice(skipOptions(rest, 'ioe', ['--input', '--output', '--error'])); continue;
      case 'chrt': case 'taskset': {
        const k = skipOptions(rest, '');
        words = rest.slice(k + 1);
        continue;
      }
      case 'timeout': {
        const k = skipOptions(rest, 'sk', ['--signal', '--kill-after']);
        words = rest.slice(k + 1);
        continue;
      }
      case 'command': {
        if (rest.some((w) => w.text === '-v' || w.text === '-V')) return;
        words = rest.slice(skipOptions(rest, ''));
        continue;
      }
      case 'env': {
        if (rest.some((w) => w.text === '-S' || w.text.startsWith('--split-string') || /^-[A-Za-z]*S/.test(w.text))) { fail(st, 'inline_code'); return; }
        let k = skipOptions(rest, 'uC', ['--unset', '--chdir']);
        while (k < rest.length && ASSIGNMENT.test(rest[k].text)) assigns.push(rest[k++]);
        if (k >= rest.length) { st.out.push(mk('env', w0.text, rest, assigns, raw, viaXargs)); return; }
        words = rest.slice(k);
        continue;
      }
      case 'xargs': {
        const k = skipOptions(rest, 'IadEeLlnPs', ['--arg-file', '--delimiter', '--eof', '--max-lines', '--max-args', '--max-procs', '--max-chars', '--replace']);
        viaXargs = true;
        words = k < rest.length ? rest.slice(k) : [{ ...newWord(), text: 'echo' }];
        continue;
      }
      case 'watch': {
        const k = skipOptions(rest, 'nq', ['--interval']);
        const cmd = rest.slice(k);
        if (cmd.some((w) => w.dynamic)) { fail(st, 'dynamic_argument'); return; }
        analyzeInto(cmd.map((w) => w.text).join(' '), depth + 1, st);
        return;
      }
      case 'flock': {
        const c = rest.findIndex((w) => w.text === '-c' || w.text === '--command');
        if (c >= 0) { followScript(rest[c + 1], depth, st); return; }
        const k = skipOptions(rest, 'wEn', ['--timeout', '--conflict-exit-code']);
        words = rest.slice(k + 1);
        continue;
      }
      case 'su': case 'runuser': {
        const c = rest.findIndex((w) => w.text === '-c' || w.text === '--command' || w.text.startsWith('--command='));
        if (c >= 0) {
          const t = rest[c].text;
          followScript(t.startsWith('--command=') ? { ...rest[c], text: t.slice('--command='.length) } : rest[c + 1], depth, st);
          return;
        }
        const dd = rest.findIndex((w) => w.text === '--');
        if (name === 'runuser' && dd >= 0) { words = rest.slice(dd + 1); continue; }
        return;
      }
      case 'ssh': {
        const k = skipOptions(rest, 'BbcDEeFIiJLlmOopQRSWw');
        const cmd = rest.slice(k + 1);
        if (!cmd.length) return;
        if (cmd.some((w) => w.dynamic)) { fail(st, 'dynamic_argument'); return; }
        analyzeInto(cmd.map((w) => w.text).join(' '), depth + 1, st);
        return;
      }
      case 'eval': fail(st, 'eval'); return;
      case 'source': case '.': {
        const target = rest[0];
        if (!target) return;
        if (target.dynamic) { fail(st, 'dynamic_argument'); return; }
        if ((target.text === '/dev/stdin' || target.text === '-') && feedsStdin) { fail(st, 'interpreter_stdin'); return; }
        return;
      }
      case 'alias': {
        for (const w of rest) {
          const eq = w.text.indexOf('=');
          if (eq < 0) continue;
          if (w.dynamic) { fail(st, 'dynamic_argument'); continue; }
          analyzeInto(w.text.slice(eq + 1), depth + 1, st);
        }
        return;
      }
      default:
        break;
    }

    if (SHELLS.has(name)) {
      let k = 0;
      let inline = false;
      for (; k < rest.length; k++) {
        const t = rest[k].text;
        if (t === '--' || t === '-') { k += 1; break; }
        if (rest[k].dynamic) break;
        if (t === '--rcfile' || t === '--init-file' || t === '-o' || t === '+o' || t === '-O' || t === '+O') { k += 1; continue; }
        if (t.startsWith('--')) continue;
        if (/^[-+][A-Za-z]+$/.test(t)) { if (t.startsWith('-') && t.includes('c')) inline = true; continue; }
        break;
      }
      const script = rest[k];
      if (inline) { followScript(script, depth, st); return; }
      if (script) {
        if (script.dynamic) { fail(st, 'dynamic_argument'); return; }
        if ((script.text === '/dev/stdin' || script.text === '-s') && feedsStdin) { fail(st, 'interpreter_stdin'); return; }
        return; // a script file: not inspected
      }
      if (feedsStdin) fail(st, 'interpreter_stdin');
      return;
    }

    const inlineRule = interpreterRule(name);
    if (inlineRule) {
      if (/^(awk|gawk|mawk|nawk)$/.test(name)) { st.out.push(mk(name, w0.text, rest, assigns, raw, viaXargs)); return; }
      let k = 0;
      for (; k < rest.length; k++) {
        const t = rest[k].text;
        if (inlineRule(t)) { fail(st, 'inline_code'); return; }
        if (t === '-m') return; // a module: not inspected
        if (!t.startsWith('-') || t === '-') break;
      }
      // pwsh treats a bare first operand as a command.
      if (/^(pwsh|powershell)/.test(name) && rest[k] && !/\.ps1$/i.test(rest[k].text)) { fail(st, 'inline_code'); return; }
      const script = rest[k];
      if (script) {
        if (script.dynamic) { fail(st, 'dynamic_argument'); return; }
        if ((script.text === '-' || script.text === '/dev/stdin') && feedsStdin) { fail(st, 'interpreter_stdin'); return; }
        return;
      }
      if (feedsStdin) fail(st, 'interpreter_stdin');
      return;
    }

    if (name === 'microk8s' && rest[0]?.text === 'kubectl') { words = rest; continue; }

    st.out.push(mk(name, w0.text, rest, assigns, raw, viaXargs));
    return;
  }
  fail(st, 'nesting_too_deep');
}

function followScript(script: Word | undefined, depth: number, st: NormState): void {
  if (!script) return;
  if (script.dynamic) { fail(st, 'dynamic_argument'); return; }
  analyzeInto(script.text, depth + 1, st);
}

function mk(name: string, path: string, args: Word[], assigns: Word[], raw: RawCommand, viaXargs: boolean): Cmd {
  return {
    name,
    path,
    args,
    assigns,
    redirects: raw.redirects,
    pipedIn: raw.pipedIn,
    stdinText: raw.stdinText,
    heredocBodies: raw.heredocBodies,
    viaXargs,
    cwdUnknown: false,
  };
}

/** Read shell text into the simple commands it would run. */
export function analyzeShell(text: string): ShellAnalysis {
  if (text.length > MAX_DETECT_INPUT) return { cmds: [], problem: 'too_long' };
  const st: NormState = { out: [] };
  analyzeInto(text, 0, st);
  // A `cd` that leaves the tree makes later relative paths unknown.
  let away = false;
  st.out.forEach((c, i) => {
    if (c.pipedIn && i > 0) c.upstream = st.out[i - 1];
  });
  for (const c of st.out) {
    c.cwdUnknown = away;
    if (c.name === 'cd' || c.name === 'pushd') {
      const target = c.args.find((w) => !w.text.startsWith('-') || w.text === '-');
      if (!target || target.text === '-') away = true;
      else {
        const cls = classifyPath(target, away).cls;
        if (cls !== 'inside') away = true;
      }
    }
  }
  return { cmds: st.out, ...(st.problem ? { problem: st.problem } : {}) };
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

export type PathClass =
  | 'inside'       // a path inside the working tree
  | 'tree_root'    // the working tree itself (., *, ./)
  | 'vcs'          // the repository's .git directory
  | 'parent'       // escapes the tree with ..
  | 'outside_cwd'  // relative, after a cd that left the tree
  | 'temp'         // a named entry under /tmp or /var/tmp
  | 'absolute'
  | 'root'
  | 'home'
  | 'dynamic';     // depends on an unknown value

/** Classify where a path points. `depth` is the number of segments below root or home. */
export function classifyPath(w: Word, cwdUnknown: boolean): { cls: PathClass; depth: number } {
  const t = w.text;
  if (w.home) {
    const segs = t.replace(/^~[^/]*/, '').split('/').filter((x) => x && x !== '.');
    if (segs.some((x) => x.includes(DYN) || x === '..')) return { cls: 'home', depth: 0 };
    return { cls: 'home', depth: segs.length };
  }
  if (t.startsWith(DYN)) return { cls: 'dynamic', depth: 0 };
  if (t.startsWith('/')) {
    const segs: string[] = [];
    for (const seg of t.split('/')) {
      if (!seg || seg === '.') continue;
      if (seg === '..') { segs.pop(); continue; }
      segs.push(seg);
    }
    if (!segs.length || (segs.length === 1 && /^[*?]+$/.test(segs[0]))) return { cls: 'root', depth: 0 };
    const tmp = segs[0] === 'tmp' ? 1 : segs[0] === 'var' && segs[1] === 'tmp' ? 2 : 0;
    if (tmp && segs.length > tmp) {
      const named = segs[tmp];
      if (named.includes(DYN)) return { cls: 'dynamic', depth: segs.length };
      if (!/[*?[]/.test(named) && !t.includes('..')) return { cls: 'temp', depth: segs.length };
    }
    return { cls: 'absolute', depth: segs.length };
  }
  if (cwdUnknown) return { cls: 'outside_cwd', depth: 0 };
  const segs: string[] = [];
  for (const seg of t.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg.includes(DYN)) return { cls: 'dynamic', depth: 0 };
    if (seg === '..') {
      if (!segs.length) return { cls: 'parent', depth: 0 };
      segs.pop();
      continue;
    }
    segs.push(seg);
  }
  if (!segs.length) return { cls: 'tree_root', depth: 0 };
  if (/^\.\*/.test(segs[0])) return { cls: 'parent', depth: 0 }; // `.*` can match `..`
  if (/^[*?]+$/.test(segs[0]) && segs.length === 1) return { cls: 'tree_root', depth: 0 };
  if (segs[0] === '.git') return { cls: 'vcs', depth: segs.length };
  return { cls: 'inside', depth: segs.length };
}

/** Operands (non-option words) of a command, honouring `--`. */
export function operands(args: Word[]): Word[] {
  const out: Word[] = [];
  let opts = true;
  for (const w of args) {
    if (opts && w.text === '--') { opts = false; continue; }
    if (opts && w.text.startsWith('-') && w.text !== '-') continue;
    out.push(w);
  }
  return out;
}

/** Lower-cased static positional words (dynamic ones kept with DYN). */
export function positionals(args: Word[]): Word[] {
  return args.filter((w) => !w.text.startsWith('-'));
}

export function hasFlag(args: Word[], ...flags: string[]): boolean {
  return args.some((w) => flags.includes(w.text) || flags.some((f) => f.startsWith('--') && w.text.startsWith(f + '=')));
}

/** A short-option cluster (like -rf) that contains the letter. */
export function hasShort(args: Word[], letter: string): boolean {
  return args.some((w) => /^-[A-Za-z]+$/.test(w.text) && w.text.slice(1).includes(letter));
}
