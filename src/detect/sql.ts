/**
 * sql_destructive: DROP, TRUNCATE, DELETE or UPDATE without a (real) WHERE, ALTER ... DROP,
 * MERGE ... DELETE, and COPY ... PROGRAM.
 *
 * Dialects disagree on comments and string escapes. Where they do, the reader takes the
 * reading that exposes more statements: `#` is not a comment, `--` is a comment only when
 * followed by whitespace, block comments do not nest, MySQL `/*! ... *\/` bodies are read
 * as code, and the text is read twice, with and without backslash escapes in strings.
 *
 * Pure. No I/O.
 */
import { found, MAX_DETECT_INPUT, NOT_MATCHED, unparseable, type DetectorResult, type UnparseableReason } from './types.js';

/** Every kind a definite sql_destructive finding can have. */
export const SQL_DESTRUCTIVE_KINDS = [
  'drop_database', 'drop_schema', 'drop_table', 'drop_object', 'truncate', 'delete_without_where', 'update_without_where',
  'alter_drop', 'merge_delete', 'copy_program',
] as const;

type TokType = 'word' | 'ident' | 'str' | 'num' | 'punct' | 'param';
interface Tok { t: TokType; v: string }

class SqlError extends Error {
  constructor(readonly reason: UnparseableReason) { super(reason); }
}

const MAX_DEPTH = 6;

function tokenize(s: string, backslash: boolean): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  let execComment = 0;
  const n = s.length;
  while (i < n) {
    const c = s[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '-' && s[i + 1] === '-' && (i + 2 >= n || /\s/.test(s[i + 2]))) {
      const nl = s.indexOf('\n', i);
      i = nl < 0 ? n : nl + 1;
      continue;
    }
    if (c === '/' && s[i + 1] === '*') {
      if (s[i + 2] === '!') {
        i += 3;
        while (i < n && /[0-9]/.test(s[i])) i++;
        execComment++;
        continue;
      }
      const end = s.indexOf('*/', i + 2);
      if (end < 0) throw new SqlError('unterminated_comment');
      i = end + 2;
      continue;
    }
    if (c === '*' && s[i + 1] === '/' && execComment > 0) { execComment--; i += 2; continue; }
    // String prefixes: E'..' (backslash escapes), N'..' (national).
    if ((c === 'E' || c === 'e' || c === 'N' || c === 'n') && s[i + 1] === "'" && !/[A-Za-z0-9_$]/.test(s[i - 1] ?? '')) {
      const r = readString(s, i + 1, backslash || c === 'E' || c === 'e');
      out.push({ t: 'str', v: r.value });
      i = r.end;
      continue;
    }
    if (c === "'") {
      const r = readString(s, i, backslash);
      out.push({ t: 'str', v: r.value });
      i = r.end;
      continue;
    }
    if (c === '"' || c === '`') {
      let j = i + 1;
      let v = '';
      for (;;) {
        if (j >= n) throw new SqlError('unbalanced_quote');
        if (s[j] === c) {
          if (s[j + 1] === c) { v += c; j += 2; continue; }
          break;
        }
        v += s[j++];
      }
      out.push({ t: 'ident', v });
      i = j + 1;
      continue;
    }
    if (c === '$') {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(s.slice(i));
      if (m) {
        const tag = m[0];
        const end = s.indexOf(tag, i + tag.length);
        if (end < 0) throw new SqlError('unbalanced_quote');
        out.push({ t: 'str', v: s.slice(i + tag.length, end) });
        i = end + tag.length;
        continue;
      }
      const p = /^\$\d+/.exec(s.slice(i));
      if (p) { out.push({ t: 'param', v: p[0] }); i += p[0].length; continue; }
    }
    if (/[A-Za-z_\u0080-￿]/.test(c)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_$\u0080-￿]/.test(s[j])) j++;
      out.push({ t: 'word', v: s.slice(i, j).toUpperCase() });
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i + 1;
      while (j < n && /[0-9.eE]/.test(s[j])) j++;
      out.push({ t: 'num', v: s.slice(i, j) });
      i = j;
      continue;
    }
    if ((c === '@' || c === ':') && /[A-Za-z_@]/.test(s[i + 1] ?? '')) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_@]/.test(s[j])) j++;
      out.push({ t: 'param', v: s.slice(i, j) });
      i = j;
      continue;
    }
    out.push({ t: 'punct', v: c });
    i++;
  }
  return out;
}

function readString(s: string, start: number, backslash: boolean): { value: string; end: number } {
  let j = start + 1;
  let v = '';
  for (;;) {
    if (j >= s.length) throw new SqlError('unbalanced_quote');
    const ch = s[j];
    if (backslash && ch === '\\' && j + 1 < s.length) { v += s[j + 1]; j += 2; continue; }
    if (ch === "'") {
      if (s[j + 1] === "'") { v += "'"; j += 2; continue; }
      return { value: v, end: j + 1 };
    }
    v += ch;
    j++;
  }
}

const isWord = (tok: Tok | undefined, ...vs: string[]): boolean => !!tok && tok.t === 'word' && (vs.length === 0 || vs.includes(tok.v));

/** Split into statements on `;` and MSSQL `GO` at paren depth 0. */
function statements(toks: Tok[]): Tok[][] {
  const out: Tok[][] = [];
  let cur: Tok[] = [];
  let depth = 0;
  for (const tok of toks) {
    if (tok.t === 'punct' && tok.v === '(') depth++;
    if (tok.t === 'punct' && tok.v === ')') depth = Math.max(0, depth - 1);
    if (depth === 0 && ((tok.t === 'punct' && tok.v === ';') || isWord(tok, 'GO'))) {
      if (cur.length) out.push(cur);
      cur = [];
      continue;
    }
    cur.push(tok);
  }
  if (cur.length) out.push(cur);
  return out;
}

/** Index of the paren closing the one at `open`, or the end. */
function closeParen(toks: Tok[], open: number): number {
  let depth = 0;
  for (let k = open; k < toks.length; k++) {
    if (toks[k].t === 'punct' && toks[k].v === '(') depth++;
    if (toks[k].t === 'punct' && toks[k].v === ')') { depth--; if (depth === 0) return k; }
  }
  return toks.length;
}

/** Tokens at paren depth 0 of `toks`, with their indices. */
function topLevel(toks: Tok[]): Array<[Tok, number]> {
  const out: Array<[Tok, number]> = [];
  let depth = 0;
  toks.forEach((tok, k) => {
    if (tok.t === 'punct' && tok.v === '(') { depth++; return; }
    if (tok.t === 'punct' && tok.v === ')') { depth--; return; }
    if (depth === 0) out.push([tok, k]);
  });
  return out;
}

function nameAt(toks: Tok[], k: number): string | undefined {
  const parts: string[] = [];
  while (k < toks.length) {
    const tok = toks[k];
    if (tok.t === 'word' || tok.t === 'ident') parts.push(tok.t === 'word' ? tok.v.toLowerCase() : tok.v);
    else if (tok.t === 'punct' && tok.v === '[') { k++; continue; }
    else if (tok.t === 'punct' && tok.v === ']') { k++; continue; }
    else break;
    k++;
    if (toks[k]?.t === 'punct' && toks[k].v === ']') k++;
    if (toks[k]?.t === 'punct' && toks[k].v === '.') { k++; continue; }
    break;
  }
  return parts.length ? parts.join('.') : undefined;
}

function skipWords(toks: Tok[], k: number, words: string[]): number {
  while (isWord(toks[k], ...words)) k++;
  return k;
}

const literal = (tok: Tok | undefined): string | null =>
  !tok ? null : tok.t === 'num' ? `n:${Number(tok.v)}` : tok.t === 'str' ? `s:${tok.v}` : tok.t === 'word' || tok.t === 'ident' ? `i:${tok.v.toLowerCase()}` : null;

/** A WHERE (or OR branch) that is always true: TRUE, a non-zero number, or X = X. */
function triviallyTrue(toks: Tok[], whereIdx: number): boolean {
  const top = topLevel(toks).filter(([, k]) => k > whereIdx);
  const starts = [whereIdx + 1, ...top.filter(([t]) => isWord(t, 'OR')).map(([, k]) => k + 1)];
  for (const k of starts) {
    let j = k;
    while (toks[j]?.t === 'punct' && toks[j].v === '(') j++;
    const x = toks[j];
    const end = (t: Tok | undefined): boolean => !t || isWord(t, 'OR', 'AND', 'RETURNING', 'ORDER', 'LIMIT') || (t.t === 'punct' && (t.v === ')' || t.v === ';'));
    if (isWord(x, 'TRUE') && end(toks[j + 1])) return true;
    if (x?.t === 'num' && Number(x.v) !== 0 && end(toks[j + 1])) return true;
    if (toks[j + 1]?.t === 'punct' && toks[j + 1].v === '=' && literal(x) !== null && literal(x) === literal(toks[j + 2])) return true;
  }
  return false;
}

interface Ctx {
  depth: number;
  prepared: Set<string>;
}

function analyzeStatement(toks: Tok[], ctx: Ctx): DetectorResult {
  // Destructive statements nested in parentheses (data-modifying CTEs, subqueries).
  for (let k = 0; k < toks.length; k++) {
    if (toks[k].t === 'punct' && toks[k].v === '(' && isWord(toks[k + 1], 'DELETE', 'UPDATE', 'DROP', 'TRUNCATE', 'ALTER', 'MERGE')) {
      const r = analyzeStatement(toks.slice(k + 1, closeParen(toks, k)), ctx);
      if (r.matched) return r;
    }
  }

  let k = skipWords(toks, 0, ['BEGIN', 'END', 'ELSE', 'LOOP', 'ATOMIC', 'DECLARE']);
  // EXPLAIN [ANALYZE] [(options)] runs the statement under ANALYZE: read the statement.
  if (isWord(toks[k], 'EXPLAIN')) {
    k++;
    if (toks[k]?.t === 'punct' && toks[k].v === '(') k = closeParen(toks, k) + 1;
    k = skipWords(toks, k, ['ANALYZE', 'ANALYSE', 'VERBOSE']);
  }
  // Control flow in procedural bodies: read what follows THEN / LOOP / ELSE.
  if (isWord(toks[k], 'IF', 'ELSIF', 'ELSEIF', 'WHILE', 'FOR', 'WHEN', 'CASE')) {
    const t = topLevel(toks).find(([tok, j]) => j > k && isWord(tok, 'THEN', 'LOOP', 'ELSE'));
    return t ? analyzeStatement(toks.slice(t[1] + 1), ctx) : NOT_MATCHED;
  }
  if (isWord(toks[k], 'WITH')) {
    const verb = topLevel(toks).find(([tok, j]) => j > k && isWord(tok, 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'VALUES', 'TABLE'));
    if (!verb) return NOT_MATCHED;
    k = verb[1];
  }
  const head = toks.slice(k);
  const verb = head[0];
  if (!isWord(verb)) return NOT_MATCHED;

  switch (verb.v) {
    case 'DROP': {
      let j = skipWords(head, 1, ['TEMPORARY', 'TEMP']);
      const what = head[j]?.t === 'word' ? head[j].v : '';
      const kind = what === 'DATABASE' ? 'drop_database' : what === 'SCHEMA' ? 'drop_schema' : what === 'TABLE' ? 'drop_table' : 'drop_object';
      j = skipWords(head, j + 1, ['IF', 'EXISTS', 'CONCURRENTLY']);
      return found(kind, nameAt(head, j));
    }
    case 'TRUNCATE':
      return found('truncate', nameAt(head, skipWords(head, 1, ['TABLE', 'ONLY'])));
    case 'DELETE':
    case 'UPDATE': {
      let j = skipWords(head, 1, ['LOW_PRIORITY', 'QUICK', 'IGNORE', 'FROM', 'ONLY']);
      if (verb.v === 'DELETE' && isWord(head[j], 'TOP')) j += 4;
      const target = nameAt(head, j);
      const where = topLevel(head).find(([tok]) => isWord(tok, 'WHERE'));
      if (!where || triviallyTrue(head, where[1])) return found(verb.v === 'DELETE' ? 'delete_without_where' : 'update_without_where', target);
      return NOT_MATCHED;
    }
    case 'ALTER': {
      const top = topLevel(head);
      for (const [tok, j] of top) {
        if (isWord(tok, 'DROP') && !isWord(head[j + 1], 'DEFAULT', 'NOT', 'IDENTITY', 'EXPRESSION')) {
          return found('alter_drop', nameAt(head, skipWords(head, 2, ['IF', 'EXISTS', 'ONLY'])));
        }
      }
      return NOT_MATCHED;
    }
    case 'MERGE':
      return topLevel(head).some(([tok]) => isWord(tok, 'DELETE')) ? found('merge_delete', nameAt(head, skipWords(head, 1, ['INTO']))) : NOT_MATCHED;
    case 'COPY':
      return topLevel(head).some(([tok]) => isWord(tok, 'PROGRAM')) ? found('copy_program') : NOT_MATCHED;
    case 'PREPARE': {
      const name = nameAt(head, 1);
      const as = topLevel(head).find(([tok]) => isWord(tok, 'AS'));
      const from = topLevel(head).find(([tok]) => isWord(tok, 'FROM'));
      let r: DetectorResult;
      if (as) r = analyzeStatement(head.slice(as[1] + 1), ctx);
      else if (from && head[from[1] + 1]?.t === 'str' && from[1] + 2 >= head.length) r = analyzeText(head[from[1] + 1].v, ctx);
      else return unparseable('dynamic_sql');
      if (!r.matched && name) ctx.prepared.add(name);
      return r;
    }
    case 'EXECUTE':
    case 'EXEC': {
      if (isWord(head[1], 'FUNCTION', 'PROCEDURE')) return NOT_MATCHED;
      let j = 1;
      if (isWord(head[j], 'SP_EXECUTESQL')) j++;
      if (isWord(head[j], 'IMMEDIATE')) j++;
      const name = nameAt(head, j);
      if (name && ctx.prepared.has(name)) return NOT_MATCHED;
      // Only literal strings (optionally parenthesized and concatenated) are readable.
      const body: string[] = [];
      for (; j < head.length; j++) {
        const tok = head[j];
        if (tok.t === 'str') { body.push(tok.v); continue; }
        if (tok.t === 'punct' && (tok.v === '(' || tok.v === ')' || tok.v === '+')) continue;
        if (tok.t === 'punct' && tok.v === ',' && body.length) break;
        if (isWord(tok, 'N')) continue;
        return unparseable('dynamic_sql');
      }
      return body.length ? analyzeText(body.join(''), ctx) : unparseable('dynamic_sql');
    }
    case 'DO': {
      const body = head.find((tok) => tok.t === 'str');
      return body ? analyzeText(body.v, ctx, true) : NOT_MATCHED;
    }
    case 'CREATE': {
      // A function or procedure body runs later, when called: read it now.
      if (topLevel(head).some(([tok]) => isWord(tok, 'FUNCTION', 'PROCEDURE', 'TRIGGER', 'RULE'))) {
        for (const tok of head) {
          if (tok.t !== 'str') continue;
          const r = analyzeText(tok.v, ctx, true);
          if (r.matched) return r;
        }
        // CREATE RULE ... DO [INSTEAD|ALSO] <statement>
        const doIdx = topLevel(head).find(([tok]) => isWord(tok, 'DO'));
        if (doIdx) return analyzeStatement(head.slice(skipWords(head, doIdx[1] + 1, ['INSTEAD', 'ALSO'])), ctx);
      }
      return NOT_MATCHED;
    }
    default:
      return NOT_MATCHED;
  }
}

function analyzeText(text: string, ctx: Ctx, body = false): DetectorResult {
  if (ctx.depth >= MAX_DEPTH) return unparseable('nesting_too_deep');
  const inner: Ctx = { depth: ctx.depth + 1, prepared: ctx.prepared };
  let uncertain: DetectorResult | null = null;
  for (const backslash of [false, true]) {
    let toks: Tok[];
    try {
      toks = tokenize(text, backslash);
    } catch (err) {
      if (err instanceof SqlError) { uncertain ??= unparseable(err.reason); continue; }
      throw err;
    }
    // Procedural bodies use EXECUTE on strings built at run time.
    if (body && toks.some((t, k) => isWord(t, 'EXECUTE') && !isWord(toks[k + 1], 'FUNCTION', 'PROCEDURE') && toks[k + 1]?.t !== 'str')) {
      uncertain ??= unparseable('dynamic_sql');
    }
    for (const stmt of statements(toks)) {
      const r = analyzeStatement(stmt, inner);
      if (r.matched && r.parsed) return r;
      if (r.matched) uncertain ??= r;
    }
  }
  return uncertain ?? NOT_MATCHED;
}

export function sqlDestructive(text: string): DetectorResult {
  if (text.length > MAX_DETECT_INPUT) return unparseable('too_long');
  return analyzeText(text, { depth: 0, prepared: new Set() });
}
