/**
 * shell_destructive: recursive rm outside the working tree, force pushes, pushes that
 * delete, mirror or push every branch, plain pushes to main/master, raw disk writes (dd, mkfs, shred, wipefs, redirects to block devices),
 * find -delete, recursive chmod/chown on broad paths, and destructive SQL sent through
 * psql / mysql / sqlite3.
 *
 * Pure. No I/O.
 */
import { overShell } from './combine.js';
import { classifyPath, hasFlag, hasShort, operands, positionals, DYN, type Cmd, type Word } from './shell.js';
import { SQL_DESTRUCTIVE_KINDS, sqlDestructive } from './sql.js';
import { found, NOT_MATCHED, unparseable, type DetectorResult, type KindFilter } from './types.js';

/**
 * Every kind a definite shell_destructive finding can have: its own, and the SQL kinds of
 * destructive SQL sent through a client (`psql -c`). A rule can narrow the detector to
 * some of them (`detect.kinds`) or leave some out (`detect.except_kinds`).
 */
export const SHELL_DESTRUCTIVE_KINDS = [
  'rm_recursive', 'rm_xargs', 'truncate_file', 'move_to_device', 'disk_write', 'overwrite_redirect', 'find_delete',
  'git_force_push', 'git_push_delete', 'git_push_mirror', 'git_push_all', 'git_push_protected',
  'recursive_permissions', 'disk_format', 'shred',
  ...SQL_DESTRUCTIVE_KINDS,
] as const;

const PROTECTED_BRANCHES = new Set(['main', 'master']);
const DISK_DEVICE = /^\/dev\/(sd|hd|vd|xvd|nvme|disk|rdisk|mmcblk|md|dm-|mapper\/|loop)/;

function rm(cmd: Cmd): DetectorResult | null {
  let recursive = false;
  let maybeRecursive = false;
  let noPreserveRoot = false;
  const targets: Word[] = [];
  let opts = true;
  for (const w of cmd.args) {
    if (opts && w.text === '--') { opts = false; continue; }
    if (opts && w.dynamic && !w.home && w.text.startsWith(DYN)) { maybeRecursive = true; targets.push(w); continue; }
    if (opts && w.text.startsWith('--')) {
      if (w.text === '--recursive') recursive = true;
      if (w.text === '--no-preserve-root') noPreserveRoot = true;
      continue;
    }
    if (opts && /^-[A-Za-z]+$/.test(w.text)) {
      if (/[rR]/.test(w.text)) recursive = true;
      continue;
    }
    targets.push(w);
  }
  if (noPreserveRoot) return found('rm_recursive', '/');
  if (cmd.viaXargs) return xargsTargets(cmd);
  if (!recursive && !maybeRecursive) return null;
  let uncertain: DetectorResult | null = null;
  for (const t of targets) {
    const { cls } = classifyPath(t, cmd.cwdUnknown);
    if (cls === 'inside' || cls === 'temp') continue;
    if (cls === 'dynamic') { uncertain ??= unparseable('dynamic_argument', 'rm_recursive'); continue; }
    if (!recursive) { uncertain ??= unparseable('dynamic_argument', 'rm_recursive'); continue; }
    return found('rm_recursive', t.text);
  }
  return uncertain;
}

/** Roots of a find command: operands before the first expression. */
function findRoots(cmd: Cmd): Word[] {
  const roots: Word[] = [];
  for (const w of cmd.args) {
    if (w.text.startsWith('-') || w.text === '(' || w.text === '!') break;
    roots.push(w);
  }
  return roots;
}

/**
 * rm fed by xargs: the targets come from stdin. Allowed only when the list comes straight
 * from a filtered find rooted inside the working tree; a dangerous find root is a definite
 * match; anything else fails safe.
 */
function xargsTargets(cmd: Cmd): DetectorResult {
  const up = cmd.upstream;
  if (up && up.name === 'find' && !cmd.cwdUnknown) {
    const roots = findRoots(up);
    const filtered = up.args.length > roots.length;
    const classes = (roots.length ? roots : [{ text: '.', dynamic: false, vars: [], home: false, glob: false, quoted: false }]).map((r) => ({ r, ...classifyPath(r, up.cwdUnknown) }));
    const danger = classes.find((c) => !['inside', 'tree_root', 'temp', 'dynamic'].includes(c.cls));
    if (danger) return found('rm_xargs', danger.r.text);
    if (filtered && classes.every((c) => c.cls === 'inside' || c.cls === 'tree_root' || c.cls === 'temp')) return NOT_MATCHED;
  }
  return unparseable('dynamic_argument', 'rm_xargs');
}

function truncateFile(cmd: Cmd): DetectorResult | null {
  let size: string | undefined;
  for (let k = 0; k < cmd.args.length; k++) {
    const t = cmd.args[k].text;
    if (t === '-s' || t === '--size') size = cmd.args[k + 1]?.text;
    else if (t.startsWith('--size=')) size = t.slice(7);
    else if (/^-s./.test(t)) size = t.slice(2);
  }
  if (size !== undefined && /^[+>]/.test(size)) return null; // only extends
  const ops: Word[] = [];
  for (let k = 0; k < cmd.args.length; k++) {
    const t = cmd.args[k].text;
    if (t === '-s' || t === '--size' || t === '-r' || t === '--reference') { k++; continue; }
    if (t.startsWith('-')) continue;
    ops.push(cmd.args[k]);
  }
  let uncertain: DetectorResult | null = null;
  for (const p of ops) {
    const { cls } = classifyPath(p, cmd.cwdUnknown);
    if (cls === 'inside' || cls === 'temp' || cls === 'tree_root') continue;
    if (cls === 'dynamic') { uncertain ??= unparseable('dynamic_argument', 'truncate_file'); continue; }
    return found('truncate_file', p.text);
  }
  return uncertain;
}

/** mv / cp onto /dev/null or a block device. */
function moveToDevice(cmd: Cmd): DetectorResult | null {
  const tFlag = cmd.args.findIndex((w) => w.text === '-t' || w.text === '--target-directory');
  const eq = cmd.args.find((w) => w.text.startsWith('--target-directory='));
  const ops = operands(cmd.args);
  const dest = tFlag >= 0 ? cmd.args[tFlag + 1]?.text : eq ? eq.text.slice(eq.text.indexOf('=') + 1) : ops.length >= 2 ? ops[ops.length - 1].text : undefined;
  if (!dest) return null;
  if (dest === '/dev/null' || DISK_DEVICE.test(dest)) return found(cmd.name === 'mv' ? 'move_to_device' : 'disk_write', dest);
  return null;
}

/** An absolute or home path an overwrite would clobber; /dev, /tmp and /var/tmp are left alone. */
function clobberable(w: Word, cwdUnknown: boolean): boolean {
  if (w.text.startsWith('/dev/')) return false;
  const { cls } = classifyPath(w, cwdUnknown);
  return cls === 'absolute' || cls === 'root' || cls === 'home';
}

function overwrite(cmd: Cmd): DetectorResult | null {
  for (const r of cmd.redirects) {
    if (!r.target || !['>', '>|', '&>'].includes(r.op)) continue;
    if (clobberable(r.target, cmd.cwdUnknown)) return found('overwrite_redirect', r.target.text);
  }
  if (cmd.name === 'tee' && !cmd.args.some((w) => w.text === '--append' || /^-[A-Za-z]*a/.test(w.text))) {
    const t = operands(cmd.args).find((w) => clobberable(w, cmd.cwdUnknown));
    if (t) return found('overwrite_redirect', t.text);
  }
  return null;
}

function find(cmd: Cmd): DetectorResult | null {
  const path = cmd.args.find((w) => !w.text.startsWith('-') && !w.text.startsWith('(') && w.text !== '!')?.text;
  for (let k = 0; k < cmd.args.length; k++) {
    const t = cmd.args[k].text;
    if (t === '-delete') return found('find_delete', path);
    if (['-exec', '-execdir', '-ok', '-okdir'].includes(t)) {
      const next = cmd.args[k + 1];
      if (!next) continue;
      if (next.dynamic) return unparseable('dynamic_argument', 'find_delete');
      const prog = next.text.split('/').pop()!.toLowerCase();
      if (['rm', 'shred', 'unlink', 'rmdir'].includes(prog)) return found('find_delete', path);
      if (['sh', 'bash', 'zsh', 'dash'].includes(prog) && cmd.args[k + 2]?.text === '-c') {
        const script = cmd.args[k + 3];
        if (script && /\brm\b|\bshred\b/.test(script.text)) return found('find_delete', path);
      }
    }
  }
  return null;
}

function git(cmd: Cmd): DetectorResult | null {
  // Global options before the subcommand.
  let k = 0;
  while (k < cmd.args.length) {
    const t = cmd.args[k].text;
    if (t === '-C' || t === '-c' || t === '--git-dir' || t === '--work-tree' || t === '--namespace' || t === '--config-env') { k += 2; continue; }
    if (t.startsWith('-')) { k += 1; continue; }
    break;
  }
  const sub = cmd.args[k];
  if (!sub) return null;
  if (sub.dynamic) return unparseable('dynamic_argument', 'git_push');
  if (sub.text !== 'push') return null;
  const rest = cmd.args.slice(k + 1);
  const refs: Word[] = [];
  let force = false;
  let del = false;
  let mirror = false;
  let all = false;
  for (let j = 0; j < rest.length; j++) {
    const w = rest[j];
    const t = w.text;
    if (t === '--') { refs.push(...rest.slice(j + 1)); break; }
    if (t.startsWith('--')) {
      if (t === '--force' || t.startsWith('--force-with-lease') || t === '--force-if-includes') force = true;
      if (t === '--delete' || t === '--prune') del = true;
      if (t === '--mirror') mirror = true;
      if (t === '--all' || t === '--branches') all = true;
      if (['--repo', '--receive-pack', '--exec', '--push-option'].includes(t)) j++;
      continue;
    }
    if (/^-[A-Za-z]+$/.test(t)) {
      if (t.includes('f')) force = true;
      if (t.includes('d')) del = true;
      if (t.endsWith('o')) j++;
      continue;
    }
    refs.push(w);
  }
  const remote = refs[0]?.text;
  const specs = refs.slice(1);
  const target = (spec: string): string => spec.replace(/^\+/, '').split(':').pop()!.replace(/^refs\/heads\//, '');
  if (mirror) return found('git_push_mirror', remote);
  if (force || specs.some((s) => s.text.startsWith('+'))) return found('git_force_push', specs[0] ? target(specs[0].text) : remote);
  if (del || specs.some((s) => s.text.startsWith(':'))) return found('git_push_delete', specs[0] ? target(specs[0].text) : remote);
  for (const s of specs) {
    if (s.dynamic) return unparseable('dynamic_argument', 'git_push');
    if (PROTECTED_BRANCHES.has(target(s.text))) return found('git_push_protected', target(s.text));
  }
  // Every branch at once (main among them): its own kind, so a policy can treat a plain
  // push to one protected branch differently without letting this through.
  if (all) return found('git_push_all', remote);
  if (refs[0]?.dynamic) return unparseable('dynamic_argument', 'git_push');
  return null;
}

function recursiveOwnership(cmd: Cmd): DetectorResult | null {
  if (!hasShort(cmd.args, 'R') && !hasFlag(cmd.args, '--recursive')) return null;
  const ops = operands(cmd.args);
  const paths = hasFlag(cmd.args, '--reference') ? ops : ops.slice(1);
  let uncertain: DetectorResult | null = null;
  for (const p of paths) {
    const { cls, depth } = classifyPath(p, cmd.cwdUnknown);
    if (cls === 'dynamic') { uncertain ??= unparseable('dynamic_argument', 'recursive_permissions'); continue; }
    const broad = cls === 'root' || cls === 'parent' || cls === 'outside_cwd' || (cls === 'home' && depth <= 1) || (cls === 'absolute' && depth <= 2);
    if (broad) return found('recursive_permissions', p.text);
  }
  return uncertain;
}

function sqlClient(cmd: Cmd): DetectorResult | null {
  const flagValue = (short: string[], long: string[]): Word | undefined => {
    for (let k = 0; k < cmd.args.length; k++) {
      const t = cmd.args[k].text;
      if (short.includes(t) || long.includes(t)) return cmd.args[k + 1];
      for (const l of long) if (t.startsWith(l + '=')) return { ...cmd.args[k], text: t.slice(l.length + 1) };
      for (const s of short) if (t.startsWith(s) && t.length > s.length && !t.startsWith('--')) return { ...cmd.args[k], text: t.slice(s.length) };
    }
    return undefined;
  };
  let sql: Word | undefined;
  switch (cmd.name) {
    case 'psql': sql = flagValue(['-c'], ['--command']); break;
    case 'mysql': case 'mariadb': sql = flagValue(['-e'], ['--execute']); break;
    case 'clickhouse-client': sql = flagValue(['-q'], ['--query']); break;
    case 'sqlite3': case 'sqlite': sql = positionals(cmd.args)[1]; break;
    default: return null;
  }
  const texts: string[] = [];
  if (sql) {
    if (sql.dynamic) return unparseable('dynamic_argument', 'sql');
    texts.push(sql.text);
  }
  texts.push(...cmd.heredocBodies);
  for (const r of cmd.redirects) {
    if (r.op === '<<<' && r.target) {
      if (r.target.dynamic) return unparseable('dynamic_argument', 'sql');
      texts.push(r.target.text);
    }
  }
  if (!sql && cmd.pipedIn) return unparseable('interpreter_stdin', 'sql');
  for (const t of texts) {
    const r = sqlDestructive(t);
    if (r.matched) return r;
  }
  return null;
}

function diskRedirect(cmd: Cmd): DetectorResult | null {
  for (const r of cmd.redirects) {
    if (!r.target || !/>|<>/.test(r.op)) continue;
    if (DISK_DEVICE.test(r.target.text)) return found('disk_write', r.target.text);
  }
  return null;
}

function check(cmd: Cmd): DetectorResult | null {
  const viaRedirect = diskRedirect(cmd) ?? overwrite(cmd);
  if (viaRedirect) return viaRedirect;
  const name = cmd.name;
  if (name === 'truncate') return truncateFile(cmd);
  if (name === 'mv' || name === 'cp') return moveToDevice(cmd);
  if (name === 'rm') return rm(cmd);
  if (name === 'find') return find(cmd);
  if (name === 'git') return git(cmd);
  if (name === 'dd') {
    const of = cmd.args.find((w) => w.text.startsWith('of='));
    return of ? found('disk_write', of.text.slice(3)) : null;
  }
  if (name === 'mkfs' || name.startsWith('mkfs.') || name === 'mke2fs' || name === 'wipefs' || name === 'mkswap') {
    return found('disk_format', operands(cmd.args).pop()?.text);
  }
  if (name === 'shred') return found('shred', operands(cmd.args)[0]?.text);
  if (name === 'chmod' || name === 'chown' || name === 'chgrp') return recursiveOwnership(cmd);
  return sqlClient(cmd);
}

/**
 * `filter` narrows the definite findings that count, per command: a command whose finding
 * is filtered out counts as not matched and reading goes on to the next command, so
 * `git push origin main && rm -rf ~/x` still matches with `git_push_protected` excluded.
 * check() returns one finding per command, and a git command's only other finding is a
 * redirect, which is checked first, so filtering one kind never hides another. Text the
 * detector cannot read still matches (fail safe), whatever the filter.
 */
export function shellDestructive(text: string, filter?: KindFilter): DetectorResult {
  if (!filter) return overShell(text, check);
  return overShell(text, (cmd) => {
    const r = check(cmd);
    if (!r || !r.matched || !r.parsed) return r;
    if (filter.only && !filter.only.includes(r.kind)) return null;
    if (filter.except && filter.except.includes(r.kind)) return null;
    return r;
  });
}
