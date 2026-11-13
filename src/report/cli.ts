import { existsSync } from 'node:fs';
import { scanLog, type ObservedEvent } from '../heartbeat/aggregate.js';
import { COUNT_NAMES, addDays, emptyCounts, utcDay, type Counts } from '../heartbeat/contract.js';
import { flag } from '../heartbeat/launch.js';
import { canonicalLogPath } from '../heartbeat/send.js';
import { hookReceiptsPath } from '../hook/decide.js';

/**
 * `mcp-guard report`: the last 7 UTC days of the local receipt log, per day and in
 * total. Read-only: it reads one log, writes nothing, and opens no network connection.
 * Counted by the heartbeat's own aggregation (heartbeat/aggregate.ts), so its six
 * totals are the numbers a heartbeat would carry for this log; unlike the heartbeat it
 * names every rule id (it prints them on this machine only) and lists observe-only
 * matches. Never prints argument text: the aggregation reads no arguments.
 */

export const REPORT_DAYS = 7;
const TOP = 10;

const HELP = `
mcp-guard report: what the guard decided in the last ${REPORT_DAYS} days, from the local receipt log

Usage:
  mcp-guard report [--config <path>] [--receipts <path>] [--json]

Options:
  --config <path>    Policy file whose log to read (default: ./pp.config.yaml). The log is
                     PP_SHARED_RECEIPTS_PATH if set, else pp-receipts.jsonl beside the policy,
                     as for the hook and the heartbeat. The policy itself is not read.
  --receipts <path>  Read this receipt log instead
  --json             Print JSON instead of text

Counts per UTC day: allowed, blocked, held, approved, denied, expired (counted as the usage
heartbeat counts them, docs/heartbeat.md), the rules that blocked or held most, and
observe-only matches (which the heartbeat does not count). Reads the log only: sends
nothing, changes nothing, never prints arguments.
`.trim();

export interface RuleCount { ruleId: string; count: number }

export interface ReportDay {
  day: string;
  counts: Counts;
  observed: number;
}

export interface Report {
  log: string;
  logFound: boolean;
  from: string;
  to: string;
  days: ReportDay[];
  total: Counts & { observed: number };
  /** Rules that blocked or held calls, most first (any rule id: this stays on the machine). */
  topRules: RuleCount[];
  /** observe: true rules that matched, most first. */
  observedRules: RuleCount[];
}

const top = (m: Map<string, number>): RuleCount[] =>
  [...m.entries()].map(([ruleId, count]) => ({ ruleId, count })).sort((a, b) => b.count - a.count || (a.ruleId < b.ruleId ? -1 : 1)).slice(0, TOP);

/** Build the report for the log at `receiptsPath`, for the 7 UTC days ending today. */
export async function buildReport(receiptsPath: string, now: number = Date.now()): Promise<Report> {
  const path = canonicalLogPath(receiptsPath);
  const to = utcDay(now);
  const from = addDays(to, -(REPORT_DAYS - 1));
  const observed: ObservedEvent[] = [];
  const logFound = existsSync(path);
  const log = await scanLog(undefined, path, 'mcp-guard', {
    now,
    maxBytes: Number.MAX_SAFE_INTEGER,
    keepRule: () => true,
    onObserved: (e) => observed.push(e),
  });

  const total = { ...emptyCounts(), observed: 0 };
  const rules = new Map<string, number>();
  const observedRules = new Map<string, number>();
  const days: ReportDay[] = [];
  for (let i = REPORT_DAYS - 1; i >= 0; i--) {
    const day = addDays(to, -i);
    const d = log.days[day];
    const counts = emptyCounts();
    if (d) {
      for (const k of COUNT_NAMES) counts[k] = d.counts[k] ?? 0;
      for (const [id, n] of Object.entries(d.rules)) rules.set(id, (rules.get(id) ?? 0) + n);
    }
    const obs = observed.filter((e) => utcDay(e.at) === day);
    for (const e of obs) if (e.ruleId) observedRules.set(e.ruleId, (observedRules.get(e.ruleId) ?? 0) + 1);
    for (const k of COUNT_NAMES) total[k] += counts[k];
    total.observed += obs.length;
    days.push({ day, counts, observed: obs.length });
  }
  return { log: path, logFound, from, to, days, total, topRules: top(rules), observedRules: top(observedRules) };
}

const isEmpty = (r: Report): boolean => COUNT_NAMES.every((k) => r.total[k] === 0) && r.total.observed === 0;

/** The empty-log line: a missing log and a log with nothing in the window are both normal. */
export function emptyLine(r: Report): string {
  return r.logFound
    ? `No guarded calls recorded between ${r.from} and ${r.to} (UTC) in ${r.log}.`
    : `No receipt log at ${r.log}: nothing to report yet. The guard writes it on the first guarded call (pass --config or --receipts to read another).`;
}

export function formatReport(r: Report): string {
  if (isEmpty(r)) return emptyLine(r);
  const cols = ['day', ...COUNT_NAMES, 'observed'];
  const rows = [
    ...r.days.map((d) => [d.day, ...COUNT_NAMES.map((k) => String(d.counts[k])), String(d.observed)]),
    ['total', ...COUNT_NAMES.map((k) => String(r.total[k])), String(r.total.observed)],
  ];
  const width = cols.map((c, i) => Math.max(c.length, ...rows.map((row) => row[i].length)));
  const line = (cells: string[]): string => cells.map((c, i) => (i === 0 ? c.padEnd(width[i]) : c.padStart(width[i]))).join('  ').trimEnd();
  const out = [
    `mcp-guard report: ${r.from} to ${r.to} (UTC), from ${r.log}`,
    '',
    line(cols),
    ...rows.slice(0, -1).map(line),
    line(rows[rows.length - 1]),
    '',
    'Rules that blocked or held most:',
    ...(r.topRules.length ? r.topRules.map((x) => `  ${x.ruleId}  ${x.count}`) : ['  none']),
    '',
    'Observe-only matches (observe: true rules; not enforced, not in the heartbeat):',
    ...(r.observedRules.length ? r.observedRules.map((x) => `  ${x.ruleId}  ${x.count}`) : ['  none']),
    '',
    'held: calls that needed a signature. approved, denied, expired: signed, rejected, or not signed in time. Counted as the usage heartbeat counts (docs/heartbeat.md).',
  ];
  return out.join('\n');
}

export async function runReport(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(HELP);
    return 0;
  }
  const known = new Set(['--config', '--receipts', '--json']);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!known.has(a)) { process.stderr.write(`[mcp-guard] report: unknown option ${a}\n${HELP}\n`); return 2; }
    if (a !== '--json') {
      if (args[i + 1] === undefined || args[i + 1].startsWith('--')) { process.stderr.write(`[mcp-guard] report: ${a} needs a value\n`); return 2; }
      i++;
    }
  }
  const receiptsPath = flag(args, '--receipts') ?? hookReceiptsPath(flag(args, '--config') ?? './pp.config.yaml');
  let report: Report;
  try {
    report = await buildReport(receiptsPath);
  } catch (e: any) {
    process.stderr.write(`[mcp-guard] report: the receipt log could not be read (${e?.code ?? 'READ_ERROR'})\n`);
    return 1;
  }
  if (args.includes('--json')) {
    if (isEmpty(report)) process.stderr.write(`[mcp-guard] ${emptyLine(report)}\n`);
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatReport(report));
  }
  return 0;
}
