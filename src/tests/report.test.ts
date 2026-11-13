import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Issuer, type ReasonCode, type ReceiptStatus, type Decider } from '../issuer.js';
import { emitCloudDecision, emitHold, emitObserved, emitReceipt, type CloudDecisionLine } from '../receipt-log.js';
import { addDays, utcDay } from '../heartbeat/contract.js';
import { bodyFor, refresh } from '../heartbeat/send.js';
import { loadState } from '../heartbeat/state.js';
import { buildReport, formatReport } from '../report/cli.js';

/**
 * `mcp-guard report`: the heartbeat's counts per day for the last 7 days, every rule id,
 * observe-only matches (which the heartbeat leaves out), no network, no argument text.
 */

const CLI = join(__dirname, '..', 'cli.js');
const SENTINEL = 'SENTINEL_report_4c2a_never_printed';
const NOON = Date.parse(`${utcDay(Date.now())}T12:00:00.000Z`);
const DAY = 86_400_000;
const iso = (ms: number): string => new Date(ms).toISOString();
const tmp = (): string => mkdtempSync(join(tmpdir(), 'mcp-guard-report-'));

const issuer = new Issuer({
  config: { mode: 'enforce', signing: 'off', server_label: 'srv', policy_sha256: '0'.repeat(64), receipt_ttl_seconds: 3600, scoped_receipt_ttl_seconds: 900 },
  agentId: 'agent-1',
});

function receipt(log: string, status: ReceiptStatus, codes: ReasonCode[], ruleId: string | null, at: number, decider: Decider = { kind: 'policy' }): void {
  emitReceipt(issuer.issue({ method: 'tools/call', tool: 'run_query', input: { sql: SENTINEL }, status, ruleId, reasonCodes: codes, decider, now: new Date(at) }), log);
}
function hold(log: string, at: number, ruleId: string | null, agentId = 'agent-1'): void {
  emitHold({ id: null, method: 'tools/call', tool: 'run_query', agentId, ruleId, inputHash: 'sha256:00', createdAt: iso(at) }, log);
}
function cloud(log: string, decision: CloudDecisionLine['decision'], at: number, ruleId: string | null, agentId = 'agent-1'): void {
  emitCloudDecision({
    decision, requestId: null, receiptId: null, receiptUrl: null, fingerprint: 'sha256:00', method: 'tools/call', tool: 'run_query', server: 'srv', agentId, ruleId,
    decider: null, reason: decision === 'released' ? null : 'r', code: null, at: iso(at), artifact: null,
  }, log);
}
function observed(log: string, at: number, ruleId: string): void {
  emitObserved({ ruleId, would: 'held_for_approval', detector: 'secret_read', kind: 'secret_file', parsed: true, reason: 'r', method: 'tools/call', tool: 'Bash', agentId: 'claude-code', inputHash: 'sha256:0', at: iso(at) }, log);
}

/** Every line kind, today and yesterday, plus one line outside the window. */
function fixture(log: string, noon: number, withObserved = true): void {
  receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, noon);                                     // allowed
  receipt(log, 'APPROVED', ['RULE_MATCHED:read-ok'], 'read-ok', noon + 1);                      // allowed
  receipt(log, 'DENIED', ['RULE_MATCHED:destructive-sql'], 'destructive-sql', noon + 2);        // blocked, built-in rule
  receipt(log, 'DENIED', ['RULE_MATCHED:my-block'], 'my-block', noon + 3);                      // blocked, custom rule
  receipt(log, 'DENIED', ['RULE_MATCHED:my-block'], 'my-block', noon + 4);                      // blocked, custom rule
  cloud(log, 'released', noon + 5, 'destructive-shell', 'claude-code');                         // held + approved (hook)
  hold(log, noon + 6, 'hold-deploy');                                                           // held (proxy) ...
  cloud(log, 'denied', noon + 60_000, 'hold-deploy');                                           // ... closed by this: denied
  receipt(log, 'DENIED', ['RULE_MATCHED:hold-deploy', 'APPROVAL_EXPIRED'], 'hold-deploy', noon + 70_000); // expired
  if (withObserved) {
    observed(log, noon + 7, 'secret-read');
    observed(log, noon + 8, 'secret-read');
    observed(log, noon + 9, 'my-observed');
  }
  appendFileSync(log, 'not json\n');
  receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, noon - DAY);                               // yesterday: allowed
  if (withObserved) observed(log, noon - DAY, 'secret-read');                                   // yesterday: observed
  receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, noon - 8 * DAY);                           // outside the 7 days
}

function run(args: string[], env: NodeJS.ProcessEnv = {}, cwd?: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const base: NodeJS.ProcessEnv = { ...process.env, ...env };
    if (!('PP_SHARED_RECEIPTS_PATH' in env)) delete base.PP_SHARED_RECEIPTS_PATH;
    const p = spawn('node', [CLI, 'report', ...args], { env: base, cwd });
    let stdout = '';
    let stderr = '';
    p.stdout.on('data', (d) => { stdout += d; });
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

describe('report: counts', () => {
  it('matches the fixture per day and in total, with every rule id and the observe-only matches', async () => {
    const dir = tmp();
    const log = join(dir, 'pp-receipts.jsonl');
    fixture(log, NOON);
    const r = await buildReport(log, NOON);
    const today = utcDay(NOON);
    const yesterday = addDays(today, -1);
    assert.equal(r.days.length, 7);
    assert.equal(r.from, addDays(today, -6));
    assert.equal(r.to, today);
    assert.ok(r.logFound);
    const byDay = Object.fromEntries(r.days.map((d) => [d.day, d]));
    assert.deepEqual(byDay[today].counts, { allowed: 2, blocked: 3, held: 2, approved: 1, denied: 1, expired: 1 });
    assert.equal(byDay[today].observed, 3);
    assert.deepEqual(byDay[yesterday].counts, { allowed: 1, blocked: 0, held: 0, approved: 0, denied: 0, expired: 0 });
    assert.equal(byDay[yesterday].observed, 1);
    for (const d of r.days) if (d.day !== today && d.day !== yesterday) assert.equal(Object.values(d.counts).reduce((a, b) => a + b, 0) + d.observed, 0, d.day);
    assert.deepEqual(r.total, { allowed: 3, blocked: 3, held: 2, approved: 1, denied: 1, expired: 1, observed: 4 });
    assert.deepEqual(r.topRules, [
      { ruleId: 'my-block', count: 2 }, { ruleId: 'destructive-shell', count: 1 }, { ruleId: 'destructive-sql', count: 1 }, { ruleId: 'hold-deploy', count: 1 },
    ]);
    assert.deepEqual(r.observedRules, [{ ruleId: 'secret-read', count: 3 }, { ruleId: 'my-observed', count: 1 }]);

    const text = formatReport(r);
    assert.match(text, new RegExp(`^${today}\\s+2\\s+3\\s+2\\s+1\\s+1\\s+1\\s+3$`, 'm'));
    assert.match(text, /^total\s+3\s+3\s+2\s+1\s+1\s+1\s+4$/m);
    assert.match(text, /^ {2}my-block {2}2$/m);
    assert.match(text, /^ {2}secret-read {2}3$/m);
  });

  it('observe-only matches are in the report and not in the heartbeat body, which they leave unchanged', async () => {
    const dir = tmp();
    const withObs = join(dir, 'with.jsonl');
    const without = join(dir, 'without.jsonl');
    fixture(withObs, NOON, true);
    fixture(without, NOON, false);
    const body = async (log: string) => {
      const state = loadState(join(dir, 'no-state.json'));
      await refresh(state, log, 'claude-code', NOON);
      return bodyFor(state, utcDay(NOON), 'enforce', 'claude-code');
    };
    const a = await body(withObs);
    const b = await body(without);
    assert.deepEqual(a, b, 'observed lines change nothing the heartbeat sends');
    assert.equal(JSON.stringify(a).includes('observed'), false);
    assert.equal(JSON.stringify(a).includes('secret-read'), false);
    assert.equal(JSON.stringify(a).includes('my-block'), false, 'custom rule ids stay out of the heartbeat');
    const r = await buildReport(withObs, NOON);
    assert.deepEqual(r.days.find((d) => d.day === utcDay(NOON))!.counts, a.counts, 'the report counts what the heartbeat counts');
    assert.equal(r.total.observed, 4);
    assert.ok(r.observedRules.some((x) => x.ruleId === 'secret-read'));
    assert.equal(existsSync(join(dir, 'no-state.json')), false, 'nothing was written');
  });
});

describe('report: CLI', () => {
  let dir: string;
  let preload: string;
  let netLog: string;
  before(() => {
    dir = tmp();
    netLog = join(dir, 'net.log');
    preload = join(dir, 'preload.js');
    // Records the pid of every process that opens a TCP connection (as in heartbeat.test.ts).
    writeFileSync(preload, `const net = require('net'); const fs = require('fs');
const orig = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...a) { try { fs.appendFileSync(${JSON.stringify(netLog)}, process.pid + '\\n'); } catch {} return orig.apply(this, a); };
`);
  });

  it('a missing log prints a clear line and exits 0; so does an empty one, also with --json', async () => {
    const ws = tmp();
    const missing = await run(['--config', join(ws, 'pp.config.yaml')]);
    assert.equal(missing.code, 0, missing.stderr);
    assert.match(missing.stdout, /^No receipt log at .*pp-receipts\.jsonl: nothing to report yet\./);
    const json = await run(['--config', join(ws, 'pp.config.yaml'), '--json']);
    assert.equal(json.code, 0);
    assert.equal(JSON.parse(json.stdout).logFound, false);
    assert.match(json.stderr, /No receipt log at/);

    writeFileSync(join(ws, 'pp-receipts.jsonl'), '');
    const empty = await run(['--config', join(ws, 'pp.config.yaml')]);
    assert.equal(empty.code, 0);
    assert.match(empty.stdout, /^No guarded calls recorded between \d{4}-\d{2}-\d{2} and \d{4}-\d{2}-\d{2} \(UTC\) in /);

    // No policy, no --config: the default ./pp.config.yaml's directory.
    const none = await run([], {}, ws);
    assert.equal(none.code, 0);
    assert.match(none.stdout, /^No guarded calls recorded/);
  });

  it('reads the log beside --config, or PP_SHARED_RECEIPTS_PATH, and refuses unknown options', async () => {
    const ws = tmp();
    const now = Date.now();
    fixture(join(ws, 'pp-receipts.jsonl'), now - 120_000);
    const r = await run(['--config', join(ws, 'pp.config.yaml'), '--json']);
    assert.equal(r.code, 0, r.stderr);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.total.blocked, 3);
    assert.equal(parsed.total.observed, 4);
    const shared = join(ws, 'shared.jsonl');
    receipt(shared, 'DENIED', ['RULE_MATCHED:x'], 'x', now);
    const s = await run(['--config', join(ws, 'pp.config.yaml'), '--json'], { PP_SHARED_RECEIPTS_PATH: shared });
    assert.equal(JSON.parse(s.stdout).total.blocked, 1);
    const bad = await run(['--send']);
    assert.equal(bad.code, 2);
    assert.match(bad.stderr, /unknown option --send/);
  });

  it('opens no network connection, even with an install token and a cloud policy', async () => {
    const ws = tmp();
    writeFileSync(join(ws, 'pp.config.yaml'), 'default_action: allow\ncloud:\n  environment: staging\n');
    fixture(join(ws, 'pp-receipts.jsonl'), Date.now() - 120_000);
    for (const args of [[], ['--json']]) {
      const r = await run(['--config', join(ws, 'pp.config.yaml'), ...args], {
        NODE_OPTIONS: `--require ${preload}`, PP_INSTALL_TOKEN: `pp_test_${'reportfake'.repeat(2)}`, MCP_GUARD_TOKEN_STORE: 'file', PP_KEYS_DIR: join(ws, 'keys'),
      });
      assert.equal(r.code, 0, r.stderr);
    }
    assert.equal(existsSync(netLog), false, existsSync(netLog) ? readFileSync(netLog, 'utf8') : '');
    assert.equal(existsSync(join(ws, 'heartbeat-state.json')), false, 'no heartbeat state written');
  });

  it('never prints argument text', async () => {
    const ws = tmp();
    const log = join(ws, 'pp-receipts.jsonl');
    const now = Date.now() - 120_000;
    fixture(log, now);
    // Lines carrying argument-like text in every field the guard could ever write, and some it never does.
    appendFileSync(log, JSON.stringify({ hold: { id: null, method: 'tools/call', tool: `Bash ${SENTINEL}`, agentId: SENTINEL, ruleId: 'r1', inputHash: SENTINEL, createdAt: iso(now), args: { command: SENTINEL } } }) + '\n');
    appendFileSync(log, JSON.stringify({ observed: { ruleId: 'o1', would: 'held_for_approval', detector: SENTINEL, kind: SENTINEL, parsed: false, reason: SENTINEL, method: 'tools/call', tool: SENTINEL, agentId: SENTINEL, inputHash: SENTINEL, at: iso(now), command: SENTINEL } }) + '\n');
    appendFileSync(log, JSON.stringify({ cloud: { decision: 'blocked', reason: SENTINEL, code: 'X', tool: SENTINEL, agentId: SENTINEL, method: 'tools/call', ruleId: 'c1', at: iso(now), artifact: { input: SENTINEL } } }) + '\n');
    assert.ok(readFileSync(log, 'utf8').includes(SENTINEL), 'the fixture carries the sentinel');
    for (const args of [[], ['--json']]) {
      const r = await run(['--receipts', log, ...args]);
      assert.equal(r.code, 0, r.stderr);
      assert.ok(r.stdout.includes('r1') && r.stdout.includes('o1'), 'the lines were counted');
      assert.equal(r.stdout.includes(SENTINEL), false);
      assert.equal(r.stderr.includes(SENTINEL), false);
      assert.equal(r.stdout.includes('run_query'), false, 'no tool names either');
    }
  });
});
