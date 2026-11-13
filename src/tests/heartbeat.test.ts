import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, statSync, truncateSync, writeFileSync } from 'node:fs';
import { createServer, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Issuer, type ReasonCode, type ReceiptStatus, type Decider } from '../issuer.js';
import { emitCloudDecision, emitHold, emitObserved, emitReceipt, type CloudDecisionLine } from '../receipt-log.js';
import { parseConfig } from '../config.js';
import { eventOf, scanLog } from '../heartbeat/aggregate.js';
import { buildBody, validateBody, utcDay, addDays, guardVersion, COUNT_NAMES } from '../heartbeat/contract.js';
import { runHeartbeat, postHeartbeat, MIN_INTERVAL_MS, REFUSED_BACKOFF_MS } from '../heartbeat/send.js';
import { loadState, acquireLock } from '../heartbeat/state.js';
import { heartbeatAfterHook } from '../heartbeat/hook.js';
import { startProxyHeartbeat } from '../heartbeat/proxy.js';
import { heartbeatDisabledReason } from '../heartbeat/launch.js';

/**
 * The usage heartbeat: count mapping from every receipt-log line type, incremental and
 * idempotent recounting, throttle and lock, opt-outs, the contract's body checks, and
 * that it never touches a decision (the hook makes no network request and does not wait).
 */

const CLI = join(__dirname, '..', 'cli.js');
const TOKEN = `pp_test_${'heartbeatfake'.repeat(2)}`;
const SENTINEL = 'SENTINEL_hb_7d1e_never_sent';
const FAKE_KEY = 'wJcxaKl9Mn3jXlE+JhdxmXZkcS6SyMiy7HoVMVLyF7g=';
const NOON = Date.parse(`${utcDay(Date.now())}T12:00:00.000Z`);
const iso = (ms: number): string => new Date(ms).toISOString();
const tmp = (): string => mkdtempSync(join(tmpdir(), 'mcp-guard-hb-'));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const issuer = new Issuer({
  config: { mode: 'enforce', signing: 'off', server_label: 'srv', policy_sha256: '0'.repeat(64), receipt_ttl_seconds: 3600, scoped_receipt_ttl_seconds: 900 },
  agentId: 'agent-1',
});

function receipt(log: string, status: ReceiptStatus, codes: ReasonCode[], ruleId: string | null, at: number, decider: Decider = { kind: 'policy' }): void {
  emitReceipt(issuer.issue({ method: 'tools/call', tool: 'run_query', input: { sql: SENTINEL }, status, ruleId, reasonCodes: codes, decider, now: new Date(at) }), log);
}
function hold(log: string, at: number, ruleId: string | null, agentId = 'agent-1', id: string | null = null): void {
  emitHold({ id, method: 'tools/call', tool: 'run_query', agentId, ruleId, inputHash: 'sha256:00', createdAt: iso(at) }, log);
}
function cloud(log: string, decision: CloudDecisionLine['decision'], at: number, ruleId: string | null, agentId = 'agent-1'): void {
  emitCloudDecision({
    decision, requestId: null, receiptId: null, receiptUrl: null, fingerprint: 'sha256:00', method: 'tools/call', tool: 'run_query', server: 'srv', agentId, ruleId,
    decider: null, reason: decision === 'released' ? null : 'r', code: decision === 'blocked' ? 'UNREACHABLE' : null, at: iso(at), artifact: null,
  }, log);
}

/** One line of every kind the guard writes, with the totals they must give. */
function fullLog(log: string): void {
  receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, NOON);                                      // allowed
  receipt(log, 'APPROVED', ['RULE_MATCHED:read-ok'], 'read-ok', NOON + 1);                       // allowed
  receipt(log, 'DENIED', ['RULE_MATCHED:block-rm-rf'], 'block-rm-rf', NOON + 2);                 // blocked
  receipt(log, 'DENIED', ['DEFAULT_ACTION'], null, NOON + 3);                                    // blocked, no rule
  hold(log, NOON + 4, 'hold-prod-db', 'agent-1', 'pa_1');                                         // held (local queue)
  receipt(log, 'APPROVED', ['RULE_MATCHED:hold-prod-db', 'OPERATOR_APPROVED'], 'hold-prod-db', NOON + 5, { kind: 'operator', operator: 'op' }); // approved
  receipt(log, 'APPROVED', ['RULE_MATCHED:hold-prod-db', 'COUNTDOWN_AUTO_RELEASE'], 'hold-prod-db', NOON + 6); // approved
  receipt(log, 'DENIED', ['RULE_MATCHED:hold-prod-db', 'OPERATOR_DENIED'], 'hold-prod-db', NOON + 7, { kind: 'operator', operator: 'op' }); // denied
  receipt(log, 'DENIED', ['RULE_MATCHED:hold-prod-db', 'APPROVAL_EXPIRED'], 'hold-prod-db', NOON + 8); // expired
  hold(log, NOON + 9, 'hold-prod-db');                                                            // held (proxy, then cloud)
  cloud(log, 'released', NOON + 60_000, 'hold-prod-db');                                          // approved, closes the hold above
  cloud(log, 'denied', NOON + 61_000, 'hold-prod-db', 'claude-code');                             // held + denied
  cloud(log, 'expired', NOON + 62_000, 'hold-prod-db', 'claude-code');                            // held + expired
  cloud(log, 'blocked', NOON + 63_000, 'hold-prod-db', 'claude-code');                            // held, no outcome
  hold(log, NOON + 64_000, 'destructive-shell', 'claude-code');                                   // held (hook, local-only)
  emitObserved({ ruleId: 'secrets', would: 'blocked', detector: 'secret_read', kind: 'x', parsed: true, reason: 'r', method: 'tools/call', tool: 'Bash', agentId: 'a', inputHash: 'sha256:0', at: iso(NOON) }, log); // nothing
  appendFileSync(log, 'not json\n{"unknown":{}}\n');                                                // nothing
}
const FULL = { allowed: 2, blocked: 2, held: 6, approved: 3, denied: 2, expired: 2 };
const FULL_RULES = { 'block-rm-rf': 1, 'hold-prod-db': 5, 'destructive-shell': 1 };

interface Hit { path: string; auth: string | undefined; body: any; raw: string }
interface Stand { url: string; hits: Hit[]; mode: { status: number; hang?: boolean; retryAfter?: string }; close(): Promise<void>; connections: number }

async function standIn(): Promise<Stand> {
  const hits: Hit[] = [];
  const sockets = new Set<Socket>();
  const stand = { url: '', hits, mode: { status: 200 } as Stand['mode'], connections: 0, close: async () => undefined } as Stand;
  const server: Server = createServer((req, res: ServerResponse) => {
    let raw = '';
    req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      let body: any = null;
      try { body = JSON.parse(raw); } catch { body = raw; }
      hits.push({ path: req.url ?? '', auth: req.headers.authorization, body, raw });
      if (stand.mode.hang) return; // never answers
      res.writeHead(stand.mode.status, { 'content-type': 'application/json', ...(stand.mode.retryAfter ? { 'retry-after': stand.mode.retryAfter } : {}) });
      res.end(JSON.stringify(stand.mode.status === 200 ? { day: body?.day, recordedAt: new Date().toISOString() } : { error: { code: 'X', message: 'no' } }));
    });
  });
  server.on('connection', (s) => { stand.connections++; sockets.add(s); s.on('close', () => sockets.delete(s)); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  stand.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  stand.close = () => new Promise<void>((r) => { for (const s of sockets) s.destroy(); server.close(() => r()); });
  return stand;
}

const policy = (apiUrl: string | null, extra = ''): string => `default_action: allow
signing: off
rules:
  - { id: no-write, tool: Write, action: block }
${apiUrl ? `cloud:
  api_url: ${apiUrl}
  environment: staging
  approval_timeout_seconds: 60
  trust_keys:
    - { key_id: k, public_key_b64: "${FAKE_KEY}" }
${extra}` : ''}`;

const fetchCounting = (status = 200): { fetchImpl: typeof fetch; bodies: string[] } => {
  const bodies: string[] = [];
  const fetchImpl = (async (_url: string, init: RequestInit) => { bodies.push(String(init.body)); return new Response('{}', { status }); }) as unknown as typeof fetch;
  return { fetchImpl, bodies };
};

describe('heartbeat: count mapping', () => {
  it('maps every receipt-log line type to the contract counts and rule totals', async () => {
    const dir = tmp();
    const log = join(dir, 'r.jsonl');
    fullLog(log);
    const state = await scanLog(undefined, log, 'mcp-proxy', { now: NOON });
    assert.deepEqual(state.days[utcDay(NOON)].counts, FULL);
    assert.deepEqual(state.days[utcDay(NOON)].rules, FULL_RULES);
  });

  it('classifies single lines: observed and junk count nothing; a hook hold never pairs', () => {
    assert.equal(eventOf('{"observed":{"ruleId":"x","at":"2026-01-01T00:00:00Z"}}'), null);
    assert.equal(eventOf('nope'), null);
    assert.equal(eventOf('{"record":{"status":"APPROVED"}}'), null, 'no time, not counted');
    const hookHold = eventOf(JSON.stringify({ hold: { id: null, agentId: 'claude-code', method: 'tools/call', tool: 'Bash', ruleId: 'r', createdAt: iso(NOON) } }));
    assert.equal(hookHold?.kind === 'hold' && hookHold.pairKey, null);
  });

  it('a cloud line does not close a hold older than the pairing window', async () => {
    const dir = tmp();
    const log = join(dir, 'r.jsonl');
    hold(log, NOON - 3 * 3_600_000, 'hold-prod-db');
    cloud(log, 'released', NOON, 'hold-prod-db');
    const s = await scanLog(undefined, log, 'mcp-proxy', { now: NOON });
    assert.equal(s.days[utcDay(NOON)].counts.held, 2);
    assert.equal(s.days[utcDay(NOON)].counts.approved, 1);
  });

  it('a partly written last line is left for the next scan', async () => {
    const dir = tmp();
    const log = join(dir, 'r.jsonl');
    receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, NOON);
    const line = readFileSync(log, 'utf8');
    appendFileSync(log, line.slice(0, 40));
    const a = await scanLog(undefined, log, 'mcp-proxy', { now: NOON });
    assert.equal(a.days[utcDay(NOON)].counts.allowed, 1);
    assert.equal(a.offset, Buffer.byteLength(line));
    appendFileSync(log, line.slice(40));
    const b = await scanLog(a, log, 'mcp-proxy', { now: NOON });
    assert.equal(b.days[utcDay(NOON)].counts.allowed, 2);
  });
});

describe('heartbeat: idempotent, bounded recounting', () => {
  it('incremental scans equal one scan from the start; scanning again adds nothing', async () => {
    const dir = tmp();
    const log = join(dir, 'r.jsonl');
    receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, NOON);
    hold(log, NOON + 1, 'hold-prod-db');
    let s = await scanLog(undefined, log, 'mcp-proxy', { now: NOON });
    fullLog(log);
    s = await scanLog(s, log, 'mcp-proxy', { now: NOON });
    s = await scanLog(s, log, 'mcp-proxy', { now: NOON });
    const fresh = await scanLog(undefined, log, 'mcp-proxy', { now: NOON });
    assert.deepEqual(s.days, fresh.days);
    assert.equal(s.offset, statSync(log).size);
  });

  it('reads at most maxBytes per run and catches up on later runs', async () => {
    const dir = tmp();
    const log = join(dir, 'r.jsonl');
    for (let i = 0; i < 50; i++) receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, NOON + i);
    let s = await scanLog(undefined, log, 'mcp-proxy', { now: NOON, maxBytes: 4096 });
    assert.ok(s.offset <= 4096 && s.days[utcDay(NOON)].counts.allowed < 50);
    for (let i = 0; i < 40 && s.offset < statSync(log).size; i++) s = await scanLog(s, log, 'mcp-proxy', { now: NOON, maxBytes: 4096 });
    assert.equal(s.days[utcDay(NOON)].counts.allowed, 50);
  });

  it('a truncated, replaced or rewritten log is recounted from the start', async () => {
    const dir = tmp();
    const log = join(dir, 'r.jsonl');
    fullLog(log);
    const s = await scanLog(undefined, log, 'mcp-proxy', { now: NOON });

    truncateSync(log, 0);
    receipt(log, 'DENIED', ['RULE_MATCHED:block-rm-rf'], 'block-rm-rf', NOON);
    const truncated = await scanLog(s, log, 'mcp-proxy', { now: NOON });
    assert.deepEqual(truncated.days[utcDay(NOON)].counts, { allowed: 0, blocked: 1, held: 0, approved: 0, denied: 0, expired: 0 });

    // Same inode, longer than before, different bytes: the tail check catches it.
    writeFileSync(log, '');
    for (let i = 0; i < 30; i++) receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, NOON + i);
    const rewritten = await scanLog(truncated, log, 'mcp-proxy', { now: NOON });
    assert.equal(rewritten.days[utcDay(NOON)].counts.allowed, 30);
    assert.equal(rewritten.days[utcDay(NOON)].counts.blocked, 0);

    const missing = await scanLog(rewritten, join(dir, 'gone.jsonl'), 'mcp-proxy', { now: NOON });
    assert.deepEqual(missing.days, {});
  });

  it('days the contract no longer accepts are dropped', async () => {
    const dir = tmp();
    const log = join(dir, 'r.jsonl');
    receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, NOON - 9 * 86_400_000);
    receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, NOON - 2 * 86_400_000);
    const s = await scanLog(undefined, log, 'mcp-proxy', { now: NOON });
    assert.deepEqual(Object.keys(s.days), [addDays(utcDay(NOON), -2)]);
  });
});

describe('heartbeat: body', () => {
  it('builds from an allowlist and drops rule ids that do not match the contract', () => {
    const body = buildBody({
      guardVersion: '0.4.0', clientLabel: 'claude-code', mode: 'enforce', day: utcDay(NOON),
      counts: { allowed: 3, blocked: 2.7, held: -1, extra: 9 } as any,
      rules: { 'block-rm-rf': 2, 'bad id': 5, 'user@laptop': 4, '/home/user/.ssh': 3, ['x'.repeat(129)]: 7, "q'uote": 1, 'ok.rule:1': 1 },
    });
    assert.deepEqual(body, {
      guardVersion: '0.4.0', clientLabel: 'claude-code', mode: 'enforce', day: utcDay(NOON),
      counts: { allowed: 3, blocked: 2, held: 0, approved: 0, denied: 0, expired: 0 },
      topRules: [{ ruleId: 'block-rm-rf', count: 2 }, { ruleId: 'ok.rule:1', count: 1 }],
    });
    assert.ok(validateBody(body, NOON).ok);
    const label = buildBody({ guardVersion: '1', clientLabel: 'my-macbook.local', mode: 'enforce', day: utcDay(NOON), counts: {} });
    assert.equal('clientLabel' in label, false, 'only fixed client-kind labels');
  });

  it('keeps the top 20 rules and stays under 8 KB', () => {
    const rules = Object.fromEntries(Array.from({ length: 60 }, (_, i) => [`r${i}-${'y'.repeat(100)}`, i + 1]));
    const body = buildBody({ guardVersion: '0.4.0', mode: 'observe', day: utcDay(NOON), counts: { allowed: 2_000_000 }, rules });
    assert.equal(body.topRules!.length, 20);
    assert.equal(body.topRules![0].count, 60);
    assert.equal(body.counts.allowed, 1_000_000);
    const v = validateBody(body, NOON);
    assert.ok(v.ok && Buffer.byteLength(v.json) <= 8192);
  });

  it('validation refuses anything outside the contract', () => {
    const good = buildBody({ guardVersion: '0.4.0', mode: 'enforce', day: utcDay(NOON), counts: {} });
    const bad: unknown[] = [
      { ...good, tool: 'Bash' },
      { ...good, argsPreview: 'x' },
      { ...good, clientLabel: 'user@host' },
      { ...good, guardVersion: '../x' },
      { ...good, mode: 'audit' },
      { ...good, day: addDays(utcDay(NOON), -8) },
      { ...good, day: addDays(utcDay(NOON), 2) },
      { ...good, day: '2026-02-30' },
      { ...good, counts: { ...good.counts, held: undefined } },
      { ...good, counts: { ...good.counts, path: 1 } },
      { ...good, topRules: [{ ruleId: 'bad id', count: 1 }] },
      { ...good, topRules: [{ ruleId: 'a', count: 1 }, { ruleId: 'a', count: 2 }] },
      { ...good, topRules: [{ ruleId: 'a', count: 1, note: 'x' }] },
    ];
    for (const b of bad) assert.equal(validateBody(b, NOON).ok, false, JSON.stringify(b));
    assert.equal(validateBody(good, NOON).ok, true);
    assert.match(guardVersion(), /^\d+\.\d+\.\d+/);
  });
});

describe('heartbeat: sending, throttle and lock', () => {
  it('sends today, then nothing within 10 minutes, then only what changed', async () => {
    const dir = tmp();
    const log = join(dir, 'r.jsonl');
    const statePath = join(dir, 'state.json');
    fullLog(log);
    const { fetchImpl, bodies } = fetchCounting();
    let now = NOON + 3_600_000;
    const run = (force = false) => runHeartbeat({ apiUrl: 'https://pp.test', mode: 'enforce', client: 'mcp-proxy', receiptsPath: log, statePath, token: TOKEN, fetchImpl, now: () => now, force });

    assert.deepEqual(await run(), { status: 'done', sent: [utcDay(NOON)], failed: null });
    const sent = JSON.parse(bodies[0]);
    assert.deepEqual(sent.counts, FULL);
    assert.equal(sent.clientLabel, 'mcp-proxy');
    assert.deepEqual(Object.keys(sent).sort(), ['clientLabel', 'counts', 'day', 'guardVersion', 'mode', 'topRules']);

    now += MIN_INTERVAL_MS - 1;
    assert.deepEqual(await run(), { status: 'skipped', reason: 'throttled' });
    now += 1;
    assert.deepEqual(await run(), { status: 'done', sent: [], failed: null }, 'unchanged: nothing sent');
    assert.equal(bodies.length, 1);

    receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, NOON + 5);
    assert.deepEqual((await run(true)).status, 'done', '--send skips the throttle');
    assert.equal(bodies.length, 2);
    assert.equal(JSON.parse(bodies[1]).counts.allowed, 3, 'a resend carries the day total, not a delta');
    const mode = statSync(statePath).mode & 0o777;
    if (process.platform !== 'win32') assert.equal(mode, 0o600);
  });

  it('sends an earlier day whose totals changed, at most 3 days a run', async () => {
    const dir = tmp();
    const log = join(dir, 'r.jsonl');
    for (let d = 1; d <= 5; d++) receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, NOON - d * 86_400_000);
    const { fetchImpl, bodies } = fetchCounting();
    await runHeartbeat({ apiUrl: 'https://pp.test', mode: 'enforce', client: 'mcp-proxy', receiptsPath: log, statePath: join(dir, 's.json'), token: TOKEN, fetchImpl, now: () => NOON });
    assert.deepEqual(bodies.map((b) => JSON.parse(b).day), [utcDay(NOON), addDays(utcDay(NOON), -1), addDays(utcDay(NOON), -2)]);
  });

  it('no install token: nothing is sent', async () => {
    const { fetchImpl, bodies } = fetchCounting();
    const dir = tmp();
    const saved = { ...process.env };
    try {
      delete process.env.PP_INSTALL_TOKEN;
      process.env.PP_KEYS_DIR = join(dir, 'keys');
      process.env.MCP_GUARD_TOKEN_STORE = 'file';
      const r = await runHeartbeat({ apiUrl: 'https://pp.test', mode: 'enforce', client: 'mcp-proxy', receiptsPath: join(dir, 'r.jsonl'), statePath: join(dir, 's.json'), fetchImpl });
      assert.deepEqual(r, { status: 'skipped', reason: 'no_token' });
    } finally {
      process.env = saved;
    }
    assert.equal(bodies.length, 0);
  });

  it('a held lock skips the run; a stale lock is taken over', async () => {
    const dir = tmp();
    const statePath = join(dir, 's.json');
    const release = acquireLock(statePath)!;
    const { fetchImpl, bodies } = fetchCounting();
    const opts = { apiUrl: 'https://pp.test', mode: 'enforce' as const, client: 'mcp-proxy' as const, receiptsPath: join(dir, 'r.jsonl'), statePath, token: TOKEN, fetchImpl };
    assert.deepEqual(await runHeartbeat(opts), { status: 'skipped', reason: 'locked' });
    assert.equal(await runHeartbeat({ ...opts, now: () => Date.now() + 10 * 60_000 }).then((r) => r.status), 'done');
    release();
    assert.equal(bodies.length, 1);
  });

  it('parallel sender processes send one heartbeat, and leave valid state', async () => {
    const stand = await standIn();
    try {
      const dir = tmp();
      const log = join(dir, 'r.jsonl');
      fullLog(log);
      const env = { ...process.env, PP_KEYS_DIR: join(dir, 'keys'), PP_INSTALL_TOKEN: TOKEN, MCP_GUARD_TOKEN_STORE: 'file' };
      const procs = Array.from({ length: 6 }, () => new Promise<number | null>((resolve) => {
        const p = spawn('node', [CLI, 'heartbeat', '--background', '--client', 'mcp-proxy', '--api-url', stand.url, '--mode', 'enforce', '--receipts', log], { env, stdio: 'ignore' });
        p.on('close', resolve);
      }));
      assert.deepEqual(await Promise.all(procs), [0, 0, 0, 0, 0, 0]);
      assert.equal(stand.hits.length, 1);
      assert.equal(stand.hits[0].path, '/api/mcp/heartbeat');
      assert.equal(stand.hits[0].auth, `Bearer ${TOKEN}`);
      assert.deepEqual(stand.hits[0].body.counts, FULL);
      const state = loadState(join(dir, 'heartbeat-state.json'));
      assert.equal(state.logs.length, 1);
      assert.ok(!existsSync(join(dir, 'heartbeat-state.json.lock')));
    } finally {
      await stand.close();
    }
  });

  it('every server error is absorbed: no throw, no retry, a back-off where the contract asks', async () => {
    const stand = await standIn();
    try {
      for (const [status, backoff] of [[401, REFUSED_BACKOFF_MS], [400, REFUSED_BACKOFF_MS], [413, REFUSED_BACKOFF_MS], [429, 120_000], [503, 0]] as const) {
        const dir = tmp();
        const statePath = join(dir, 's.json');
        stand.mode = { status, retryAfter: status === 429 ? '120' : undefined };
        const before = stand.hits.length;
        const r = await runHeartbeat({ apiUrl: stand.url, mode: 'enforce', client: 'mcp-proxy', receiptsPath: join(dir, 'r.jsonl'), statePath, token: TOKEN, now: () => NOON });
        assert.deepEqual(r, { status: 'done', sent: [], failed: { day: utcDay(NOON), code: `HTTP_${status}` } });
        assert.equal(stand.hits.length - before, 1, 'one request, no retry');
        assert.equal(loadState(statePath).nextAllowedAt, backoff ? NOON + backoff : 0);
      }
      stand.mode = { status: 200, hang: true };
      const t0 = Date.now();
      assert.deepEqual(await postHeartbeat(stand.url, TOKEN, '{}', { timeoutMs: 300 }), { ok: false, code: 'TIMEOUT' });
      assert.ok(Date.now() - t0 < 3000);
    } finally {
      await stand.close();
    }
    const closed = await standIn();
    const url = closed.url;
    await closed.close();
    assert.deepEqual(await postHeartbeat(url, TOKEN, '{}'), { ok: false, code: 'UNREACHABLE' });
  });
});

describe('heartbeat: opt-out and preconditions', () => {
  it('the policy key: cloud.heartbeat true or false only', () => {
    const on = parseConfig(policy('http://127.0.0.1:1'));
    assert.equal(on.cloud!.heartbeat, undefined);
    assert.equal(heartbeatDisabledReason(on, {}), null);
    const off = parseConfig(policy('http://127.0.0.1:1', '  heartbeat: false\n'));
    assert.equal(off.cloud!.heartbeat, false);
    assert.match(heartbeatDisabledReason(off, {})!, /cloud.heartbeat: false/);
    assert.throws(() => parseConfig(policy('http://127.0.0.1:1', '  heartbeat: "off"\n')), /cloud.heartbeat: must be true or false/);
    assert.throws(() => parseConfig(policy('https://app.permissionprotocol.com', '  heartbeatz: false\n').replace(/  trust_keys:\n.*\n/, '')), /Unknown cloud key/);
    assert.match(heartbeatDisabledReason(parseConfig(policy(null)), {})!, /no cloud/);
    for (const v of ['off', '0', 'false', 'OFF', ' False ']) assert.match(heartbeatDisabledReason(on, { MCP_GUARD_HEARTBEAT: v })!, /MCP_GUARD_HEARTBEAT/);
    assert.equal(heartbeatDisabledReason(on, { MCP_GUARD_HEARTBEAT: 'on' }), null);
  });

  it('the hook starts no sender when off, without cloud, or when not due', () => {
    const dir = tmp();
    const spawned: string[][] = [];
    const fakeSpawn = ((_c: string, args: string[]) => { spawned.push(args); const e = new EventEmitter() as any; e.unref = () => undefined; return e; }) as any;
    const write = (name: string, text: string): string => { const p = join(dir, name); writeFileSync(p, text); return p; };
    const statePath = join(dir, 's.json');
    const deps = { spawn: fakeSpawn, statePath, env: {} as NodeJS.ProcessEnv };
    heartbeatAfterHook(['--config', write('none.yaml', policy(null))], deps);
    heartbeatAfterHook(['--config', write('off.yaml', policy('http://127.0.0.1:1', '  heartbeat: false\n'))], deps);
    heartbeatAfterHook(['--config', write('on.yaml', policy('http://127.0.0.1:1'))], { ...deps, env: { MCP_GUARD_HEARTBEAT: 'off' } });
    heartbeatAfterHook(['--config', join(dir, 'missing.yaml')], deps);
    assert.equal(spawned.length, 0);
    heartbeatAfterHook(['--config', join(dir, 'on.yaml'), '--mode', 'observe'], deps);
    assert.equal(spawned.length, 1);
    assert.deepEqual(spawned[0].slice(1, 4), ['heartbeat', '--background', '--client']);
    assert.ok(spawned[0].includes('observe'));
    writeFileSync(statePath, JSON.stringify({ v: 1, logs: [], lastAttemptAt: Date.now(), nextAllowedAt: 0, sent: {} }));
    heartbeatAfterHook(['--config', join(dir, 'on.yaml')], deps);
    assert.equal(spawned.length, 1, 'throttled: no process started');
  });

  it('the proxy timer is off without cloud or when opted out; it copies only the fixed failure line', async () => {
    const off = parseConfig(policy('http://127.0.0.1:1', '  heartbeat: false\n'));
    assert.equal(startProxyHeartbeat(off, 'r.jsonl', { env: {} }), null);
    assert.equal(startProxyHeartbeat(parseConfig(policy(null)), 'r.jsonl', { env: {} }), null);
    const on = parseConfig(policy('http://127.0.0.1:1'));
    assert.equal(startProxyHeartbeat(on, 'r.jsonl', { env: { MCP_GUARD_HEARTBEAT: '0' } }), null);

    const children: any[] = [];
    const fakeSpawn = (() => { const c = new EventEmitter() as any; c.stderr = new EventEmitter(); c.unref = () => undefined; c.kill = () => undefined; children.push(c); return c; }) as any;
    const lines: string[] = [];
    const hb = startProxyHeartbeat(on, 'r.jsonl', { env: {}, spawn: fakeSpawn, stderr: (t) => lines.push(t), firstDelayMs: 1e9, intervalMs: 1e9 })!;
    hb.tick();
    hb.tick();
    assert.equal(children.length, 1, 'one sender at a time');
    children[0].stderr.emit('data', Buffer.from(`Authorization: Bearer ${TOKEN}\n[mcp-guard] heartbeat not sent (HTTP_503)\n${SENTINEL}\n`));
    children[0].emit('close', 0);
    assert.deepEqual(lines, ['[mcp-guard] heartbeat not sent (HTTP_503)\n']);
    hb.tick();
    assert.equal(children.length, 2);
    hb.stop();
  });

  it('CLI: --send refuses when off or without a token; --show prints the body and sends nothing', async () => {
    const stand = await standIn();
    try {
      const dir = tmp();
      const env = { ...process.env, PP_KEYS_DIR: join(dir, 'keys'), MCP_GUARD_TOKEN_STORE: 'file' } as NodeJS.ProcessEnv;
      delete env.PP_INSTALL_TOKEN;
      delete env.PP_SHARED_RECEIPTS_PATH;
      writeFileSync(join(dir, 'pp.config.yaml'), policy(stand.url));
      fullLog(join(dir, 'pp-receipts.jsonl'));
      // Asynchronous: the stand-in answers from this process.
      const cli = (args: string[], extra: NodeJS.ProcessEnv = {}) => new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => {
        const p = spawn('node', [CLI, 'heartbeat', ...args, '--config', join(dir, 'pp.config.yaml')], { env: { ...env, ...extra } });
        let stdout = '';
        let stderr = '';
        p.stdout.on('data', (d) => { stdout += d; });
        p.stderr.on('data', (d) => { stderr += d; });
        p.on('close', (status) => resolve({ status, stdout, stderr }));
      });

      const noToken = await cli(['--send']);
      assert.equal(noToken.status, 1);
      assert.match(noToken.stderr, /no install token/);
      const optedOut = await cli(['--send'], { PP_INSTALL_TOKEN: TOKEN, MCP_GUARD_HEARTBEAT: 'off' });
      assert.equal(optedOut.status, 1);
      assert.match(optedOut.stderr, /heartbeat is off: MCP_GUARD_HEARTBEAT/);

      const show = await cli(['--show'], { PP_INSTALL_TOKEN: TOKEN });
      assert.equal(show.status, 0, show.stderr);
      const body = JSON.parse(show.stdout);
      assert.deepEqual(body.counts, FULL);
      assert.equal(body.day, utcDay(Date.now()));
      assert.ok(!show.stdout.includes(SENTINEL) && !show.stderr.includes(TOKEN));
      assert.match(show.stderr, new RegExp(`Would POST to ${stand.url}/api/mcp/heartbeat \\(install token: present\\)`));
      assert.equal(stand.hits.length, 0, '--show sends nothing');
      assert.ok(!existsSync(join(dir, 'heartbeat-state.json')), '--show changes nothing');

      const send = await cli(['--send'], { PP_INSTALL_TOKEN: TOKEN });
      assert.equal(send.status, 0, send.stderr);
      assert.equal(stand.hits.length, 1);
      assert.deepEqual(stand.hits[0].body, body, '--show printed exactly what --send sent');
      assert.ok(!send.stderr.includes(TOKEN));

      stand.mode = { status: 401 };
      receipt(join(dir, 'pp-receipts.jsonl'), 'APPROVED', ['DEFAULT_ACTION'], null, Date.now());
      const refused = await cli(['--send'], { PP_INSTALL_TOKEN: TOKEN });
      assert.equal(refused.status, 1);
      assert.equal(refused.stderr, '[mcp-guard] heartbeat not sent (HTTP_401)\n');
    } finally {
      await stand.close();
    }
  });
});

describe('heartbeat: never touches a decision', () => {
  let dir: string;
  let preload: string;
  let netLog: string;
  before(() => {
    dir = tmp();
    netLog = join(dir, 'net.log');
    preload = join(dir, 'preload.js');
    // Records the pid of every process that opens a TCP connection.
    writeFileSync(preload, `const net = require('net'); const fs = require('fs');
const orig = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...a) { try { fs.appendFileSync(${JSON.stringify(netLog)}, process.pid + '\\n'); } catch {} return orig.apply(this, a); };
`);
  });

  const event = (tool: string, input: Record<string, unknown>): string =>
    JSON.stringify({ session_id: 's', cwd: '/tmp', permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: tool, tool_input: input, tool_use_id: 't' });

  function hook(ws: string, stdin: string, env: NodeJS.ProcessEnv = {}): Promise<{ code: number | null; stdout: string; stderr: string; ms: number; pid: number }> {
    return new Promise((resolve) => {
      const t0 = Date.now();
      const base: NodeJS.ProcessEnv = {
        ...process.env, PP_KEYS_DIR: join(ws, 'keys'), PP_INSTALL_TOKEN: TOKEN, MCP_GUARD_TOKEN_STORE: 'file', NODE_OPTIONS: `--require ${preload}`, ...env,
      };
      delete base.PP_SHARED_RECEIPTS_PATH;
      const p = spawn('node', [CLI, 'hook', '--config', join(ws, 'pp.config.yaml')], { env: base, cwd: ws });
      let stdout = '';
      let stderr = '';
      p.stdout.on('data', (d) => { stdout += d; });
      p.stderr.on('data', (d) => { stderr += d; });
      p.on('close', (code) => resolve({ code, stdout, stderr, ms: Date.now() - t0, pid: p.pid! }));
      p.stdin.end(stdin);
    });
  }
  const pids = (): string[] => (existsSync(netLog) ? readFileSync(netLog, 'utf8').trim().split('\n').filter(Boolean) : []);
  async function until(f: () => boolean, ms = 8000): Promise<boolean> {
    for (const end = Date.now() + ms; Date.now() < end; await sleep(50)) if (f()) return true;
    return f();
  }

  it('an allowed call: the hook makes no network request and exits without waiting for a server that never answers', async () => {
    const stand = await standIn();
    stand.mode = { status: 200, hang: true };
    try {
      const ws = tmp();
      writeFileSync(join(ws, 'pp.config.yaml'), policy(stand.url));
      const r = await hook(ws, event('Bash', { command: `echo ${SENTINEL}` }));
      assert.equal(r.code, 0, r.stderr);
      assert.equal(r.stdout, '');
      assert.ok(r.ms < 4000, `the hook returned in ${r.ms} ms; the sender's request timeout is 5000 ms`);
      assert.ok(await until(() => stand.hits.length === 1), 'the detached sender reached the server');
      assert.ok(!pids().includes(String(r.pid)), 'no connection from the hook process');
      assert.ok(pids().length >= 1, 'the connection came from the sender process');
      const sent = stand.hits[0];
      assert.ok(!sent.raw.includes(SENTINEL) && !sent.raw.includes('echo') && !sent.raw.includes('Bash'), 'no argument text, command or tool name');
      assert.equal(sent.body.clientLabel, 'claude-code');
      assert.deepEqual(sent.body.counts, { allowed: 1, blocked: 0, held: 0, approved: 0, denied: 0, expired: 0 });
      const state = readFileSync(join(ws, 'heartbeat-state.json'), 'utf8');
      assert.ok(!state.includes(SENTINEL) && !state.includes(TOKEN), 'the state file holds counts, not arguments or the token');

      // Within the throttle: the next hook run starts nothing.
      const before = pids().length;
      const again = await hook(ws, event('Bash', { command: 'ls' }));
      assert.equal(again.code, 0);
      await sleep(500);
      assert.equal(pids().length, before);
      assert.equal(stand.connections, 1);
    } finally {
      await stand.close();
    }
  });

  it('server errors, timeouts and refused connections never change a hook decision or exit code', async () => {
    const stand = await standIn();
    const refused = await standIn();
    const refusedUrl = refused.url;
    await refused.close();
    try {
      const modes: [string, Stand['mode'] | null][] = [
        ['401', { status: 401 }], ['400', { status: 400 }], ['413', { status: 413 }], ['429', { status: 429, retryAfter: '30' }],
        ['503', { status: 503 }], ['timeout', { status: 200, hang: true }], ['refused', null],
      ];
      for (const [name, mode] of modes) {
        const ws = tmp();
        writeFileSync(join(ws, 'pp.config.yaml'), policy(mode ? stand.url : refusedUrl));
        if (mode) stand.mode = mode;
        const allowed = await hook(ws, event('Bash', { command: `echo ${SENTINEL}` }));
        const blocked = await hook(ws, event('Write', { file_path: '/tmp/x', content: SENTINEL }));
        const offWs = tmp();
        writeFileSync(join(offWs, 'pp.config.yaml'), policy(mode ? stand.url : refusedUrl));
        const blockedOff = await hook(offWs, event('Write', { file_path: '/tmp/x', content: SENTINEL }), { MCP_GUARD_HEARTBEAT: 'off' });
        assert.equal(allowed.code, 0, `${name}: allowed`);
        assert.equal(allowed.stdout, '', name);
        assert.equal(blocked.code, 2, `${name}: blocked`);
        assert.equal(blocked.stdout, blockedOff.stdout, `${name}: the same answer as with the heartbeat off`);
        assert.equal(blocked.stderr, blockedOff.stderr, name);
        assert.ok(allowed.ms < 4000 && blocked.ms < 4000, `${name}: no wait`);
      }
    } finally {
      await stand.close();
    }
  });

});

describe('heartbeat: privacy', () => {
  it('nothing from a tool call reaches the body, whatever the arguments hold', async () => {
    const dir = tmp();
    const log = join(dir, 'r.jsonl');
    receipt(log, 'APPROVED', ['DEFAULT_ACTION'], null, NOON);
    emitHold({ id: null, method: 'tools/call', tool: SENTINEL, agentId: SENTINEL, ruleId: `${SENTINEL} /etc/passwd`, inputHash: 'sha256:0', createdAt: iso(NOON) }, log);
    emitCloudDecision({ decision: 'denied', requestId: SENTINEL, receiptId: SENTINEL, receiptUrl: `https://x/${SENTINEL}`, fingerprint: SENTINEL, method: 'tools/call', tool: SENTINEL, server: SENTINEL, agentId: SENTINEL, ruleId: SENTINEL, decider: { id: SENTINEL, display: SENTINEL, authMethod: null }, reason: SENTINEL, code: null, at: iso(NOON), artifact: { x: SENTINEL } }, log);
    const { fetchImpl, bodies } = fetchCounting();
    await runHeartbeat({ apiUrl: 'https://pp.test', mode: 'enforce', client: 'claude-code', receiptsPath: log, statePath: join(dir, 's.json'), token: TOKEN, fetchImpl, now: () => NOON });
    assert.equal(bodies.length, 1);
    const body = JSON.parse(bodies[0]);
    // The sentinel is a valid rule id, so it is the one field it can reach: a rule id the policy author wrote.
    assert.deepEqual(body.topRules, [{ ruleId: SENTINEL, count: 1 }]);
    const withoutRules = JSON.stringify({ ...body, topRules: undefined });
    assert.ok(!withoutRules.includes(SENTINEL));
    assert.ok(!bodies[0].includes('/etc/passwd'));
    assert.deepEqual(Object.keys(body.counts), [...COUNT_NAMES]);
    assert.ok(!readFileSync(join(dir, 's.json'), 'utf8').includes('/etc/passwd'));
  });
});
