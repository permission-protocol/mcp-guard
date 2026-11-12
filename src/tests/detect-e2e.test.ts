import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * End to end through the built CLI: detect rules decide on arguments, and the argument
 * text a detector found never lands in the receipt log, stderr or a client error.
 */

const CLI = join(__dirname, '..', 'cli.js');
const ECHO = join(__dirname, 'fixtures-echo-server.js');
const SENTINEL_PATH = '/srv/customer-data-SENTINEL-91c2';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const POLICY = `
default_action: allow
rules:
  - id: block-destructive-shell
    tool: "*"
    detect: { detector: shell_destructive, args: [command] }
    action: block
  - id: block-drop
    tool: run_sql
    detect: { detector: sql_destructive, args: [sql] }
    action: block
`;

describe('detect rules end to end', () => {
  let dir: string;
  let guard: ChildProcess;
  let stderr = '';
  const responses = new Map<unknown, any>();
  const env = () => ({
    ...process.env,
    PP_KEYS_DIR: join(dir, 'keys'),
    PP_SHARED_RECEIPTS_PATH: join(dir, 'receipts.jsonl'),
    ECHO_LOG: join(dir, 'server.log'),
  });
  const serverLog = () => (existsSync(join(dir, 'server.log')) ? readFileSync(join(dir, 'server.log'), 'utf-8') : '');
  const receipts = () => readFileSync(join(dir, 'receipts.jsonl'), 'utf-8');
  const call = (id: number, name: string, args: Record<string, unknown>) =>
    guard.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) + '\n');

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-guard-detect-e2e-'));
    writeFileSync(join(dir, 'pp.config.yaml'), POLICY);
    const init = spawnSync('node', [CLI, 'keys', 'init'], { env: env() });
    assert.equal(init.status, 0, init.stderr?.toString());
    guard = spawn('node', [CLI, '--config', join(dir, 'pp.config.yaml'), '--agent-id', 'e2e-agent', '--', 'node', ECHO],
      { env: env(), stdio: ['pipe', 'pipe', 'pipe'] });
    guard.stderr!.on('data', (d) => { stderr += d.toString(); });
    let buf = '';
    guard.stdout!.on('data', (d) => {
      buf += d.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const m = JSON.parse(buf.slice(0, nl));
        buf = buf.slice(nl + 1);
        responses.set(m.id, m);
      }
    });
    call(1, 'bash', { command: `rm -rf ${SENTINEL_PATH}` });
    call(2, 'bash', { command: 'rm -rf node_modules' });
    call(3, 'run_sql', { sql: 'DROP TABLE customers_SENTINEL' });
    call(4, 'bash', { command: 'eval "$X"', _pp: { confidence: 100 } });
    for (let i = 0; i < 100 && responses.size < 4; i++) await sleep(50);
  });

  after(() => { guard?.kill('SIGTERM'); });

  it('blocks a destructive command on any tool and never forwards it', () => {
    assert.equal(responses.get(1)?.error?.code !== undefined, true, JSON.stringify(responses.get(1)));
    assert.match(responses.get(1).error.message, /block-destructive-shell.*shell_destructive: rm_recursive/);
    assert.equal(serverLog().includes(SENTINEL_PATH), false);
  });

  it('forwards a benign command', () => {
    assert.equal(responses.get(2)?.result?.echoed, 'tools/call');
  });

  it('blocks destructive SQL', () => {
    assert.match(responses.get(3)?.error?.message ?? '', /block-drop.*drop_table/);
  });

  it('fails safe on an unparseable command whatever _pp says', () => {
    assert.match(responses.get(4)?.error?.message ?? '', /fail-safe/);
  });

  it('argument text never reaches receipts, stderr or client errors', () => {
    const log = receipts();
    assert.ok(log.length > 0);
    for (const where of [log, stderr, JSON.stringify([...responses.values()])]) {
      assert.equal(where.includes('SENTINEL'), false);
    }
  });
});
