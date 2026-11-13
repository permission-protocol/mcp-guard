import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fingerprintOfCall } from '../cloud/fingerprint.js';
import { pinsFor } from '../cloud/pinned-keys.js';
import { verifyCloudReceipt } from '../cloud/verify.js';
import { startFakePp, type FakePp } from './cloud-helpers.js';

/**
 * `mcp-guard hook` through the real CLI: one Claude Code PreToolUse event on stdin, the
 * answer on stdout / stderr / exit code, receipts in the shared log, and a local
 * stand-in for Permission Protocol for held calls.
 */

const CLI = join(__dirname, '..', 'cli.js');
const TOKEN = `pp_test_${'hook'.repeat(8)}`;
const SENTINEL = 'SENTINEL_9f3c_do_not_log';

interface Run { code: number | null; stdout: string; stderr: string; json: any }

function workspace(policyText: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-hook-'));
  writeFileSync(join(dir, 'pp.config.yaml'), policyText);
  assert.equal(spawnSync('node', [CLI, 'keys', 'init'], { env: { ...process.env, PP_KEYS_DIR: join(dir, 'keys') } }).status, 0);
  return dir;
}

function runHook(dir: string, stdin: string, extra: string[] = [], env: Record<string, string | undefined> = {}): Promise<Run> {
  const base: NodeJS.ProcessEnv = {
    ...process.env,
    PP_KEYS_DIR: join(dir, 'keys'),
    PP_SHARED_RECEIPTS_PATH: join(dir, 'receipts.jsonl'),
    PP_INSTALL_TOKEN: TOKEN,
    MCP_GUARD_TOKEN_STORE: 'file',
    ...env,
  };
  for (const [k, v] of Object.entries(env)) if (v === undefined) delete base[k];
  return new Promise((resolve) => {
    const proc = spawn('node', [CLI, 'hook', '--config', join(dir, 'pp.config.yaml'), ...extra], { env: base, cwd: dir });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => { stdout += d; });
    proc.stderr.on('data', (d) => { stderr += d; });
    proc.on('close', (code) => {
      let json: any = null;
      try { json = stdout.trim() ? JSON.parse(stdout) : null; } catch { json = 'unparseable'; }
      resolve({ code, stdout, stderr, json });
    });
    proc.stdin.end(stdin);
  });
}

const event = (tool: string, input: Record<string, unknown>): string =>
  JSON.stringify({ session_id: 's1', cwd: '/tmp', permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: tool, tool_input: input, tool_use_id: 'toolu_1' });
const bash = (command: string): string => event('Bash', { command, description: 'model-written description', timeout: 120000, run_in_background: false });

const logText = (dir: string): string => (existsSync(join(dir, 'receipts.jsonl')) ? readFileSync(join(dir, 'receipts.jsonl'), 'utf8') : '');
const logLines = (dir: string): any[] => logText(dir).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));

function assertDenied(r: Run, reason: RegExp): void {
  assert.equal(r.code, 2, `exit 2 blocks the call. stderr: ${r.stderr}`);
  assert.equal(r.json.hookSpecificOutput.hookEventName, 'PreToolUse');
  assert.equal(r.json.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(r.json.hookSpecificOutput.permissionDecisionReason, reason);
  assert.equal(r.stderr.trim(), r.json.hookSpecificOutput.permissionDecisionReason, 'stderr is exactly the reason');
}

const LOCAL_POLICY = `default_action: block
rules:
  - { id: no-secrets, tool: "*", detect: { detector: secret_read, args: [command, file_path] }, action: block }
  - { id: destructive-shell, tool: "*", detect: { detector: shell_destructive, args: [command] }, action: require_approval }
  - { id: bash, tool: Bash, action: allow }
  - { id: write, tool: Write, action: allow }
`;

function cloudPolicy(fake: FakePp | null, apiUrl?: string): string {
  const key = fake ? `{ key_id: ${fake.issuer.keyId}, public_key_b64: "${fake.issuer.publicKeyB64}" }` : '{ key_id: k, public_key_b64: "wJcxaKl9Mn3jXlE+JhdxmXZkcS6SyMiy7HoVMVLyF7g=" }';
  return `${LOCAL_POLICY}cloud:
  api_url: ${apiUrl ?? fake!.url}
  environment: staging
  approval_timeout_seconds: 60
  trust_keys:
    - ${key}
`;
}

describe('mcp-guard hook: policy decisions', () => {
  let dir: string;
  before(() => { dir = workspace(LOCAL_POLICY); });

  it('an allowed call answers nothing (Claude Code\'s own permission flow still runs) and logs a signed receipt', async () => {
    const r = await runHook(dir, bash('ls -la'));
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    const receipt = logLines(dir).at(-1);
    assert.equal(receipt.record.status, 'APPROVED');
    assert.match(receipt.record.reasonCodes, /RULE_MATCHED:bash/);
    assert.ok(receipt.artifact, 'signed');
  });

  it('a blocked call is denied with exit 2, naming only the rule id and detector kind', async () => {
    const r = await runHook(dir, bash('cat ~/.aws/credentials'));
    assertDenied(r, /^mcp-guard: blocked by rule "no-secrets" \(secret_read: [a-z_]+\)\.$/);
    assert.equal(logLines(dir).at(-1).record.status, 'DENIED');
  });

  it('a held call without a cloud section is denied (local-only cannot wait for a person)', async () => {
    const r = await runHook(dir, bash('rm -rf ~/build'));
    assertDenied(r, /held by rule "destructive-shell" \(shell_destructive: [a-z_]+\) for approval \(local-only/);
    assert.ok(logLines(dir).at(-1).hold, 'recorded as a hold');
  });

  it('an unknown tool follows default_action', async () => {
    const r = await runHook(dir, event('Glob', { pattern: '**/*' }));
    assertDenied(r, /blocked by default_action "block" \(no rule matched\)/);

    const open = workspace(LOCAL_POLICY.replace('default_action: block', 'default_action: allow'));
    const r2 = await runHook(open, event('Glob', { pattern: '**/*' }));
    assert.equal(r2.code, 0);
    assert.equal(r2.stdout, '');
  });

  it('malformed stdin is denied', async () => {
    for (const input of ['not json', '[]', JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash' }), JSON.stringify({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: {} }), '']) {
      const r = await runHook(dir, input);
      assertDenied(r, /^mcp-guard: denied: HOOK_(INPUT_MALFORMED|EVENT_UNSUPPORTED)/);
    }
  });

  it('an unreadable policy denies every call, including ones it would allow', async () => {
    const broken = workspace(LOCAL_POLICY);
    writeFileSync(join(broken, 'pp.config.yaml'), 'default_action: maybe\nrules: []\n');
    assertDenied(await runHook(broken, bash('ls')), /the policy could not be loaded/);
    assertDenied(await runHook(broken, bash('ls'), ['--config', join(broken, 'missing.yaml')]), /the policy could not be loaded/);
  });

  it('a missing signing key denies in enforce mode', async () => {
    const r = await runHook(dir, bash('ls'), [], { PP_KEYS_DIR: join(dir, 'no-keys') });
    assertDenied(r, /no receipt can be signed .*keys init/);
  });

  it('observe mode lets blocked and held calls through and records them, as the proxy does', async () => {
    const r = await runHook(dir, bash('cat ~/.aws/credentials'), ['--mode', 'observe']);
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /OBSERVE: would block "Bash"/);
    const held = await runHook(dir, bash('rm -rf ~/build'), ['--mode', 'observe']);
    assert.equal(held.code, 0);
    assert.ok(logLines(dir).at(-1).hold);
  });
});

describe('mcp-guard hook: held calls and Permission Protocol', () => {
  let fake: FakePp;
  before(async () => { fake = await startFakePp(TOKEN); });
  after(async () => { await fake.close(); });

  it('hold then approve: verified, redeemed once, answered allow, logged in the proxy\'s cloud format', async () => {
    const dir = workspace(cloudPolicy(fake));
    fake.decision = 'approve';
    fake.decideAfterReads = 1;
    const redeemedBefore = fake.redeemed.length;
    const r = await runHook(dir, bash('rm -rf ~/build'));
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.json.hookSpecificOutput.permissionDecision, 'allow');
    assert.match(r.json.hookSpecificOutput.permissionDecisionReason, /released by receipt rcpt_fake_\d+, signed by Maria Signer/);
    assert.equal(fake.redeemed.length, redeemedBefore + 1);

    const create = fake.calls.filter((c) => c.method === 'POST' && c.path === '/api/mcp/approval-requests').at(-1)!;
    assert.deepEqual({ tool: create.body.tool, server: create.body.server, agentId: create.body.agentId, timeoutSec: create.body.timeoutSec }, { tool: 'Bash', server: 'claude-code', agentId: 'claude-code', timeoutSec: 60 });

    const line = logLines(dir).find((l) => l.cloud)!.cloud;
    assert.equal(line.decision, 'released');
    assert.equal(line.fingerprint, fingerprintOfCall('claude-code', 'Bash', { command: 'rm -rf ~/build' }));
    assert.equal(line.ruleId, 'destructive-shell');
    const again = verifyCloudReceipt(line.artifact, { keySet: fake.issuer.keySet, trust: pinsFor(fake.issuer.keySet), fingerprint: line.fingerprint, requestId: line.requestId, expect: 'APPROVED' });
    assert.equal(again.ok, true);
  });

  it('a rejection is denied', async () => {
    const dir = workspace(cloudPolicy(fake));
    fake.decision = 'reject';
    assertDenied(await runHook(dir, bash('rm -rf ~/dist')), /denied in Permission Protocol .*Approval was denied/);
  });

  it('a receipt that does not verify is denied and never redeemed', async () => {
    const dir = workspace(cloudPolicy(fake));
    fake.decision = 'tampered';
    const redeemedBefore = fake.redeemed.length;
    assertDenied(await runHook(dir, bash('rm -rf ~/tmp')), /not released \(RECEIPT_SIGNATURE_INVALID\)/);
    assert.equal(fake.redeemed.length, redeemedBefore);
  });

  it('hold with the wait running out is denied, says how to retry, and the retry resumes the same request', async () => {
    const dir = workspace(cloudPolicy(fake));
    fake.decision = 'approve';
    fake.decideAfterReads = 2;
    const creates = () => fake.calls.filter((c) => c.method === 'POST' && c.path === '/api/mcp/approval-requests').length;
    const before = creates();
    const first = await runHook(dir, bash('rm -rf ~/resume'), ['--wait', '1']);
    assertDenied(first, /nobody signed within the hook's 1-second wait\. Request mcpreq_\d+ stays open .*sign it at http:\/\/127\.0\.0\.1:\d+\/sign\/mcpreq_\d+.*run exactly the same call again/);
    assert.equal(logLines(dir).at(-1).cloud.decision, 'expired');

    // Same call; the model rewrote its description, which is not part of what is signed.
    const retry = await runHook(dir, event('Bash', { command: 'rm -rf ~/resume', description: 'another description' }), ['--wait', '5']);
    assert.equal(retry.code, 0, retry.stderr);
    assert.equal(retry.json.hookSpecificOutput.permissionDecision, 'allow');
    assert.equal(creates() - before, 1, 'one request, resumed');
  });

  it('hold that is never signed is denied at the wait limit', async () => {
    const dir = workspace(cloudPolicy(fake));
    fake.decision = 'never';
    assertDenied(await runHook(dir, bash('rm -rf ~/never'), ['--wait', '1']), /nobody signed within the hook's 1-second wait/);
  });

  it('hold with Permission Protocol unreachable is denied', async () => {
    const dir = workspace(cloudPolicy(null, 'http://127.0.0.1:9'));
    const r = await runHook(dir, bash('rm -rf ~/build'));
    assertDenied(r, /not released \(API_UNREACHABLE\)/);
    assert.equal(logLines(dir).at(-1).cloud.decision, 'blocked');
  });

  it('hold with no install token is denied; allowed calls still need no token or network', async () => {
    const dir = workspace(cloudPolicy(null, 'http://127.0.0.1:9'));
    assertDenied(await runHook(dir, bash('rm -rf ~/build'), [], { PP_INSTALL_TOKEN: undefined }), /cloud approvals are not available \(INSTALL_TOKEN_MISSING\)/);
    const allowed = await runHook(dir, bash('ls'), [], { PP_INSTALL_TOKEN: undefined });
    assert.equal(allowed.code, 0);
    assert.equal(allowed.stdout, '');
  });

  it('argument text never reaches the log, stderr or the reason', async () => {
    const dir = workspace(cloudPolicy(fake));
    fake.decision = 'approve';
    fake.decideAfterReads = 1;
    const runs = [
      await runHook(dir, bash(`echo ${SENTINEL}`)),                       // allowed
      await runHook(dir, bash(`cat ~/.ssh/id_rsa ${SENTINEL}`)),          // blocked
      await runHook(dir, bash(`rm -rf ~/${SENTINEL}`)),                   // held, approved
      await runHook(dir, event('Write', { file_path: `/tmp/${SENTINEL}`, content: SENTINEL })),
      await runHook(dir, bash(`rm -rf ~/${SENTINEL}`), ['--mode', 'observe']),
    ];
    fake.decision = 'reject';
    runs.push(await runHook(dir, bash(`rm -rf ~/${SENTINEL}-2`)));
    for (const r of runs) {
      assert.doesNotMatch(r.stdout, new RegExp(SENTINEL));
      assert.doesNotMatch(r.stderr, new RegExp(SENTINEL));
    }
    assert.ok(logLines(dir).length >= 6);
    assert.doesNotMatch(logText(dir), new RegExp(SENTINEL));
  });
});

describe('mcp-guard hook install / uninstall', () => {
  const install = (dir: string, ...args: string[]) => spawnSync('node', [CLI, 'hook', 'install', '--project', dir, ...args], { encoding: 'utf8' });
  const uninstall = (dir: string) => spawnSync('node', [CLI, 'hook', 'uninstall', '--project', dir], { encoding: 'utf8' });
  const settings = (dir: string) => JSON.parse(readFileSync(join(dir, '.claude', 'settings.json'), 'utf8'));

  it('creates the settings file with one PreToolUse entry', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-install-'));
    const r = install(dir);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /added the PreToolUse hook for "Bash\|PowerShell\|Write\|Edit\|NotebookEdit"/);
    assert.deepEqual(settings(dir), {
      hooks: {
        PreToolUse: [{
          matcher: 'Bash|PowerShell|Write|Edit|NotebookEdit',
          hooks: [{
            type: 'command',
            command: 'npx --no-install mcp-guard hook --config "${CLAUDE_PROJECT_DIR}"/pp.config.yaml --wait 240',
            timeout: 300,
            onFailure: 'block',
            statusMessage: 'mcp-guard: checking policy (a held call waits for a Permission Protocol signature)',
          }],
        }],
      },
    });
  });

  it('is idempotent and preserves every existing key and hook', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-install-'));
    mkdirSync(join(dir, '.claude'));
    const existing = {
      permissions: { allow: ['Bash(npm test)'], deny: ['Read(./.env)'] },
      env: { FOO: 'bar' },
      hooks: {
        PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: './lint-shell.sh' }] }],
        PostToolUse: [{ matcher: 'Write', hooks: [{ type: 'command', command: 'prettier --write' }] }],
      },
    };
    writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify(existing, null, 2));
    assert.equal(install(dir).status, 0);
    const once = readFileSync(join(dir, '.claude', 'settings.json'), 'utf8');
    const r = install(dir);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /already installed.*nothing changed/);
    assert.equal(readFileSync(join(dir, '.claude', 'settings.json'), 'utf8'), once, 'second install changes nothing');

    const s = settings(dir);
    assert.deepEqual(s.permissions, existing.permissions);
    assert.deepEqual(s.env, existing.env);
    assert.deepEqual(s.hooks.PostToolUse, existing.hooks.PostToolUse);
    assert.deepEqual(s.hooks.PreToolUse[0], existing.hooks.PreToolUse[0]);
    assert.equal(s.hooks.PreToolUse.length, 2);

    // A different wait replaces the guard's entry instead of adding a second one.
    const changed = install(dir, '--wait', '60');
    assert.match(changed.stdout, /replaced/);
    const s2 = settings(dir);
    assert.equal(s2.hooks.PreToolUse.length, 2);
    assert.equal(s2.hooks.PreToolUse[1].hooks[0].timeout, 120);

    // Uninstall removes only the guard's entry.
    const u = uninstall(dir);
    assert.equal(u.status, 0);
    assert.match(u.stdout, /removed 1 mcp-guard PreToolUse hook/);
    assert.deepEqual(settings(dir), existing);
    assert.match(uninstall(dir).stdout, /nothing changed/);
  });

  it('refuses a settings file that is not valid JSON and leaves it untouched', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-install-'));
    mkdirSync(join(dir, '.claude'));
    const broken = '{ "permissions": { "allow": [ } // half-edited\n';
    writeFileSync(join(dir, '.claude', 'settings.json'), broken);
    const r = install(dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /SETTINGS_INVALID_JSON: .*not valid JSON.*nothing was written/);
    assert.equal(readFileSync(join(dir, '.claude', 'settings.json'), 'utf8'), broken);
    assert.equal(uninstall(dir).status, 1);
    assert.equal(readFileSync(join(dir, '.claude', 'settings.json'), 'utf8'), broken);

    writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({ hooks: { PreToolUse: { matcher: 'Bash' } } }));
    const shape = install(dir);
    assert.equal(shape.status, 1);
    assert.match(shape.stderr, /SETTINGS_UNEXPECTED_SHAPE/);
  });
});
