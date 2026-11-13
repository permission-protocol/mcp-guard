import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fingerprintOfCall } from '../cloud/fingerprint.js';
import { pinsFor } from '../cloud/pinned-keys.js';
import { verifyCloudReceipt } from '../cloud/verify.js';
import { startFakePp, type FakePp } from './cloud-helpers.js';
import { HOOK_STATUS_MESSAGE, LAUNCH_FAILED_REASON, LAUNCHER_NOT_FOUND_REASON } from '../hook/install.js';
import { codingAgentPolicyBody } from '../presets/coding-agent.js';

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

  it('without PP_SHARED_RECEIPTS_PATH the log goes beside the policy, whatever the working directory', async () => {
    const own = workspace(LOCAL_POLICY);
    const elsewhere = mkdtempSync(join(tmpdir(), 'mcp-guard-hook-cwd-'));
    mkdirSync(join(elsewhere, 'src', 'deep'), { recursive: true });
    const r = await new Promise<number | null>((done) => {
      const env: NodeJS.ProcessEnv = { ...process.env, PP_KEYS_DIR: join(own, 'keys') };
      delete env.PP_SHARED_RECEIPTS_PATH;
      const proc = spawn('node', [CLI, 'hook', '--config', join(own, 'pp.config.yaml')], { env, cwd: join(elsewhere, 'src', 'deep') });
      proc.on('close', done);
      proc.stdin.end(bash('ls'));
    });
    assert.equal(r, 0);
    const beside = readFileSync(join(own, 'pp-receipts.jsonl'), 'utf8').trim().split('\n');
    assert.equal(beside.length, 1, 'receipt beside the policy');
    assert.equal(JSON.parse(beside[0]).record.status, 'APPROVED');
    assert.equal(existsSync(join(elsewhere, 'src', 'deep', 'pp-receipts.jsonl')), false);
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

describe('mcp-guard hook: observe-only rules (coding-agent preset)', () => {
  it('records an observed secret read, as the proxy does, and still lets the call pass', async () => {
    const dir = workspace(codingAgentPolicyBody());
    const r = await runHook(dir, bash('cat .env'));
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, '', 'no decision: the outcome is what it would be without the rule');
    assert.match(r.stderr, /OBSERVE: Matched rule "secret-read" \(secret_read: \w+\) would hold "Bash"; not enforced \(observe: true\)/);
    const lines = logLines(dir);
    const observed = lines.find((l) => l.observed)?.observed;
    assert.ok(observed, 'an observed line is written');
    assert.equal(observed.ruleId, 'secret-read');
    assert.equal(observed.would, 'held_for_approval');
    assert.equal(observed.detector, 'secret_read');
    assert.equal(observed.tool, 'Bash');
    assert.equal(observed.agentId, 'claude-code');
    assert.match(observed.inputHash, /^sha256:/);
    assert.deepEqual(Object.keys(observed).sort(), ['agentId', 'at', 'detector', 'inputHash', 'kind', 'method', 'parsed', 'reason', 'ruleId', 'tool', 'would']);
    // The policy decision is unchanged: allowed, signed, no rule.
    const receipt = lines.find((l) => l.record)?.record;
    assert.equal(receipt.status, 'APPROVED');
  });

  it('a destructive call is still held when an observe rule also matched', async () => {
    const dir = workspace(codingAgentPolicyBody());
    const r = await runHook(dir, bash('cat .env && rm -rf ~/build'));
    assert.equal(r.code, 2);
    assert.match(r.json.hookSpecificOutput.permissionDecisionReason, /held by rule "destructive-shell"/);
  });

  it('argument text never reaches the log or stderr in the observed path', async () => {
    const dir = workspace(codingAgentPolicyBody());
    const runs = [
      await runHook(dir, bash(`cat ~/${SENTINEL}/.env`)),
      await runHook(dir, bash(`cat ~/.aws/credentials # ${SENTINEL}`)),
      await runHook(dir, event('Read', { file_path: `/home/u/${SENTINEL}/.env` })),
      await runHook(dir, bash(`cat ~/${SENTINEL}/.env`), ['--mode', 'observe']),
    ];
    for (const r of runs) {
      assert.equal(r.code, 0, r.stderr);
      assert.doesNotMatch(r.stdout, new RegExp(SENTINEL));
      assert.doesNotMatch(r.stderr, new RegExp(SENTINEL));
    }
    assert.equal(logLines(dir).filter((l) => l.observed).length, runs.length, 'every run recorded its observed match');
    assert.doesNotMatch(logText(dir), new RegExp(SENTINEL));
    assert.doesNotMatch(logText(dir), /\.aws|credentials|\.env/);
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
    // On an allow the reason reaches only the debug log: Claude gets additionalContext, the person systemMessage.
    // The fake's receipt link is http, not an https page of the configured API, so the verified receipt id is named.
    assert.match(r.json.hookSpecificOutput.additionalContext, /^Approved by Maria Signer through Permission Protocol\. Receipt: rcpt_fake_\d+$/);
    assert.match(r.json.systemMessage, /^mcp-guard: Approved by Maria Signer through Permission Protocol\./);
    assert.equal(fake.redeemed.length, redeemedBefore + 1);

    const create = fake.calls.filter((c) => c.method === 'POST' && c.path === '/api/mcp/approval-requests').at(-1)!;
    assert.deepEqual({ tool: create.body.tool, server: create.body.server, agentId: create.body.agentId, timeoutSec: create.body.timeoutSec }, { tool: 'Bash', server: 'claude-code', agentId: 'claude-code', timeoutSec: 60 });
    // Exactly the 0.5.0 body: no new field can reach Permission Protocol by accident.
    assert.deepEqual(Object.keys(create.body).sort(), ['agentId', 'argsHash', 'argsPreview', 'env', 'server', 'timeoutSec', 'tool']);

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
    // The person sees the link too, and that the same call can be retried after a signature.
    assert.match(first.json.systemMessage, /still waiting for a signature\. After someone signs, the same call can be retried\. Signing link: http:\/\/127\.0\.0\.1:\d+\/sign\/mcpreq_\d+$/);

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
            command: 'npx --no-install mcp-guard hook --config "${CLAUDE_PROJECT_DIR}"/pp.config.yaml --wait 240; c=$?; case $c in 0|2) exit $c;; '
              + `127) echo '${LAUNCHER_NOT_FOUND_REASON}' >&2; exit 2;; esac; echo '${LAUNCH_FAILED_REASON}' >&2; exit 2`,
            timeout: 300,
            onFailure: 'block',
            statusMessage: 'mcp-guard: checking this call. A held call waits here until a named person signs it.',
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

describe('installed hook command: fail closed on any exit but 0 and 2', () => {
  // The command Claude Code runs in shell form (sh -c on macOS and Linux), with a stand-in launcher.
  const run = (launcher: string, env: Record<string, string> = {}) => {
    const project = mkdtempSync(join(tmpdir(), 'mcp-guard-wrap-'));
    assert.equal(spawnSync('node', [CLI, 'hook', 'install', '--project', project, '--launcher', launcher]).status, 0);
    const { command } = JSON.parse(readFileSync(join(project, '.claude', 'settings.json'), 'utf8')).hooks.PreToolUse[0].hooks[0];
    return spawnSync('sh', ['-c', command], { input: bash('ls'), encoding: 'utf8', env: { ...process.env, CLAUDE_PROJECT_DIR: project, ...env } });
  };
  const fake = (): string => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-fake-'));
    const path = join(dir, 'fake-mcp-guard');
    writeFileSync(path, '#!/bin/sh\nprintf "%s" "$FAKE_STDOUT"\n[ -n "$FAKE_STDERR" ] && printf "%s" "$FAKE_STDERR" >&2\nexit "$FAKE_CODE"\n');
    chmodSync(path, 0o755);
    return path;
  };

  it('launcher not found (exit 127) exits 2 with its own fixed reason: not on the PATH Claude Code gave the hook, how to remove it', () => {
    for (const launcher of ['/nonexistent/dir/mcp-guard', 'mcp-guard-launcher-that-is-not-on-path']) {
      const r = run(launcher);
      assert.equal(r.status, 2, launcher);
      assert.equal(r.stdout, '');
      assert.ok(r.stderr.includes(LAUNCHER_NOT_FOUND_REASON), r.stderr);
      assert.equal(r.stderr.includes(LAUNCH_FAILED_REASON), false, 'not the reinstall advice, which does not fix a PATH');
    }
    const r = run(fake(), { FAKE_CODE: '127', FAKE_STDOUT: '' });
    assert.equal(r.status, 2);
    assert.ok(r.stderr.includes(LAUNCHER_NOT_FOUND_REASON));
    assert.match(LAUNCHER_NOT_FOUND_REASON, /PATH Claude Code gave this hook/);
    assert.match(LAUNCHER_NOT_FOUND_REASON, /hooks\.PreToolUse in \.claude\/settings\.json/);
    assert.equal(LAUNCHER_NOT_FOUND_REASON.includes("'"), false, 'safe inside single quotes');
    assert.ok(HOOK_STATUS_MESSAGE.length <= 90);
  });

  it('launcher exiting 1 (or any other code) exits 2', () => {
    for (const code of ['1', '3', '126', '137']) {
      const r = run(fake(), { FAKE_CODE: code, FAKE_STDOUT: '' });
      assert.equal(r.status, 2, `exit ${code}`);
      assert.ok(r.stderr.includes(LAUNCH_FAILED_REASON));
    }
  });

  it('exit 0 and exit 2 pass through with stdout and stderr untouched', () => {
    const allow = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"x"}}\n';
    const ok = run(fake(), { FAKE_CODE: '0', FAKE_STDOUT: allow });
    assert.equal(ok.status, 0);
    assert.equal(ok.stdout, allow);
    assert.equal(ok.stderr, '');
    const denied = run(fake(), { FAKE_CODE: '2', FAKE_STDOUT: '{"d":1}\n', FAKE_STDERR: 'mcp-guard: blocked by rule "x".\n' });
    assert.equal(denied.status, 2);
    assert.equal(denied.stdout, '{"d":1}\n');
    assert.equal(denied.stderr, 'mcp-guard: blocked by rule "x".\n');
  });

  it('the real guard through the wrapper: allow passes, block stays 2', () => {
    const dir = workspace(LOCAL_POLICY);
    const binDir = mkdtempSync(join(tmpdir(), 'mcp-guard-bin-'));
    const launcher = join(binDir, 'mcp-guard');
    writeFileSync(launcher, `#!/bin/sh\nexec node ${JSON.stringify(CLI)} "$@"\n`);
    chmodSync(launcher, 0o755);
    const project = mkdtempSync(join(tmpdir(), 'mcp-guard-wrap-'));
    assert.equal(spawnSync('node', [CLI, 'hook', 'install', '--project', project, '--launcher', launcher, '--config', join(dir, 'pp.config.yaml')]).status, 0);
    const { command } = JSON.parse(readFileSync(join(project, '.claude', 'settings.json'), 'utf8')).hooks.PreToolUse[0].hooks[0];
    const env = { ...process.env, CLAUDE_PROJECT_DIR: project, PP_KEYS_DIR: join(dir, 'keys'), PP_SHARED_RECEIPTS_PATH: join(dir, 'receipts.jsonl') };
    const allowed = spawnSync('sh', ['-c', command], { input: bash('ls'), encoding: 'utf8', env });
    assert.equal(allowed.status, 0);
    assert.equal(allowed.stdout, '');
    const blocked = spawnSync('sh', ['-c', command], { input: bash('cat ~/.aws/credentials'), encoding: 'utf8', env });
    assert.equal(blocked.status, 2);
    assert.equal(JSON.parse(blocked.stdout).hookSpecificOutput.permissionDecision, 'deny');
    assert.doesNotMatch(blocked.stderr, /did not run/);
    // Re-install is still idempotent and uninstall still finds the wrapped entry.
    assert.match(spawnSync('node', [CLI, 'hook', 'install', '--project', project, '--launcher', launcher, '--config', join(dir, 'pp.config.yaml')], { encoding: 'utf8' }).stdout, /nothing changed/);
    assert.match(spawnSync('node', [CLI, 'hook', 'uninstall', '--project', project], { encoding: 'utf8' }).stdout, /removed 1/);
  });
});
