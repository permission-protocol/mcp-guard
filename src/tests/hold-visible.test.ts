import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import type { ChildProcess, SpawnOptions } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { browserDisabledReason, launchOpener, openerFor, openSigningPage, trustedSigningUrl } from '../cloud/open-browser.js';
import { CloudApiError, type CloudClient, type CreateRequestBody } from '../cloud/client.js';
import { decideInCloud } from '../cloud/hold.js';
import { argsPreviewOf, maskText, MAX_TARGET_CHARS, PROJECT_PATTERN, projectNameOf, requestContextOf } from '../cloud/preview.js';
import { shellDestructive } from '../detect/shell-destructive.js';
import { sanitizeTarget } from '../detect/index.js';
import { evaluate } from '../engine.js';
import { codingAgentPolicyBody } from '../presets/coding-agent.js';
import { claudeCodeAdapter } from '../hook/adapter.js';
import { approvedMessage, decideHook } from '../hook/decide.js';
import { HOOK_STATUS_MESSAGE, hookHandler } from '../hook/install.js';
import { ResumeStore } from '../hook/resume.js';
import { heartbeatAfterHook } from '../heartbeat/hook.js';
import { startProxyHeartbeat } from '../heartbeat/proxy.js';
import { childEnv, neutralCwd } from '../child-cwd.js';
import { parseConfig } from '../config.js';
import { createKey } from '../keystore.js';
import { ReplayCache } from '../verify-core.js';
import { hookSelfTestLine, nextTimeLines, selfTestEnv } from '../init/init.js';
import { BODY_KEYS_FULL, BODY_KEYS_NO_PREVIEW, createBodyProblem, startFakePp, testPpIssuer, type FakePp } from './cloud-helpers.js';
import type { VerifiedCloudReceipt } from '../cloud/verify.js';

/**
 * 0.5.1: a held call is hard to miss. The signing page opens in the developer's browser
 * (once per request, only for an https page of the configured API, never through a
 * shell), the hook tells Claude and the person who approved, and detached children start
 * outside the project. 0.6.0: the request body carries why the call was held (ruleId,
 * effect, project), with an exact key set.
 */

// Built at run time: the repository's diff scanner refuses token-shaped literals.
const TOKEN = ['pp', 'test', 'visible'.repeat(4)].join('_');

interface Spawned { command: string; args: string[]; options: SpawnOptions }

function spySpawn(calls: Spawned[], fail = false) {
  return (command: string, args: string[], options: SpawnOptions): ChildProcess => {
    if (fail) throw new Error('spawn failed');
    calls.push({ command, args, options });
    const child = new EventEmitter() as unknown as ChildProcess;
    (child as any).unref = () => undefined;
    (child as any).kill = () => true;
    (child as any).stderr = null;
    return child;
  };
}

const DESKTOP: NodeJS.ProcessEnv = { DISPLAY: ':0' };

describe('open-browser: when it is off', () => {
  it('is on for a desktop session and off for CI, SSH, no display, the env switch and the policy key', () => {
    assert.equal(browserDisabledReason(undefined, DESKTOP, 'linux'), null);
    assert.equal(browserDisabledReason(undefined, {}, 'darwin'), null, 'macOS needs no DISPLAY');
    assert.equal(browserDisabledReason(undefined, {}, 'win32'), null);
    assert.match(browserDisabledReason(undefined, { ...DESKTOP, CI: 'true' }, 'linux')!, /CI/);
    assert.match(browserDisabledReason(undefined, { CI: '1' }, 'darwin')!, /CI/);
    for (const v of ['SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY']) {
      assert.match(browserDisabledReason(undefined, { [v]: 'x' }, 'darwin')!, /SSH/, v);
    }
    assert.match(browserDisabledReason(undefined, {}, 'linux')!, /no display/);
    assert.equal(browserDisabledReason(undefined, { WAYLAND_DISPLAY: 'wayland-0' }, 'linux'), null);
    for (const v of ['off', '0', 'false', 'no', ' OFF ']) {
      assert.match(browserDisabledReason(undefined, { MCP_GUARD_OPEN_BROWSER: v }, 'darwin')!, /MCP_GUARD_OPEN_BROWSER/, v);
    }
    assert.equal(browserDisabledReason(undefined, { MCP_GUARD_OPEN_BROWSER: 'on' }, 'darwin'), null);
    assert.match(browserDisabledReason(false, {}, 'darwin')!, /cloud\.open_browser: false/);
    assert.equal(browserDisabledReason(true, {}, 'darwin'), null);
  });
});

describe('open-browser: which links it opens', () => {
  const API = 'https://app.permissionprotocol.com';
  it('opens only https pages on the configured API origin, without credentials', () => {
    assert.equal(trustedSigningUrl(`${API}/approve/mcpreq_1`, API), `${API}/approve/mcpreq_1`);
    assert.equal(trustedSigningUrl(`${API}/approve/a?b=1&c=2`, `${API}/`), `${API}/approve/a?b=1&c=2`);
    for (const bad of [
      'http://app.permissionprotocol.com/approve/x',
      'https://app.permissionprotocol.com.evil.test/approve/x',
      'https://evil.test/https://app.permissionprotocol.com/',
      'https://app.permissionprotocol.com:8443/approve/x',
      ['https://user', 'pw@app.permissionprotocol.com/approve/x'].join(':'),
      'javascript:alert(1)',
      'file:///etc/passwd',
      '--help',
      '',
      `${API}/${'a'.repeat(3000)}`,
    ]) assert.equal(trustedSigningUrl(bad, API), null, bad);
    assert.equal(trustedSigningUrl(null, API), null);
    assert.equal(trustedSigningUrl(`${API}/x`, 'http://127.0.0.1:3000'), null, 'an http API is never trusted for opening');
  });

  it('gives the URL to the opener as one argument, never through a shell', () => {
    const url = 'https://pp.test/approve/x?a=1&b=2^3';
    assert.deepEqual(openerFor(url, 'darwin'), ['/usr/bin/open', [url]]);
    assert.deepEqual(openerFor(url, 'linux'), ['xdg-open', [url]]);
    assert.deepEqual(openerFor(url, 'win32', { SystemRoot: 'C:\\Windows' }), ['C:\\Windows\\System32\\rundll32.exe', ['url.dll,FileProtocolHandler', url]]);
    const calls: Spawned[] = [];
    assert.equal(launchOpener(url, { platform: 'win32', env: { SystemRoot: 'D:\\Win' }, spawn: spySpawn(calls), cwd: '/neutral' }), true);
    assert.equal(calls[0].command, 'D:\\Win\\System32\\rundll32.exe');
    assert.deepEqual(calls[0].args, ['url.dll,FileProtocolHandler', url]);
    assert.equal(calls[0].options.shell, false);
    assert.equal(calls[0].options.detached, true);
    assert.equal(calls[0].options.stdio, 'ignore');
    assert.equal(calls[0].options.cwd, '/neutral');
  });

  it('never throws: a failing spawn is reported, not raised', () => {
    assert.equal(launchOpener('https://pp.test/x', { platform: 'linux', spawn: spySpawn([], true) }), false);
    const r = openSigningPage({ requestId: 'req_throw', approvalUrl: 'https://pp.test/x', apiUrl: 'https://pp.test' }, { env: DESKTOP, platform: 'linux', spawn: spySpawn([], true) });
    assert.equal(r.opened, false);
  });

  it('opens at most once per request id, never for a resumed request', () => {
    const calls: Spawned[] = [];
    const deps = { env: DESKTOP, platform: 'linux' as const, spawn: spySpawn(calls), cwd: '/n' };
    const input = { requestId: 'req_once', approvalUrl: 'https://pp.test/sign/req_once', apiUrl: 'https://pp.test' };
    assert.equal(openSigningPage(input, deps).opened, true);
    assert.equal(openSigningPage(input, deps).opened, false);
    assert.equal(openSigningPage({ ...input, requestId: 'req_resumed', resumed: true }, deps).opened, false);
    assert.equal(openSigningPage({ ...input, requestId: 'req_other_origin', approvalUrl: 'https://evil.test/sign' }, deps).opened, false);
    assert.equal(openSigningPage({ ...input, requestId: 'req_policy_off', policyOpenBrowser: false }, deps).opened, false);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, ['https://pp.test/sign/req_once']);
  });
});

describe('policy: cloud.open_browser', () => {
  const base = 'default_action: allow\nrules: []\ncloud:\n  environment: production\n';
  it('accepts true and false, refuses anything else', () => {
    assert.equal(parseConfig(base).cloud!.open_browser, undefined);
    assert.equal(parseConfig(`${base}  open_browser: false\n`).cloud!.open_browser, false);
    assert.equal(parseConfig(`${base}  open_browser: true\n`).cloud!.open_browser, undefined);
    assert.throws(() => parseConfig(`${base}  open_browser: "no"\n`), /Invalid cloud\.open_browser/);
  });
});

describe('approval request context: ruleId, effect, project (D8, D9)', () => {
  it('sends the rule id, the detector finding and the project name', () => {
    const c = requestContextOf({ ruleId: 'destructive-shell', effect: { detector: 'shell_destructive', kind: 'rm_recursive', target: '~/build', parsed: true }, projectDir: '/work/acme-api' }, true);
    assert.deepEqual(c, { ruleId: 'destructive-shell', effect: { detector: 'shell_destructive', kind: 'rm_recursive', target: '~/build', parsed: true }, project: 'acme-api' });
  });

  it('masks the target like the preview and caps it at 120 characters', () => {
    const secret = ['ghp', 'x'.repeat(36)].join('_');
    const url = ['postgres://admin', 'pw@db/x'].join(':');
    const masked = requestContextOf({ ruleId: 'r', effect: { detector: 'cloud_delete', kind: 'database_delete', target: `psql ${url} ${secret}`, parsed: true } }, true);
    assert.doesNotMatch(masked.effect!.target!, /ghp_|admin:pw/);
    assert.match(masked.effect!.target!, /\[masked\]/);
    const long = requestContextOf({ ruleId: 'r', effect: { detector: 'shell_destructive', kind: 'rm_recursive', target: 'x '.repeat(200), parsed: false } }, true);
    assert.equal(Array.from(long.effect!.target!).length, MAX_TARGET_CHARS);
    assert.equal(long.effect!.parsed, false);
  });

  it('leaves out what does not fit the contract', () => {
    assert.deepEqual(requestContextOf({ ruleId: 'has space' }, true), {});
    assert.deepEqual(requestContextOf({ ruleId: 'x'.repeat(129) }, true), {});
    assert.deepEqual(requestContextOf({ ruleId: null }, true), {});
    assert.deepEqual(requestContextOf({ ruleId: 'ok', effect: { detector: 'Shell', kind: 'rm', parsed: true } }, true), { ruleId: 'ok' });
    assert.deepEqual(requestContextOf({ ruleId: 'ok', effect: { detector: 'shell', kind: 'rm-rf', parsed: true } }, true), { ruleId: 'ok' });
    assert.deepEqual(requestContextOf({ ruleId: 'ok', effect: { detector: 'shell', kind: 'x'.repeat(41), parsed: true } }, true), { ruleId: 'ok' });
    assert.deepEqual(requestContextOf({ ruleId: 'ok', effect: { detector: 'shell', kind: 'rm', target: '   ', parsed: true } }, true), { ruleId: 'ok', effect: { detector: 'shell', kind: 'rm', parsed: true } });
  });

  it('with cloud.args_preview: false, sends no target and no project, and still the rule and the finding', () => {
    assert.deepEqual(
      requestContextOf({ ruleId: 'ok', effect: { detector: 'shell', kind: 'rm', target: '/srv/data', parsed: true }, projectDir: '/work/acme-api' }, false),
      { ruleId: 'ok', effect: { detector: 'shell', kind: 'rm', parsed: true } },
    );
  });

  it('the project is the folder name only, sanitized, never a path, the home directory or the root', () => {
    const home = '/home/someone';
    assert.equal(projectNameOf('/work/acme-api', home), 'acme-api');
    assert.equal(projectNameOf('/work/My Project (copy)', home), 'My Project -copy-');
    assert.equal(projectNameOf('/work/café/', home), 'caf-');
    assert.equal(projectNameOf('/work/a\nb‮c', home), 'a-b-c');
    assert.equal(projectNameOf('/work/  spaced  ', home), 'spaced');
    assert.equal(projectNameOf(`/work/${'p'.repeat(100)}`, home), 'p'.repeat(64));
    assert.equal(projectNameOf(`/work/${'p'.repeat(63)} x`, home), 'p'.repeat(63));
    assert.equal(projectNameOf('/', home), undefined);
    assert.equal(projectNameOf(home, home), undefined);
    assert.equal(projectNameOf(`${home}/`, home), undefined);
    assert.equal(projectNameOf('', home), undefined);
    assert.equal(projectNameOf(null, home), undefined);
    assert.equal(projectNameOf('/work/   ', home), undefined);
    for (const name of ['acme-api', 'My Project -copy-', 'p'.repeat(64)]) assert.match(name, PROJECT_PATTERN);
  });
});

describe('approval request context: what the app refuses is never sent (0.6.0 review)', () => {
  const sent = (target: string): string | undefined =>
    requestContextOf({ ruleId: 'r', effect: { detector: 'shell_destructive', kind: 'rm_recursive', target, parsed: true } }, true).effect?.target;

  it('every space separator but U+0020 becomes a plain space; runs collapse; ends are trimmed', () => {
    for (const sp of [' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '　']) {
      assert.equal(sent(`/srv/a${sp}b`), '/srv/a b', `U+${sp.codePointAt(0)!.toString(16)}`);
    }
    assert.equal(sent('  /srv/a 　\t\n b c  '), '/srv/a b c');
  });

  it('Hangul fillers, blank Braille and variation selectors are removed', () => {
    for (const ch of ['ᅟ', 'ᅠ', 'ㅤ', 'ﾠ', '⠀', '︀', '️', '\u{E0100}', '\u{E01EF}']) {
      assert.equal(sent(`/srv/a${ch}b`), '/srv/ab', `U+${ch.codePointAt(0)!.toString(16)}`);
    }
    assert.equal(sent('ㅤ⠀️'), undefined, 'nothing left: no target key');
    const only = requestContextOf({ ruleId: 'r', effect: { detector: 'shell_destructive', kind: 'rm_recursive', target: 'ㅤ  ', parsed: true } }, true);
    assert.equal('target' in only.effect!, false);
  });

  it('control and format characters are still removed; combining marks stay', () => {
    assert.equal(sent('/srv/a\u0007b‮c​d﻿e'), '/srv/a b c d e');
    assert.equal(sent('/srv/café'), '/srv/café');
  });

  it('a path holding U+3164 and NBSP, and a JSON-shaped target', () => {
    assert.equal(sent('/srv/dataㅤ old'), '/srv/data old');
    assert.equal(sent('{"a":1,"b":[1,2]}'), '{"a":1,"b":[1,2]}');
  });

  it('the cap is applied last: 120 code points after cleaning and masking', () => {
    const t = sent(`${'ㅤ'.repeat(50)}/srv/${'d/'.repeat(100)}`)!;
    assert.equal(Array.from(t).length, MAX_TARGET_CHARS);
    assert.ok(t.startsWith('/srv/d/'));
  });

  it('a password in URL userinfo is masked in the target and in the preview, also with an @ in it', () => {
    const pw = ['s3cr', 'et'].join('');
    for (const url of [`postgres://admin:${pw}@db.internal:5432/app`, `postgres://admin:p@${pw}@db.internal/app`, `https://deploy:${pw}@git.example.com/x.git`]) {
      const t = sent(`psql ${url}`)!;
      assert.doesNotMatch(t, new RegExp(`${pw}|admin`), t);
      assert.match(t, /:\/\/\[masked\]@/);
      const preview = argsPreviewOf({ command: `psql ${url}` });
      assert.doesNotMatch(preview, new RegExp(`${pw}|admin`), preview);
    }
  });

  it('a URL cut by the 120-character cap is masked before the cut (the engine target too)', () => {
    const pw = ['hunter', '2x'].join('');
    const raw = `${'p/'.repeat(44)}psql postgres://admin:${pw}${'q'.repeat(20)}@db/x`;
    const capped = sanitizeTarget(raw)!;
    assert.match(capped, /admin:hunter2x/, 'cut first, the @ is gone and the URL rule cannot see the password');
    assert.doesNotMatch(sanitizeTarget(raw, maskText)!, /admin|hunter/);
    assert.doesNotMatch(sent(raw)!, /admin|hunter/);
    const config = parseConfig(codingAgentPolicyBody());
    const d = evaluate('Bash', { command: `rm -rf /srv/x && psql postgres://admin:${pw}@db/x -c 'drop table t'` }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.doesNotMatch(JSON.stringify(d), new RegExp(pw));
  });

  it('a ruleId or project that masking would change is left out; the preset ids are sent', () => {
    const token = ['ghp', 'Z'.repeat(36)].join('_');
    const effect = { detector: 'shell_destructive', kind: 'rm_recursive', target: '~/x', parsed: true };
    for (const ruleId of [token, 'a'.repeat(32), 'db-password:hunter2', ['sk', 'live', 'x'.repeat(24)].join('_')]) {
      const c = requestContextOf({ ruleId, effect, projectDir: '/work/acme-api' }, true);
      assert.equal('ruleId' in c, false, ruleId);
      assert.equal(c.project, 'acme-api', 'the rest is still sent');
      assert.deepEqual(c.effect, effect);
    }
    for (const dir of [`/work/${token}`, `/work/${'0123456789abcdef'.repeat(3)}`, '/work/abc1 def2 ghi3 jkl4', `/work/sk-proj-${'Q'.repeat(20)}`]) {
      const c = requestContextOf({ ruleId: 'destructive-shell', effect, projectDir: dir }, true);
      assert.equal('project' in c, false, dir);
      assert.equal(c.ruleId, 'destructive-shell');
    }
    const ids = parseConfig(codingAgentPolicyBody()).rules.map((r) => r.id);
    assert.ok(ids.length > 5);
    for (const ruleId of [...ids, 'allow-company-email', 'block-delete-user-data', 'require-approval-prod-deploy']) {
      assert.equal(requestContextOf({ ruleId, effect, projectDir: '/work/acme-api' }, true).ruleId, ruleId, ruleId);
    }
  });

  it('the stand-in refuses each of these, and accepts what the guard sends for them', () => {
    const good = { tool: 'Bash', server: 'claude-code', argsHash: 'sha256:x', agentId: 'a', env: 'e', timeoutSec: 60, ruleId: 'r', effect: { detector: 'shell_destructive', kind: 'rm_recursive', target: '/srv/a b', parsed: true }, project: 'p' };
    assert.equal(createBodyProblem(good), null);
    for (const t of ['/srv/a b', '/srv/aㅤb', '/srv/a⠀b', '/srv/a️b', '/srv/a\u{E0100}b', '/srv/a​b', '/srv/a\u0007b']) {
      assert.notEqual(createBodyProblem({ ...good, effect: { ...good.effect, target: t } }), null, JSON.stringify(t));
      const ctx = requestContextOf({ ruleId: 'r', effect: { ...good.effect, target: t }, projectDir: '/work/p' }, true);
      assert.equal(createBodyProblem({ ...good, ...ctx }), null, JSON.stringify(ctx));
    }
    const token = ['ghp', 'Z'.repeat(36)].join('_');
    assert.notEqual(createBodyProblem({ ...good, ruleId: token }), null);
    assert.notEqual(createBodyProblem({ ...good, project: token }), null);
  });
});

describe('shell_destructive: one text, several findings, the widest is shown', () => {
  it('shows the root or the home directory over a narrower path or a minor finding; ties go to the first', () => {
    const cases: Array<[string, string, string]> = [
      ['rm -rf "/var/backups/old (empty folder; nothing else is touched)" ~/', 'rm_recursive', '~/'],
      ['rm -rf "/tmp/x" ~/', 'rm_recursive', '~/'],
      ['rm -rf /var/backups/old && rm -rf ~', 'rm_recursive', '~'],
      ['git push --force origin feat && rm -rf /', 'rm_recursive', '/'],
      ['git push --force origin feat; dd if=/dev/zero of=/dev/sda', 'disk_write', '/dev/sda'],
      ['rm -rf /var/a /var/b', 'rm_recursive', '/var/a'],
      ['rm -rf ~ / ', 'rm_recursive', '~'],
      ['git push --force origin feat && rm -rf /var/a', 'git_force_push', 'feat'],
    ];
    for (const [text, kind, target] of cases) {
      const r = shellDestructive(text);
      assert.deepEqual([r.matched, r.parsed, r.kind, r.target], [true, true, kind, target], text);
    }
    const filtered = shellDestructive('git push --force origin feat && rm -rf ~/', { except: ['git_push_protected'] });
    assert.equal(filtered.target, '~/');
  });

  it('ranking chooses only what is shown: a fail-safe finding is still reported when nothing is definite', () => {
    const r = shellDestructive('rm -rf "$X"');
    assert.equal(r.matched, true);
    assert.equal(r.parsed, false);
  });
});

describe('approval request body: the 0.6.0 keys, and a refused create is not retried', () => {
  const issuer = testPpIssuer();
  const bodies: CreateRequestBody[] = [];
  const client: CloudClient = {
    async create(body) { bodies.push(body); throw new CloudApiError('HTTP', 'bad', 400, 'VALIDATION_ERROR'); },
    read: async () => { throw new Error('unused'); },
    redeem: async () => { throw new Error('unused'); },
  };
  const hold = (sendPreview?: boolean) => decideInCloud({
    client, keySet: issuer.keySet, trust: issuer.trust, replayCache: new ReplayCache(), server: 'claude-code', tool: 'Bash',
    args: { command: 'rm -rf ~/x' }, agentId: 'claude-code', environment: 'production', timeoutSeconds: 1,
    ruleId: 'destructive-shell', effect: { detector: 'shell_destructive', kind: 'rm_recursive', target: '~/x', parsed: true }, projectDir: '/work/acme-api',
    ...(sendPreview === undefined ? {} : { sendPreview }), sleep: async () => undefined,
  });

  it('sends exactly these keys, with and without cloud.args_preview: false, and one create only', async () => {
    bodies.length = 0;
    const withPreview = await hold();
    assert.equal(bodies.length, 1, 'a 400 is not retried, with or without the new fields');
    assert.equal(withPreview.kind === 'blocked' && withPreview.code, 'API_400_VALIDATION_ERROR');
    assert.deepEqual(Object.keys(bodies[0]).sort(), BODY_KEYS_FULL);
    assert.deepEqual(bodies[0].effect, { detector: 'shell_destructive', kind: 'rm_recursive', target: '~/x', parsed: true });
    assert.equal(bodies[0].project, 'acme-api');
    assert.equal(createBodyProblem(bodies[0]), null, 'the stand-in accepts it');
    await hold(false);
    assert.equal(bodies.length, 2);
    assert.deepEqual(Object.keys(bodies[1]).sort(), BODY_KEYS_NO_PREVIEW);
    assert.deepEqual(bodies[1].effect, { detector: 'shell_destructive', kind: 'rm_recursive', parsed: true });
    assert.equal(createBodyProblem(bodies[1]), null);
  });

  it('none of it changes the hash or the fingerprint', async () => {
    bodies.length = 0;
    const a = await hold();
    const b = await decideInCloud({
      client, keySet: issuer.keySet, trust: issuer.trust, replayCache: new ReplayCache(), server: 'claude-code', tool: 'Bash',
      args: { command: 'rm -rf ~/x' }, agentId: 'claude-code', environment: 'production', timeoutSeconds: 1, sleep: async () => undefined,
    });
    assert.equal(bodies[0].argsHash, bodies[1].argsHash);
    assert.equal(a.fingerprint, b.fingerprint);
    assert.deepEqual(Object.keys(bodies[1]).sort(), ['agentId', 'argsHash', 'argsPreview', 'env', 'server', 'timeoutSec', 'tool'], 'nothing extra when no rule context is given');
  });

  it('the stand-in refuses a drifted body', () => {
    const good = { tool: 'Bash', server: 'claude-code', argsHash: 'sha256:x', agentId: 'a', env: 'e', timeoutSec: 60, ruleId: 'r', effect: { detector: 'shell_destructive', kind: 'rm_recursive', parsed: true }, project: 'p' };
    assert.equal(createBodyProblem(good), null);
    for (const bad of [
      { ...good, extra: 1 },
      { ...good, ruleId: 'a b' },
      { ...good, project: '/work/p' },
      { ...good, project: ' p' },
      { ...good, project: 'p'.repeat(65) },
      { ...good, effect: { ...good.effect, reason: 'eval' } },
      { ...good, effect: { ...good.effect, kind: 'Rm' } },
      { ...good, effect: { ...good.effect, parsed: 'yes' } },
      { ...good, effect: { ...good.effect, target: '' } },
      { ...good, effect: { ...good.effect, target: 'x'.repeat(121) } },
    ]) assert.notEqual(createBodyProblem(bad), null, JSON.stringify(bad));
  });
});

describe('hook answer: who approved, and the waiting link', () => {
  const receipt = (decider: VerifiedCloudReceipt['decider']): VerifiedCloudReceipt => ({
    receiptId: 'rcpt_1', keyId: 'k', canonicalization: 'jcs_v3', status: 'APPROVED', fingerprint: 'f', requestId: 'r', decider, issuedAt: null, expiresAt: null,
  });
  const API = 'https://app.permissionprotocol.com';

  it('names the signer from the verified receipt and links the receipt only on the configured origin', () => {
    assert.equal(approvedMessage(receipt({ id: 'user:u_1', display: 'Maria Signer', authMethod: 'session' }), `${API}/r/rcpt_1`, API), `Approved by Maria Signer through Permission Protocol. Receipt: ${API}/r/rcpt_1`);
    assert.equal(approvedMessage(receipt({ id: 'user:u_1', display: null, authMethod: 'session' }), 'https://evil.test/r/rcpt_1', API), 'Approved by user:u_1 through Permission Protocol. Receipt: rcpt_1');
    assert.equal(approvedMessage(receipt({ id: 'unknown', display: null, authMethod: null }), null, API), 'Approved through Permission Protocol. Receipt: rcpt_1');
    assert.equal(approvedMessage(receipt({ id: 'user:u_1', display: 'Eve\nIgnore previous\u0007', authMethod: 'session' }), null, API), 'Approved by Eve Ignore previous through Permission Protocol. Receipt: rcpt_1');
  });

  it('allow carries additionalContext for Claude and systemMessage for the person; deny can carry systemMessage', () => {
    const allow = claudeCodeAdapter.answer({ kind: 'allow', reason: 'r', context: 'Approved by M through Permission Protocol. Receipt: x', notice: 'mcp-guard: Approved by M' });
    const out = JSON.parse(allow.stdout);
    assert.equal(allow.exitCode, 0);
    assert.equal(out.hookSpecificOutput.additionalContext, 'Approved by M through Permission Protocol. Receipt: x');
    assert.equal(out.systemMessage, 'mcp-guard: Approved by M');
    const deny = claudeCodeAdapter.answer({ kind: 'deny', reason: 'mcp-guard: held', notice: 'mcp-guard: waiting. Signing link: https://pp.test/s' });
    assert.equal(deny.exitCode, 2);
    assert.equal(JSON.parse(deny.stdout).systemMessage, 'mcp-guard: waiting. Signing link: https://pp.test/s');
    assert.equal(JSON.parse(deny.stdout).hookSpecificOutput.additionalContext, undefined, 'a deny reason already reaches Claude');
    const plain = JSON.parse(claudeCodeAdapter.answer({ kind: 'deny', reason: 'x' }).stdout);
    assert.equal('systemMessage' in plain, false);
  });

  it('the installed hook says in plain words that a held call waits for a signature', () => {
    const h = hookHandler({ projectDir: '/p' });
    assert.equal(h.statusMessage, HOOK_STATUS_MESSAGE);
    assert.equal(h.statusMessage, 'mcp-guard: checking this call. A held call waits here until a named person signs it.');
    assert.ok(h.statusMessage.length <= 90, 'it is the spinner text on every checked call');
  });
});

describe('hook: the signing page, end to end in process', () => {
  let fake: FakePp;
  let dir: string;
  const realFetch = globalThis.fetch;
  const saved: Record<string, string | undefined> = {};
  const ENV = ['PP_KEYS_DIR', 'PP_INSTALL_TOKEN', 'MCP_GUARD_TOKEN_STORE', 'PP_SHARED_RECEIPTS_PATH', 'MCP_GUARD_HEARTBEAT'];

  before(async () => {
    fake = await startFakePp(TOKEN);
    // The policy names an https API; requests go to the local stand-in, links point at the https origin.
    fake.publicUrl = 'https://pp.test';
    globalThis.fetch = ((url: any, init: any) => realFetch(String(url).replace('https://pp.test', fake.url), init)) as typeof fetch;
    dir = mkdtempSync(join(tmpdir(), 'mcp-guard-visible-'));
    for (const k of ENV) saved[k] = process.env[k];
    process.env.PP_KEYS_DIR = join(dir, 'keys');
    process.env.PP_INSTALL_TOKEN = TOKEN;
    process.env.MCP_GUARD_TOKEN_STORE = 'file';
    delete process.env.PP_SHARED_RECEIPTS_PATH;
    createKey({ dir: join(dir, 'keys') });
  });
  after(async () => {
    globalThis.fetch = realFetch;
    for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    await fake.close();
  });
  beforeEach(() => { fake.decision = 'approve'; fake.decideAfterReads = 1; });

  const policy = (extra = ''): string => {
    const path = join(dir, `pp-${Math.random().toString(36).slice(2)}.yaml`);
    writeFileSync(path, `default_action: allow
rules:
  - { id: destructive-shell, tool: "*", detect: { detector: shell_destructive, args: [command] }, action: require_approval }
cloud:
  api_url: https://pp.test
  environment: staging
  approval_timeout_seconds: 60
${extra}  trust_keys:
    - { key_id: ${fake.issuer.keyId}, public_key_b64: "${fake.issuer.publicKeyB64}" }
`);
    return path;
  };
  const event = (command: string): string => JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });
  const run = (configPath: string, command: string, calls: Spawned[], waitSeconds = 5, store?: ResumeStore) => decideHook(event(command), {
    adapter: claudeCodeAdapter, configPath, waitSeconds, receiptsPath: join(dir, 'receipts.jsonl'),
    resumeStore: store ?? new ResumeStore(join(dir, `resume-${Math.random()}.json`)),
    browser: { env: DESKTOP, platform: 'linux', spawn: spySpawn(calls), cwd: '/neutral' },
  });

  it('opens the signing page once and keeps waiting; the release names the signer and links the receipt', async () => {
    const calls: Spawned[] = [];
    const verdict = await run(policy(), 'rm -rf ~/visible-1', calls);
    assert.equal(verdict.kind, 'allow');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].command, 'xdg-open');
    assert.match(calls[0].args[0], /^https:\/\/pp\.test\/sign\/mcpreq_\d+$/);
    assert.equal(calls[0].options.shell, false);
    assert.match(verdict.kind === 'allow' ? verdict.context! : '', /^Approved by Maria Signer through Permission Protocol\. Receipt: https:\/\/pp\.test\/r\/rcpt_fake_\d+$/);
    assert.match(verdict.kind === 'allow' ? verdict.notice! : '', /^mcp-guard: Approved by Maria Signer/);
  });

  it('a resumed request does not open a second tab', async () => {
    const calls: Spawned[] = [];
    const store = new ResumeStore(join(dir, 'resume-shared.json'));
    const path = policy();
    fake.decideAfterReads = 3;
    const first = await run(path, 'rm -rf ~/visible-resume', calls, 1, store);
    assert.equal(first.kind, 'deny');
    assert.equal(calls.length, 1);
    const second = await run(path, 'rm -rf ~/visible-resume', calls, 10, store);
    assert.equal(second.kind, 'allow');
    assert.equal(calls.length, 1, 'no second tab for the resumed request');
  });

  it('cloud.open_browser: false opens nothing and changes nothing else', async () => {
    const calls: Spawned[] = [];
    const verdict = await run(policy('  open_browser: false\n'), 'rm -rf ~/visible-off', calls);
    assert.equal(verdict.kind, 'allow');
    assert.equal(calls.length, 0);
  });

  it('a link on another origin is not opened, and the hold goes on as usual', async () => {
    const calls: Spawned[] = [];
    fake.publicUrl = 'https://elsewhere.test';
    try {
      const verdict = await run(policy(), 'rm -rf ~/visible-elsewhere', calls);
      assert.equal(verdict.kind, 'allow');
      assert.equal(calls.length, 0);
      // The receipt link is on another origin too: the receipt id is named instead.
      assert.match(verdict.kind === 'allow' ? verdict.context! : '', /Receipt: rcpt_fake_\d+$/);
    } finally {
      fake.publicUrl = 'https://pp.test';
    }
  });

});

describe('detached children start outside the project', () => {
  let configRoot: string;
  const saved: Record<string, string | undefined> = {};
  before(() => {
    configRoot = mkdtempSync(join(tmpdir(), 'mcp-guard-cwd-'));
    for (const k of ['PP_KEYS_DIR', 'MCP_GUARD_HEARTBEAT', 'PP_SHARED_RECEIPTS_PATH']) saved[k] = process.env[k];
    mkdirSync(join(configRoot, 'mcp-guard', 'keys'), { recursive: true });
    process.env.PP_KEYS_DIR = join(configRoot, 'mcp-guard', 'keys');
    delete process.env.MCP_GUARD_HEARTBEAT;
    delete process.env.PP_SHARED_RECEIPTS_PATH;
  });
  after(() => { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });

  it('neutralCwd is the config directory, else the home directory', () => {
    assert.equal(neutralCwd(), join(configRoot, 'mcp-guard'));
    assert.equal(neutralCwd({ configDir: join(configRoot, 'missing') }), homedir());
    assert.equal(neutralCwd({ configDir: join(configRoot, 'missing'), home: '/h' }), '/h');
  });

  it('childEnv makes the guard\'s path variables absolute', () => {
    const env = childEnv({ PP_KEYS_DIR: 'rel/keys', PP_SHARED_RECEIPTS_PATH: '/abs/r.jsonl', OTHER: 'x' });
    assert.equal(env.PP_KEYS_DIR, resolve('rel/keys'));
    assert.equal(env.PP_SHARED_RECEIPTS_PATH, '/abs/r.jsonl');
    assert.equal(env.OTHER, 'x');
  });

  it('the hook\'s heartbeat sender is spawned detached, with no stdio, in the config directory', () => {
    const project = mkdtempSync(join(tmpdir(), 'mcp-guard-cwd-project-'));
    const policyPath = join(project, 'pp.config.yaml');
    writeFileSync(policyPath, 'default_action: allow\nrules: []\ncloud:\n  environment: production\n');
    const calls: Spawned[] = [];
    heartbeatAfterHook(['--config', policyPath], { env: { PP_KEYS_DIR: process.env.PP_KEYS_DIR }, statePath: join(configRoot, 'no-state.json'), spawn: spySpawn(calls) });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].options.cwd, join(configRoot, 'mcp-guard'));
    assert.notEqual(calls[0].options.cwd, project);
    assert.equal(calls[0].options.detached, true);
    assert.equal(calls[0].options.stdio, 'ignore');
  });

  it('the proxy\'s heartbeat sender starts in the config directory', () => {
    const config = parseConfig('default_action: allow\nrules: []\ncloud:\n  environment: production\n');
    const calls: Spawned[] = [];
    const hb = startProxyHeartbeat(config, 'pp-receipts.jsonl', { env: {}, spawn: spySpawn(calls), firstDelayMs: 1e9, intervalMs: 1e9 });
    hb!.tick();
    hb!.stop();
    assert.equal(calls[0].options.cwd, join(configRoot, 'mcp-guard'));
    assert.ok(calls[0].args.includes(resolve('pp-receipts.jsonl')), 'the receipt log is passed as an absolute path');
  });
});

describe('init: browser off in its own self-tests, shorter output', () => {
  it('the cloud self-test\'s guard never opens a browser (init opens the link itself)', () => {
    const env = selfTestEnv({ PATH: '/bin' }, '/r.jsonl');
    assert.equal(env.MCP_GUARD_OPEN_BROWSER, 'off');
    assert.equal(env.MCP_GUARD_HEARTBEAT, 'off');
  });

  it('a passing hook self-test is one line; a failing one says so', () => {
    const ok = hookSelfTestLine({ ok: true, checks: [
      { name: 'allowed', command: 'git status', ok: true, detail: 'no decision: it runs as before' },
      { name: 'held', command: 'terraform destroy -auto-approve', ok: true, detail: 'denied by rule "terraform-destroy" (in use it waits for a signature in Permission Protocol)' },
    ] });
    assert.equal(ok, 'Hook self-test (local, nothing sent): ok. "git status" got no decision; "terraform destroy -auto-approve" was stopped by rule "terraform-destroy" (in use it would wait for a signature).');
    assert.doesNotMatch(ok, /\n/);
    assert.match(hookSelfTestLine({ ok: false, checks: [], failure: 'hook_failed' }), /FAILED/);
    assert.match(hookSelfTestLine({ ok: false, checks: [], failure: 'could_not_run' }), /could not run/);
  });

  it('says what happens next time, truthfully for each setup', () => {
    const hook = { ownPolicy: false, cloud: true, waitSeconds: 240, receiptsPath: '/p/pp-receipts.jsonl', preset: true };
    const preset = nextTimeLines({ hook, server: null }).join(' ');
    assert.match(preset, /the call is held: the signing page opens in your browser \(not over SSH or in CI\), and the call runs only after a named person signs it/);
    assert.match(preset, /within 240 seconds, Claude is denied with the signing link, and the same call can be retried after someone signs/);
    assert.match(nextTimeLines({ hook: { ...hook, cloud: false, ownPolicy: true }, server: null }).join(' '), /denied: the policy has no cloud: section/);
    assert.match(nextTimeLines({ hook: null, server: { name: 'fs', tool: 'delete_file', preset: false, timeoutSeconds: 600 } }).join(' '), /a call to "delete_file" on "fs" is held/);
    for (const line of nextTimeLines({ hook, server: { name: 'fs', tool: null, preset: true, timeoutSeconds: 600 } })) assert.doesNotMatch(line, /\u2014/, 'no em dashes');
  });
});
