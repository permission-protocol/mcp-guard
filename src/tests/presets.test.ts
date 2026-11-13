import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseConfig, type Config } from '../config.js';
import { evaluate } from '../engine.js';
import { DETECTORS } from '../detect/index.js';
import { PRODUCTION_API_URL } from '../cloud/pinned-keys.js';
import { policyText } from '../init/init.js';
import { codingAgentPolicyBody } from '../presets/coding-agent.js';
import { startFakePp } from './cloud-helpers.js';
import { fakeNpx } from './fake-npx.js';

const CLI = join(__dirname, '..', 'cli.js');
const ECHO = join(__dirname, 'fixtures-echo-server.js');
const temp = (name: string) => mkdtempSync(join(tmpdir(), `mcp-guard-${name}-`));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const preset = (): Config => parseConfig(codingAgentPolicyBody());
const withTargets = (targets: string): Config =>
  parseConfig(codingAgentPolicyBody().replace(/targets:\n(  .*\n){4}/, `targets:\n${targets}\n`));

// ---------------------------------------------------------------------------
// The preset itself
// ---------------------------------------------------------------------------

describe('coding-agent preset', () => {
  it('loads under the strict loader, alone and as init writes it', () => {
    const c = preset();
    assert.equal(c.default_action, 'allow');
    assert.equal(c.mode, 'enforce');
    assert.deepEqual(c.targets, { databases: [], cloud_accounts: [], kube_contexts: [], git_branches: [] });
    for (const apiUrl of [PRODUCTION_API_URL, 'https://staging.example.test']) {
      const trustKeys = apiUrl === PRODUCTION_API_URL ? [] : [{ key_id: 'k1', alg: 'ed25519' as const, public_key_b64: Buffer.alloc(32, 7).toString('base64') }];
      const written = parseConfig(policyText({ serverLabel: 'shell', tool: null, environment: 'production', apiUrl, trustKeys, preset: 'coding-agent' }));
      assert.equal(written.server_label, 'shell');
      assert.equal(written.cloud?.api_url, apiUrl);
      assert.deepEqual(written.rules, c.rules);
    }
  });

  it('has no allow rule, and only secret-read is observe-only', () => {
    const c = preset();
    assert.equal(c.rules.some((r) => r.action === 'allow'), false);
    assert.deepEqual(c.rules.filter((r) => r.observe).map((r) => r.id), ['secret-read']);
    // The guard rules come first, then destruction, then production, then secrets.
    const ids = c.rules.map((r) => r.id);
    assert.ok(ids.indexOf('guard-tamper') < ids.indexOf('destructive-sql'));
    assert.ok(ids.indexOf('cloud-delete') < ids.indexOf('production-target'));
    assert.equal(ids[ids.length - 1], 'secret-read');
  });

  it('scans the argument names coding agents use', () => {
    const c = preset();
    const shell = c.rules.find((r) => r.id === 'destructive-shell')!.detect!.args;
    for (const a of ['command', 'cmd', 'script']) assert.ok(shell.includes(a), a);
    const sql = c.rules.find((r) => r.id === 'destructive-sql')!.detect!.args;
    for (const a of ['sql', 'query']) assert.ok(sql.includes(a), a);
  });

  const held: Array<[string, Record<string, unknown>, string, string]> = [
    ['run_sql', { query: 'DROP TABLE customers' }, 'destructive-sql', 'drop_table'],
    ['postgres', { sql: 'DELETE FROM orders' }, 'destructive-sql', 'delete_without_where'],
    ['Bash', { command: 'rm -rf ~/' }, 'destructive-shell', 'rm_recursive'],
    ['run_terminal_cmd', { command: 'git push --force origin main' }, 'destructive-shell', 'git_push_force'],
    ['shell', { command: ['bash', '-lc', 'psql -c "DROP DATABASE app"'] }, 'destructive-shell', 'drop_database'],
    ['exec', { cmd: 'terraform destroy -auto-approve' }, 'terraform-destroy', 'destroy'],
    ['exec', { script: 'aws rds delete-db-instance --db-instance-identifier app' }, 'cloud-delete', 'aws_delete'],
    ['Bash', { command: 'kubectl delete namespace payments' }, 'cloud-delete', 'kubectl_delete'],
  ];
  for (const [tool, args, rule] of held) {
    it(`holds ${tool} ${JSON.stringify(args)} (${rule})`, () => {
      const d = evaluate(tool, args, preset());
      assert.equal(d.decision, 'held_for_approval', d.reason);
      assert.equal(d.rule_id, rule);
      assert.equal(d.effect?.parsed, true);
    });
  }

  it('fails safe on commands it cannot read', () => {
    const d = evaluate('Bash', { command: 'eval "$CLEANUP"' }, preset());
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.effect?.parsed, false);
  });

  for (const [tool, args] of [
    ['Bash', { command: 'npm test' }],
    ['Bash', { command: 'git push origin feature/x' }],
    ['Bash', { command: 'rm -rf node_modules dist' }],
    ['run_sql', { query: 'SELECT * FROM users WHERE id = 1' }],
    ['Read', { file_path: 'README.md' }],
  ] as Array<[string, Record<string, unknown>]>) {
    it(`lets ${tool} ${JSON.stringify(args)} through`, () => {
      const d = evaluate(tool, args, preset());
      assert.equal(d.decision, 'allowed', d.reason);
      assert.equal(d.observed, undefined);
    });
  }

  for (const [tool, args, kind] of [
    ['Bash', { command: 'cat .env.production' }, 'secret_file'],
    ['Bash', { command: 'printenv' }, 'env_dump'],
    ['Read', { file_path: '/home/dev/.aws/credentials' }, 'secret_file'],
    ['read_file', { path: '.env' }, 'secret_file'],
  ] as Array<[string, Record<string, unknown>, string]>) {
    it(`observes a secret read and lets it proceed: ${JSON.stringify(args)}`, () => {
      const d = evaluate(tool, args, preset());
      assert.equal(d.decision, 'allowed');
      assert.equal(d.rule_id, null);
      assert.equal(d.observed?.rule_id, 'secret-read');
      assert.equal(d.observed?.would, 'held_for_approval');
      assert.equal(d.observed?.effect?.kind, kind);
      assert.doesNotMatch(d.observed!.reason, /aws|\.env/);
    });
  }

  it('enforces secret reads once observe is removed', () => {
    const c = parseConfig(codingAgentPolicyBody().replace(', observe: true', ''));
    assert.equal(evaluate('Bash', { command: 'cat .env' }, c).decision, 'held_for_approval');
  });
});

// ---------------------------------------------------------------------------
// Per-rule observe
// ---------------------------------------------------------------------------

describe('observe: true on a rule', () => {
  it('records, then decides as if the rule were absent: a later rule still applies', () => {
    const c = parseConfig(`
default_action: allow
rules:
  - { id: watch, tool: deploy, action: block, observe: true }
  - { id: hold, tool: deploy, action: require_approval }
  - { id: watch-all, tool: "*", detect: { detector: shell_destructive, args: [command] }, action: require_approval, observe: true }
`);
    const d = evaluate('deploy', {}, c);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.rule_id, 'hold');
    assert.equal(d.observed?.rule_id, 'watch');
    assert.equal(d.observed?.would, 'blocked');
    const e = evaluate('sh', { command: 'rm -rf /' }, c);
    assert.equal(e.decision, 'allowed');
    assert.equal(e.observed?.rule_id, 'watch-all');
    assert.equal(e.observed?.effect?.kind, 'rm_recursive');
  });

  it('is refused on allow rules and when not a boolean', () => {
    assert.throws(() => parseConfig('default_action: block\nrules:\n  - { id: a, tool: x, action: allow, observe: true }\n'), /observe applies to block and require_approval/);
    assert.throws(() => parseConfig('default_action: block\nrules:\n  - { id: a, tool: x, action: block, observe: "yes" }\n'), /observe must be true or false/);
  });

  it('leaves existing rules unchanged: duplicates are still refused, false is the default', () => {
    assert.throws(() => parseConfig('default_action: block\nrules:\n  - { id: a, tool: x, action: allow }\n  - { id: b, tool: x, action: block }\n'), /duplicates another rule/);
    const c = parseConfig('default_action: block\nrules:\n  - { id: a, tool: x, action: block, observe: false }\n');
    assert.equal(c.rules[0].observe, undefined);
    assert.equal(evaluate('x', {}, c).decision, 'blocked');
  });
});

// ---------------------------------------------------------------------------
// Production targets
// ---------------------------------------------------------------------------

describe('production targets', () => {
  const c = withTargets(`  databases: [prod-db.internal, app_production]
  cloud_accounts: [acme-prod, "012345678901"]
  kube_contexts: [prod-eu-1]
  git_branches: [release]`);

  it('loads names lower-cased and holds a call that names one', () => {
    assert.deepEqual(c.targets!.cloud_accounts, ['acme-prod', '012345678901']);
    for (const [tool, args, kind] of [
      ['Bash', { command: 'psql -h PROD-DB.internal -c "select 1"' }, 'databases'],
      ['Bash', { command: 'gcloud config set project acme-prod' }, 'cloud_accounts'],
      ['Bash', { command: 'aws s3 ls --profile x --account 012345678901' }, 'cloud_accounts'],
      ['Bash', { command: 'kubectl --context=prod-eu-1 get pods' }, 'kube_contexts'],
      ['Bash', { command: 'git push origin release' }, 'git_branches'],
      ['query_db', { database: 'app_production', sql: 'select 1' }, 'databases'],
      ['Bash', { command: 'psql postgres://u@prod-db.internal:5432/app' }, 'databases'],
      ['Bash', { command: `gcloud --project 'acme'"-prod" sql list` }, 'cloud_accounts'],
      ['k8s', { context: ['prod-eu-1'] }, 'kube_contexts'],
    ] as Array<[string, Record<string, unknown>, string]>) {
      const d = evaluate(tool, args, c);
      assert.equal(d.decision, 'held_for_approval', `${JSON.stringify(args)}: ${d.reason}`);
      assert.equal(d.rule_id, 'production-target');
      assert.deepEqual([d.effect?.detector, d.effect?.kind, d.effect?.parsed], ['production_target', kind, true]);
    }
  });

  it('matches whole words only', () => {
    for (const command of ['psql -h prod-db.internal2', 'gcloud config set project acme-production', 'git push origin release-notes2x'.replace('release-', 'prerelease'), 'echo app_productionx']) {
      assert.equal(evaluate('Bash', { command }, c).decision, 'allowed', command);
    }
  });

  it('a number argument is read as text', () => {
    const d = withTargets('  cloud_accounts: ["123456789012"]');
    assert.equal(evaluate('aws', { command: 'x', project_id: 123456789012 }, d).decision, 'held_for_approval');
  });

  it('fails safe on arguments it cannot read', () => {
    for (const value of [{ nested: 'acme-prod' }, ['a', { b: 1 }], 'x'.repeat(64 * 1024 + 1)]) {
      const d = evaluate('query_db', { database: value }, c);
      assert.equal(d.decision, 'held_for_approval');
      assert.equal(d.rule_id, 'production-target');
      assert.equal(d.effect?.parsed, false);
    }
    // Absent, null and boolean carry no text.
    for (const value of [undefined, null, true]) assert.equal(evaluate('x', { database: value }, c).decision, 'allowed');
  });

  it('empty lists match nothing', () => {
    assert.equal(evaluate('Bash', { command: 'psql -h anything' }, preset()).decision, 'allowed');
  });

  it('narrows by kind with `in`', () => {
    const d = parseConfig(`
default_action: allow
targets: { databases: [prod-db], git_branches: [release] }
rules:
  - { id: db, tool: "*", mentions_target: { in: [databases], args: [command] }, action: block }
`);
    assert.equal(evaluate('sh', { command: 'psql -h prod-db' }, d).decision, 'blocked');
    assert.equal(evaluate('sh', { command: 'git push origin release' }, d).decision, 'allowed');
  });

  const bad: Array<[string, RegExp]> = [
    ['targets: { databases: [prod], hosts: [x] }\nrules: []', /Unknown targets key: "hosts"/],
    ['targets: { cloud_accounts: [123456789012] }\nrules: []', /must be a quoted string/],
    ['targets: { databases: ["prod.*"] }\nrules: []', /literal names, not patterns/],
    ['targets: { databases: [p] }\nrules: []', /2-128 characters/],
    ['targets: { databases: [prod, PROD] }\nrules: []', /listed twice/],
    [`targets: { databases: [${Array.from({ length: 65 }, (_, i) => `db${i}`).join(', ')}] }\nrules: []`, /at most 64 names/],
    ['targets: { databases: prod }\nrules: []', /must be a list of names/],
    ['targets: [prod]\nrules: []', /Invalid targets/],
    ['rules:\n  - { id: t, tool: "*", mentions_target: { args: [command] }, action: block }', /needs a top-level "targets:" section/],
    ['targets: {}\nrules:\n  - { id: t, tool: x, mentions_target: { args: [command] }, action: allow }', /cannot be used with action "allow"/],
    ['targets: {}\nrules:\n  - { id: t, tool: "*", mentions_target: { in: [hosts], args: [command] }, action: block }', /mentions_target.in "hosts" is unknown/],
    ['targets: {}\nrules:\n  - { id: t, tool: "*", mentions_target: { args: [] }, action: block }', /non-empty list/],
    ['targets: {}\nrules:\n  - { id: t, tool: "*", mentions_target: { args: [_pp] }, action: block }', /agent metadata/],
    ['targets: {}\nrules:\n  - { id: t, tool: "*", mentions_target: { args: [command], pattern: x }, action: block }', /unknown key: "pattern"/],
  ];
  for (const [yaml, error] of bad) {
    it(`refuses at load: ${error.source}`, () => {
      assert.throws(() => parseConfig(`default_action: allow\n${yaml}\n`), error);
    });
  }
});

// ---------------------------------------------------------------------------
// Self-protection
// ---------------------------------------------------------------------------

describe('detector guard_tamper', () => {
  const fn = DETECTORS.guard_tamper;
  const hits: Array<[string, string]> = [
    ['echo "default_action: allow" > pp.config.yaml', 'edit_policy'],
    ['sed -i s/require_approval/allow/ ~/.config/mcp-guard/policies/shell.yaml', 'edit_policy'],
    ['rm pp.config.yml', 'edit_policy'],
    ['git checkout -- pp.config.yaml', 'edit_policy'],
    ['ln -sf /dev/null pp.config.yaml', 'edit_policy'],
    ['dd if=/dev/null of=pp.config.yaml', 'edit_policy'],
    ['vim ~/.config/mcp-guard/policies/x.yaml', 'edit_policy'],
    ['truncate -s 0 pp-receipts.jsonl', 'edit_receipts'],
    ['echo {} >> /var/log/self-test-receipts.jsonl', 'edit_receipts'],
    ['rm *.jsonl', 'edit_receipts'],
    ['rm -rf ~/.config/mcp-guard', 'edit_keys'],
    ['mv ~/.config ~/.config.old', 'edit_keys'],
    ['chmod 644 ~/.config/mcp-guard/keys/mcpg-1.private.pem', 'edit_keys'],
    ['rm $HOME/.config/mcp-guard/install-token', 'edit_keys'],
    ['find ~/.config/mcp-guard -delete', 'edit_keys'],
    ['mcp-guard keys revoke mcpg-1', 'guard_cli'],
    ['npx -y @permission-protocol/mcp-guard@0.5.1 keys rotate', 'guard_cli'],
    ['cp /tmp/plain.json .mcp.json', 'edit_client_config'],
    ['mv .mcp.json .mcp.json.off', 'edit_client_config'],
    ['cp ~/Downloads/.mcp.json ./', 'edit_client_config'],
    ['jq "del(.mcpServers.db)" ~/.claude.json > /tmp/x && mv /tmp/x ~/.claude.json', 'edit_client_config'],
    ['tee .cursor/mcp.json < new.json', 'edit_client_config'],
    ['rm -rf .claude', 'edit_client_config'],
    ['code .claude/settings.local.json', 'edit_client_config'],
    ['python3 - <<EOF\nx\nEOF\nrm ~/.codex/config.toml', 'edit_client_config'],
    ['pkill -f mcp-guard', 'kill_guard'],
    ['killall node', 'kill_guard'],
    ['kill -9 $(pgrep -f mcp-guard)', 'kill_guard'],
    ['kill -9 -1', 'kill_guard'],
    ['taskkill /F /IM node.exe', 'kill_guard'],
    ['sudo bash -c "rm pp.config.yaml"', 'edit_policy'],
  ];
  for (const [text, kind] of hits) {
    it(`matches ${JSON.stringify(text)} as ${kind}`, () => {
      const r = fn(text);
      assert.equal(r.matched, true, JSON.stringify(r));
      assert.equal(r.parsed, true, JSON.stringify(r));
      assert.equal(r.kind, kind);
    });
  }
  const misses = [
    'cat pp.config.yaml',
    'grep require_approval ~/.config/mcp-guard/policies/shell.yaml',
    'tail -n 20 pp-receipts.jsonl',
    'cp pp.config.yaml /tmp/policy-copy.yaml',
    'cp .mcp.json /tmp/backup.json',
    'git diff pp.config.yaml',
    'ln -s pp.config.yaml policy-link',
    'mcp-guard keys show',
    'mcp-guard receipt verify rcpt_1',
    'kill $(lsof -ti:3000)',
    'kill -1 1234',
    'pkill -f "vite dev"',
    'rm -rf ~/code/mcp-guard',
    'rm -rf .config',
    'echo hi > notes.md',
    'npm test',
  ];
  for (const text of misses) {
    it(`does not match ${JSON.stringify(text)}`, () => {
      const r = fn(text);
      assert.equal(r.matched, false, JSON.stringify(r));
    });
  }

  it('through the preset: editing is held, reading is not, for shell and file tools', () => {
    const c = preset();
    assert.equal(evaluate('Bash', { command: 'cat pp.config.yaml' }, c).decision, 'allowed');
    assert.equal(evaluate('read_file', { path: '/home/dev/.config/mcp-guard/policies/fs.yaml' }, c).decision, 'allowed');
    assert.equal(evaluate('Read', { file_path: '/home/dev/.claude.json' }, c).decision, 'allowed');
    for (const [tool, args, rule] of [
      ['Bash', { command: 'echo "default_action: allow" > pp.config.yaml' }, 'guard-tamper'],
      ['write_file', { path: '/home/dev/.config/mcp-guard/policies/fs.yaml', content: 'x' }, 'guard-tamper-write_file'],
      ['Write', { file_path: '/home/dev/project/.mcp.json', content: '{}' }, 'guard-tamper-write'],
      ['Edit', { file_path: '/home/dev/.claude.json', old_string: 'a', new_string: 'b' }, 'guard-tamper-edit'],
      ['edit_file', { target_file: '.cursor/mcp.json' }, 'guard-tamper-edit_file'],
      ['move_file', { source: 'pp-receipts.jsonl', destination: '/tmp/r' }, 'guard-tamper-move_file'],
      ['delete_file', { target_file: 'pp.config.yaml' }, 'guard-tamper-delete_file'],
      ['apply_patch', { input: '*** Begin Patch\n*** Update File: .mcp.json\n@@\n-a\n+b\n*** End Patch' }, 'guard-tamper-apply-patch'],
      ['Bash', { command: 'pkill -f mcp-guard' }, 'guard-tamper'],
    ] as Array<[string, Record<string, unknown>, string]>) {
      const d = evaluate(tool, args, c);
      assert.equal(d.decision, 'held_for_approval', `${tool} ${JSON.stringify(args)}: ${d.reason}`);
      assert.equal(d.rule_id, rule);
    }
    assert.equal(evaluate('Write', { file_path: 'src/index.ts', content: 'x' }, c).decision, 'allowed');
    assert.equal(evaluate('apply_patch', { input: '*** Begin Patch\n*** Update File: src/a.ts\n*** End Patch' }, c).decision, 'allowed');
  });
});

// Claude Code's built-in tools as the hook adapter passes them to evaluate(): Bash and
// PowerShell { command }, Write { file_path, content }, Edit { file_path, old_string,
// new_string, replace_all }. file_path is absolute.
describe('coding-agent preset with Claude Code hook tool shapes', () => {
  const c = preset();
  const P = '/home/dev/project';
  const cases: Array<[string, Record<string, unknown>, 'held_for_approval' | 'allowed', string | null]> = [
    ['Edit', { file_path: `${P}/pp.config.yaml`, old_string: 'require_approval', new_string: 'allow', replace_all: true }, 'held_for_approval', 'guard-tamper-edit'],
    ['Write', { file_path: `${P}/.claude/settings.json`, content: '{}' }, 'held_for_approval', 'guard-tamper-write'],
    ['Write', { file_path: `${P}/.claude/settings.local.json`, content: '{}' }, 'held_for_approval', 'guard-tamper-write'],
    ['Edit', { file_path: '/home/dev/.claude/settings.json', old_string: 'a', new_string: 'b', replace_all: false }, 'held_for_approval', 'guard-tamper-edit'],
    ['Edit', { file_path: '/home/dev/.config/mcp-guard/hook-requests.json', old_string: 'a', new_string: 'b', replace_all: false }, 'held_for_approval', 'guard-tamper-edit'],
    ['Write', { file_path: `${P}/pp-receipts.jsonl`, content: '' }, 'held_for_approval', 'guard-tamper-write'],
    ['Write', { file_path: '/home/dev/.config/mcp-guard/keys/keys.json', content: '{}' }, 'held_for_approval', 'guard-tamper-write'],
    ['Write', { file_path: `${P}/src/../.claude/./settings.json`, content: '{}' }, 'held_for_approval', 'guard-tamper-write'],
    ['Write', { file_path: 'C:\\Users\\Dev User\\project\\.claude\\settings.json', content: '{}' }, 'held_for_approval', 'guard-tamper-write'],
    ['Write', { file_path: '/Users/dev/Library/Application Support/Claude/claude_desktop_config.json', content: '{}' }, 'held_for_approval', 'guard-tamper-write'],
    ['NotebookEdit', { notebook_path: `${P}/.mcp.json` }, 'held_for_approval', 'guard-tamper-notebookedit'],
    ['Bash', { command: 'rm .claude/settings.json' }, 'held_for_approval', 'guard-tamper'],
    ['Bash', { command: 'echo "{}" > .claude/settings.json' }, 'held_for_approval', 'guard-tamper'],
    ['Bash', { command: 'jq ".hooks={}" .claude/settings.json > /tmp/s && mv /tmp/s ./.claude//settings.json' }, 'held_for_approval', 'guard-tamper'],
    ['Bash', { command: 'echo x > "$SETTINGS"' }, 'held_for_approval', 'guard-tamper'],
    ['PowerShell', { command: 'Remove-Item .claude/settings.json -Force' }, 'held_for_approval', 'guard-tamper'],
    ['PowerShell', { command: 'Stop-Process -Name node' }, 'held_for_approval', 'guard-tamper'],
    ['Edit', { file_path: `${P}/src/index.ts`, old_string: 'a', new_string: 'b', replace_all: false }, 'allowed', null],
    ['Write', { file_path: `${P}/docs/settings.json.md`, content: 'x' }, 'allowed', null],
    ['Bash', { command: 'cat pp.config.yaml' }, 'allowed', null],
    ['Bash', { command: 'cat .claude/settings.json' }, 'allowed', null],
    ['Bash', { command: 'echo done > "$OUT/build.log"' }, 'allowed', null],
  ];
  for (const [tool, args, decision, rule] of cases) {
    it(`${decision === 'allowed' ? 'allows' : 'holds'} ${tool} ${JSON.stringify(args).slice(0, 90)}`, () => {
      const d = evaluate(tool, args, c);
      assert.equal(d.decision, decision, d.reason);
      assert.equal(d.rule_id, rule);
    });
  }
});

// ---------------------------------------------------------------------------
// End to end through the CLI: holds, observations, and no argument text anywhere
// ---------------------------------------------------------------------------

describe('coding-agent preset end to end', () => {
  let dir: string;
  let guard: ChildProcess;
  let stderr = '';
  const responses = new Map<unknown, any>();
  const env = () => ({ ...process.env, PP_KEYS_DIR: join(dir, 'keys'), PP_SHARED_RECEIPTS_PATH: join(dir, 'receipts.jsonl'), ECHO_LOG: join(dir, 'server.log') });
  const serverLog = () => (existsSync(join(dir, 'server.log')) ? readFileSync(join(dir, 'server.log'), 'utf-8') : '');
  const call = (id: number, name: string, args: Record<string, unknown>) =>
    guard.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) + '\n');

  before(async () => {
    dir = temp('preset-e2e');
    writeFileSync(join(dir, 'pp.config.yaml'), codingAgentPolicyBody());
    assert.equal(spawnSync('node', [CLI, 'keys', 'init'], { env: env() }).status, 0);
    guard = spawn('node', [CLI, '--config', join(dir, 'pp.config.yaml'), '--agent-id', 'e2e', '--', 'node', ECHO], { env: env(), stdio: ['pipe', 'pipe', 'pipe'] });
    guard.stderr!.on('data', (d) => { stderr += d.toString(); });
    let buf = '';
    guard.stdout!.on('data', (d) => {
      buf += d.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) { const m = JSON.parse(buf.slice(0, nl)); buf = buf.slice(nl + 1); responses.set(m.id, m); }
    });
    call(1, 'Bash', { command: 'rm -rf /srv/data-SENTINEL-7f1' });
    call(2, 'Bash', { command: 'cat /work/.env.SENTINEL-prod' });
    call(3, 'Bash', { command: 'cat pp.config.yaml' });
    call(4, 'Bash', { command: 'echo SENTINEL > pp.config.yaml' });
    call(5, 'run_sql', { query: 'DROP TABLE SENTINEL_customers' });
    for (let i = 0; i < 100 && responses.size < 5; i++) await sleep(50);
  });

  after(() => { guard?.kill('SIGTERM'); });

  it('holds destruction and tampering, and never forwards them', () => {
    for (const id of [1, 4, 5]) assert.equal(responses.get(id)?.error?.code, -32002, JSON.stringify(responses.get(id)));
    assert.match(responses.get(4).error.message, /guard-tamper.*guard_tamper: edit_policy/);
    assert.equal(/rm -rf|DROP TABLE|echo SENTINEL/.test(serverLog()), false);
  });

  it('forwards a secret read and records it as observed', () => {
    assert.equal(responses.get(2)?.result?.echoed, 'tools/call');
    assert.equal(responses.get(3)?.result?.echoed, 'tools/call');
    assert.match(stderr, /OBSERVE: Matched rule "secret-read" \(secret_read: secret_file\) would hold "Bash"; not enforced/);
    const observed = readFileSync(join(dir, 'receipts.jsonl'), 'utf-8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((l) => l.observed);
    assert.equal(observed.length, 1);
    assert.deepEqual([observed[0].observed.ruleId, observed[0].observed.detector, observed[0].observed.kind, observed[0].observed.would], ['secret-read', 'secret_read', 'secret_file', 'held_for_approval']);
    assert.match(observed[0].observed.inputHash, /^sha256:/);
  });

  it('argument text never reaches receipts, stderr or client errors', () => {
    const log = readFileSync(join(dir, 'receipts.jsonl'), 'utf-8');
    const errors = JSON.stringify([1, 4, 5].map((id) => responses.get(id)));
    for (const where of [log, stderr, errors]) assert.equal(where.includes('SENTINEL'), false);
  });
});

// ---------------------------------------------------------------------------
// init --preset
// ---------------------------------------------------------------------------

describe('mcp-guard init --preset', () => {
  const TOKEN = `pp_test_${'pres'.repeat(8)}`;

  function run(args: string[], env: NodeJS.ProcessEnv, cwd: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(process.execPath, [CLI, ...args], { env, cwd, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => { stdout += d.toString(); });
      child.stderr.on('data', (d) => { stderr += d.toString(); });
      child.on('exit', (code) => resolve({ code, stdout, stderr }));
    });
  }

  function machine() {
    const root = temp('preset-init');
    const project = join(root, 'project');
    mkdirSync(project, { recursive: true });
    const mcpConfig = join(project, '.mcp.json');
    writeFileSync(mcpConfig, JSON.stringify({ mcpServers: { shell: { command: process.execPath, args: [ECHO] } } }, null, 2) + '\n');
    // The wrap step checks `npx -y @permission-protocol/mcp-guard@<version>`: a stand-in runs this build, never the registry.
    const npx = fakeNpx(root);
    const env: NodeJS.ProcessEnv = { ...process.env, XDG_CONFIG_HOME: join(root, 'config'), MCP_GUARD_TOKEN_STORE: 'file', ECHO_LOG: join(root, 'server.log'), HOME: root, USERPROFILE: root, ...npx.env };
    for (const key of Object.keys(env)) if (key.startsWith('PP_')) delete env[key];
    return { project, mcpConfig, env, policyPath: join(root, 'config', 'mcp-guard', 'policies', 'shell.yaml') };
  }

  it('writes the preset, which loads, and asks nothing extra', async () => {
    const fake = await startFakePp(TOKEN);
    const m = machine();
    try {
      const r = await run(['init', '--api-url', fake.url, '--trust-key', `${fake.issuer.keyId}=${fake.issuer.publicKeyB64}`, '--mcp-config', m.mcpConfig, '--preset', 'coding-agent', '--yes', '--no-browser', '--skip-self-test'], m.env, m.project);
      assert.equal(r.code, 0, `${r.stdout}\n${r.stderr}`);
      assert.match(r.stdout, /Policy preset: coding-agent/);
      assert.doesNotMatch(r.stdout, /Which tool/);
      const c = parseConfig(readFileSync(m.policyPath, 'utf-8'));
      assert.deepEqual(c.rules, preset().rules);
      assert.equal(c.server_label, 'shell');
      assert.equal(c.cloud?.api_url, fake.url);
    } finally { await fake.close(); }
  });

  it('refuses an unknown preset and --preset with --tool, before anything changes', async () => {
    const m = machine();
    const unknown = await run(['init', '--preset', 'yolo', '--mcp-config', m.mcpConfig], m.env, m.project);
    assert.equal(unknown.code, 2);
    assert.match(unknown.stderr, /--preset must be one of: coding-agent/);
    const both = await run(['init', '--preset', 'coding-agent', '--tool', 'x', '--mcp-config', m.mcpConfig], m.env, m.project);
    assert.equal(both.code, 2);
    assert.match(both.stderr, /cannot be used together/);
    assert.equal(existsSync(m.policyPath), false);
  });
});
