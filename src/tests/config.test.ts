import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { loadConfig, parseConfig } from '../config.js';

const ROOT = join(__dirname, '..', '..', '..');

describe('Config Parser', () => {
  it('parses a valid config', () => {
    const config = parseConfig(`
default_action: allow
rules:
  - id: block-delete
    tool: delete_user_data
    action: block
  - id: hold-deploy
    tool: deploy_production
    action: require_approval
  - id: hold-reads
    method: resources/read
    action: require_approval
`);
    assert.equal(config.default_action, 'allow');
    assert.equal(config.rules.length, 3);
    assert.equal(config.rules[0].method, 'tools/call');
    assert.equal(config.rules[2].method, 'resources/read');
    assert.equal(config.mode, 'enforce');
    assert.equal(config.approval_ttl_seconds, 900);
    assert.equal(config.receipt_ttl_seconds, 3600);
    assert.equal(config.scoped_receipt_ttl_seconds, 900);
    assert.equal(config.server_label, 'mcp-server');
    assert.equal(config.signing, 'required');
    assert.match(config.policy_sha256, /^[0-9a-f]{64}$/);
  });

  it('reads receipt expiry, server label, signing mode and per-rule expiry', () => {
    const config = parseConfig(`
default_action: block
receipt_ttl_seconds: 600
scoped_receipt_ttl_seconds: 300
server_label: github-mcp
signing: off
rules:
  - { id: m, tool: merge_pr, action: require_approval, receipt_ttl_seconds: 120 }
`);
    assert.equal(config.receipt_ttl_seconds, 600);
    assert.equal(config.scoped_receipt_ttl_seconds, 300);
    assert.equal(config.server_label, 'github-mcp');
    assert.equal(config.signing, 'off');
    assert.equal(config.rules[0].receipt_ttl_seconds, 120);
  });

  const bad: Array<[string, string, RegExp]> = [
    ['unknown top-level key', 'default_action: allow\ntools: {}\nrules: []', /Unknown config key: "tools"/],
    ['unknown rule key (typo)', 'default_action: allow\nrules:\n  - { id: s, tool: spend, action: require_approval, capusd: 5 }', /unknown key: "capusd"/],
    ['duplicate tool rule', 'default_action: allow\nrules:\n  - { id: a, tool: x, action: allow }\n  - { id: b, tool: x, action: block }', /duplicates another rule/],
    ['duplicate method rule', 'default_action: allow\nrules:\n  - { id: a, method: prompts/get, action: allow }\n  - { id: b, method: prompts/get, action: block }', /duplicates another rule/],
    ['duplicate id', 'default_action: allow\nrules:\n  - { id: a, tool: x, action: allow }\n  - { id: a, tool: y, action: block }', /duplicates id/],
    ['countdown on irreversible', 'default_action: allow\nrules:\n  - { id: a, tool: x, action: require_approval, reversibility: irreversible, countdown_seconds: 5 }', /countdown_seconds requires reversibility/],
    ['countdown without reversibility', 'default_action: allow\nrules:\n  - { id: a, tool: x, action: require_approval, countdown_seconds: 5 }', /countdown_seconds requires reversibility/],
    ['cap without amount_arg', 'default_action: allow\nrules:\n  - { id: a, tool: spend, action: require_approval, cap_usd: 50 }', /cap_usd requires amount_arg/],
    ['amount_arg without cap', 'default_action: allow\nrules:\n  - { id: a, tool: spend, action: require_approval, amount_arg: amount }', /amount_arg is only valid with cap_usd/],
    ['amount_arg reading _pp', 'default_action: allow\nrules:\n  - { id: a, tool: spend, action: require_approval, cap_usd: 5, amount_arg: _pp }', /cannot read agent metadata/],
    ['tool on a non-tools method', 'default_action: allow\nrules:\n  - { id: a, method: prompts/get, tool: x, action: allow }', /applies only to tools\/call/],
    ['bad action', 'default_action: allow\nrules:\n  - { id: a, tool: x, action: maybe }', /invalid action/],
    ['bad default_action', 'default_action: yolo\nrules: []', /Invalid default_action/],
    ['bad ttl', 'default_action: allow\napproval_ttl_seconds: 0\nrules: []', /approval_ttl_seconds/],
    ['receipt ttl over a day', 'default_action: allow\nreceipt_ttl_seconds: 86401\nrules: []', /at most 86400/],
    ['rule receipt ttl over a day', 'default_action: allow\nrules:\n  - { id: a, tool: x, action: allow, receipt_ttl_seconds: 90000 }', /at most 86400/],
    ['server label with spaces (a command line)', 'default_action: allow\nserver_label: node server.js --token x\nrules: []', /Invalid server_label/],
    ['unknown signing mode', 'default_action: allow\nsigning: maybe\nrules: []', /Invalid signing/],
  ];
  for (const [name, yaml, re] of bad) {
    it(`rejects ${name}`, () => assert.throws(() => parseConfig(yaml), re));
  }

  it('throws on missing file', () => {
    assert.throws(() => loadConfig('/nonexistent/path.yaml'), /Failed to read config file/);
  });

  it('every shipped config loads under the strict loader', () => {
    const files = [
      'example/pp.config.yaml',
      'actions-mcp/pp.config.yaml',
      'infra-mcp/pp.config.yaml',
      ...readdirSync(join(ROOT, 'scripts')).filter((f) => f.endsWith('.config.yaml')).map((f) => `scripts/${f}`),
    ];
    assert.ok(files.length >= 6);
    for (const f of files) assert.doesNotThrow(() => loadConfig(join(ROOT, f)), f);
  });
});
