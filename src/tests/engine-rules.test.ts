import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../engine.js';
import { parseConfig } from '../config.js';

const config = parseConfig(`
default_action: allow
rules:
  - id: allow-git-status
    tool: shell
    match: { command: { equals: "git status" } }
    action: allow
  - id: block-prod-sql
    tool: run_sql
    match:
      database: { equals: prod, ignore_case: true }
      sql: { pattern: "\\\\bdrop\\\\b", ignore_case: true }
    action: block
  - id: hold-sql
    tool: run_sql
    detect: { detector: sql_destructive, args: [sql, query] }
    action: require_approval
  - id: hold-shell
    tool: "*"
    detect: { detector: shell_destructive, args: [command, cmd] }
    action: require_approval
  - id: block-secrets
    tool: "*"
    detect: { detector: secret_read, args: [command, path] }
    action: block
  - id: hold-reversible
    tool: deploy
    detect: { detector: terraform_destroy, args: [command] }
    action: require_approval
    reversibility: reversible
  - id: shell-default
    tool: shell
    action: require_approval
`);

describe('Argument rules', () => {
  it('wildcard + detect holds a destructive command on any tool', () => {
    for (const tool of ['shell', 'bash', 'run_terminal_cmd']) {
      const d = evaluate(tool, { command: 'rm -rf /' }, config);
      assert.equal(d.decision, 'held_for_approval', tool);
      assert.equal(d.rule_id, 'hold-shell');
      assert.deepEqual(d.effect, { detector: 'shell_destructive', kind: 'rm_recursive', target: '/', parsed: true });
      assert.equal(d.lane, 'decide');
      assert.equal(d.reversibility, 'irreversible');
    }
  });

  it('reads every listed argument', () => {
    assert.equal(evaluate('bash', { cmd: 'git push -f' }, config).rule_id, 'hold-shell');
    assert.equal(evaluate('read_file', { path: '/home/u/.ssh/id_rsa' }, config).rule_id, 'block-secrets');
  });

  it('a benign command falls through to later rules and the default', () => {
    assert.equal(evaluate('bash', { command: 'rm -rf node_modules' }, config).decision, 'allowed');
    const d = evaluate('shell', { command: 'npm test' }, config);
    assert.equal(d.rule_id, 'shell-default');
    assert.equal(d.effect, undefined);
  });

  it('first match wins: an earlier allow rule shadows a later detect rule', () => {
    assert.equal(evaluate('shell', { command: 'git status' }, config).rule_id, 'allow-git-status');
    assert.equal(evaluate('shell', { command: 'git status; rm -rf /' }, config).rule_id, 'hold-shell');
  });

  it('first match wins: match before detect on the same tool', () => {
    assert.equal(evaluate('run_sql', { database: 'PROD', sql: 'DROP TABLE t' }, config).decision, 'blocked');
    const held = evaluate('run_sql', { database: 'staging', sql: 'DROP TABLE t' }, config);
    assert.equal(held.rule_id, 'hold-sql');
    assert.equal(held.effect?.kind, 'drop_table');
    assert.equal(evaluate('run_sql', { database: 'staging', query: 'TRUNCATE t' }, config).rule_id, 'hold-sql');
    assert.equal(evaluate('run_sql', { database: 'prod', sql: 'SELECT 1' }, config).decision, 'allowed');
  });

  it('all match conditions must hold; a missing argument does not match', () => {
    assert.equal(evaluate('run_sql', { sql: 'drop table t' }, config).rule_id, 'hold-sql');
  });

  it('an undecidable match condition resolves toward the stricter outcome', () => {
    // block rule: a non-string or oversized value holds the condition.
    assert.equal(evaluate('run_sql', { database: ['prod'], sql: 'drop x' }, config).rule_id, 'block-prod-sql');
    // allow rule: it does not.
    assert.equal(evaluate('shell', { command: ['git', 'status'] }, config).rule_id, 'shell-default');
    const big = 'git status' + ' '.repeat(70 * 1024);
    assert.equal(evaluate('shell', { command: big }, config).rule_id, 'shell-default');
  });

  it('an unparseable command fails safe and says so', () => {
    const d = evaluate('shell', { command: 'eval "$PAYLOAD"' }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.rule_id, 'hold-shell');
    assert.equal(d.effect?.parsed, false);
    assert.equal(d.effect?.reason, 'eval');
    assert.match(d.reason, /fail-safe/);
  });

  it('a definite finding in one argument wins over an unparseable one', () => {
    const d = evaluate('shell', { command: 'eval x', cmd: 'rm -rf ~' }, config);
    assert.equal(d.effect?.parsed, true);
    assert.equal(d.effect?.kind, 'rm_recursive');
  });

  it('the reason names the rule and detector kind, never the argument text', () => {
    const secret = 'rm -rf /srv/customer-data-7f3a9c';
    const d = evaluate('shell', { command: secret }, config);
    assert.equal(d.reason.includes('customer-data'), false);
    assert.match(d.reason, /^Matched rule "hold-shell" \(shell_destructive: rm_recursive\)/);
    assert.equal(d.effect?.target, '/srv/customer-data-7f3a9c');
  });

  it('the effect target is sanitized and bounded', () => {
    const d = evaluate('shell', { command: `rm -rf "/data/‮${'x'.repeat(400)}"` }, config);
    assert.ok(d.effect?.target);
    assert.equal(d.effect!.target!.includes('‮'), false);
    assert.ok(Array.from(d.effect!.target!).length <= 120);
  });

  it('agent metadata under _pp cannot lower a detect-based hold', () => {
    for (const _pp of [{ confidence: 100 }, { requires_input: true }, { confidence: 100, requires_input: true, amount_usd: 0 }, { decision: 'allowed' }]) {
      const d = evaluate('shell', { command: 'rm -rf /', _pp }, config);
      assert.equal(d.decision, 'held_for_approval', JSON.stringify(_pp));
      assert.equal(d.reversibility, 'irreversible');
    }
    // Even on a reversible rule, requires_input only re-routes the lane; it stays held.
    const d = evaluate('deploy', { command: 'terraform destroy', _pp: { requires_input: true, confidence: 100 } }, config);
    assert.equal(d.decision, 'held_for_approval');
    assert.equal(d.lane, 'unblock');
    assert.equal(d.effect?.kind, 'destroy');
  });

  it('_pp cannot carry the inspected argument', () => {
    // The detector reads only `command`; a hidden copy under _pp changes nothing, and
    // the call is decided on what the server will receive.
    const d = evaluate('shell', { command: 'rm -rf /', _pp: { command: 'ls' } }, config);
    assert.equal(d.rule_id, 'hold-shell');
  });

  it('a block detect rule blocks', () => {
    const d = evaluate('bash', { command: 'cat .env' }, config);
    assert.equal(d.decision, 'blocked');
    assert.equal(d.effect?.kind, 'secret_file');
  });

  it('a wildcard rule never matches non-tool methods', () => {
    assert.equal(evaluate(null, { command: 'rm -rf /' }, config, 'resources/read').rule_id, null);
  });

  it('existing exact-name rules behave as before', () => {
    const legacy = parseConfig('default_action: allow\nrules:\n  - { id: d, tool: deploy_production, action: require_approval }\n');
    assert.equal(evaluate('deploy_production', { command: 'anything' }, legacy).rule_id, 'd');
    assert.equal(evaluate('deploy_production', {}, legacy).effect, undefined);
  });
});
