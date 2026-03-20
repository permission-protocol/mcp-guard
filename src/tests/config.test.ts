import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig } from '../config.js';

describe('Config Parser', () => {
  it('parses a valid config', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-test-'));
    const path = join(dir, 'config.yaml');
    writeFileSync(path, `
default_action: allow
rules:
  - id: block-delete
    tool: delete_user_data
    action: block
  - id: hold-deploy
    tool: deploy_production
    action: require_approval
`);
    const config = loadConfig(path);
    assert.equal(config.default_action, 'allow');
    assert.equal(config.rules.length, 2);
    assert.equal(config.rules[0].id, 'block-delete');
    assert.equal(config.rules[0].tool, 'delete_user_data');
    assert.equal(config.rules[0].action, 'block');
    assert.equal(config.rules[1].action, 'require_approval');
    assert.equal(config.mode, 'enforce'); // default
    unlinkSync(path);
  });

  it('rejects invalid config (bad action)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-test-'));
    const path = join(dir, 'config.yaml');
    writeFileSync(path, `
default_action: allow
rules:
  - id: bad
    tool: foo
    action: nuke_it
`);
    assert.throws(() => loadConfig(path), /invalid action/i);
    unlinkSync(path);
  });

  it('throws on missing file', () => {
    assert.throws(() => loadConfig('/tmp/nonexistent-mcp-guard-config.yaml'), /Failed to read config/);
  });

  it('rejects config with invalid default_action', () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-guard-test-'));
    const path = join(dir, 'config.yaml');
    writeFileSync(path, `
default_action: yolo
rules: []
`);
    assert.throws(() => loadConfig(path), /Invalid default_action/);
    unlinkSync(path);
  });
});
