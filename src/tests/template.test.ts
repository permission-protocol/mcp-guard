import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { runVerify } from '../verify-cli.js';
import { loadSigningKey, keySetPath } from '../keystore.js';
import { isolateKeys, testIssuer } from './helpers.js';

const ROOT = join(__dirname, '..', '..', '..');
const TEMPLATE = join(ROOT, 'templates', 'github-actions', 'receipt-gate.yml');

describe('receipt-gate template (B8)', () => {
  const wf = parse(readFileSync(TEMPLATE, 'utf-8'));
  const steps: any[] = wf.jobs['receipt-gate'].steps;
  const verify = steps.find((s) => String(s.run ?? '').includes(' verify'));

  it('pins the verifier to this package version', () => {
    const { version } = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf-8'));
    assert.ok(verify.run.includes(`@permission-protocol/mcp-guard@${version} verify`), `template must pin ${version}`);
  });

  it('reads the key set only from the default branch and pins the key from a repository variable', () => {
    const checkout = steps.find((s) => String(s.uses ?? '').startsWith('actions/checkout'));
    assert.equal(checkout.with.ref, '${{ github.event.repository.default_branch }}');
    assert.equal(checkout.with['sparse-checkout'], '.pp/keys.json');
    assert.equal(verify.env.TRUST, '${{ vars.MCP_GUARD_TRUST }}');
    assert.match(verify.run, /--keys trust\/\.pp\/keys\.json/);
    assert.match(verify.run, /--trust "\$TRUST"/);
    assert.match(verify.run, /if \[ -z "\$TRUST" \]/, 'an unset pin fails the gate');
  });

  it('never weakens the gate: no legacy, demo or policy-approval opt-ins, receipt only from the dispatch input', () => {
    for (const flag of ['--accept-legacy', '--allow-demo', '--allow-policy-approval', '--pubkey']) {
      assert.ok(!verify.run.includes(flag), `template must not pass ${flag}`);
    }
    assert.equal(verify.env.RECEIPT, '${{ inputs.receipt }}');
    assert.equal(verify.env.CALL, '${{ inputs.call }}');
    assert.match(verify.run, /--require-call/);
    assert.match(verify.run, /--call "\$RUNNER_TEMP\/call.json"/);
    assert.match(verify.run, /--scope deploy:production/);
    assert.match(verify.run, /--scope-sha "\$GITHUB_SHA"/);
  });

  it('the verify step, run as written, passes a person-approved receipt and refuses a policy one', () => {
    const dir = isolateKeys();
    const key = loadSigningKey();
    const sha = 'f00dfeed';
    mkdirSync(join(dir, 'trust', '.pp'), { recursive: true });
    writeFileSync(join(dir, 'trust', '.pp', 'keys.json'), readFileSync(keySetPath()));
    const receipt = (operator: boolean) => {
      const p = join(dir, `receipt-${operator}.json`);
      writeFileSync(p, JSON.stringify(testIssuer().issue({
        method: 'tools/call', tool: 'deploy', input: { env: 'production', sha }, status: 'APPROVED', ruleId: 'deploy',
        reasonCodes: [operator ? 'OPERATOR_APPROVED' : 'COUNTDOWN_AUTO_RELEASE'],
        decider: operator ? { kind: 'operator', operator: 'rod' } : { kind: 'policy' }, scope: { scope: 'deploy:production', scope_sha: sha },
      })));
      return p;
    };
    const callFile = join(dir, 'call.json');
    writeFileSync(callFile, JSON.stringify({ tool: 'deploy', operation: 'tools/call', input: { env: 'production', sha } }));
    // The template's argv with its shell variables substituted.
    const args = (file: string) => ['--receipt-file', file, '--keys', join(dir, 'trust', '.pp', 'keys.json'), '--trust', `${key.keyId}=${key.fingerprint}`, '--require-call', '--call', callFile, '--scope', 'deploy:production', '--scope-sha', sha];
    const log = console.log, err = console.error;
    console.log = () => {}; console.error = () => {};
    try {
      assert.equal(runVerify(args(receipt(true))), 0);
      assert.equal(runVerify(args(receipt(false))), 1);
    } finally { console.log = log; console.error = err; }
  });
});
