import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyGithubSignature, parsePrEvent, shouldGate, scopeForPr } from '../webhook.js';
import { addExternalDecision, getPending, getAction, _resetQueue, type PendingEnrichment } from '../pending.js';

const SECRET = 'shhh-test-secret';
const sign = (body: string) => 'sha256=' + crypto.createHmac('sha256', SECRET).update(body).digest('hex');

const prPayload = (over = {}) => ({
  action: 'labeled',
  repository: { full_name: 'permission-protocol/mcp-guard' },
  pull_request: {
    number: 16,
    title: 'feat: permission deck',
    head: { sha: 'abc123def456' },
    html_url: 'https://github.com/permission-protocol/mcp-guard/pull/16',
    labels: [{ name: 'needs-authority' }, { name: 'enhancement' }],
  },
  ...over,
});

describe('GitHub webhook — signature', () => {
  it('verifies a correct HMAC-SHA256 signature', () => {
    const body = JSON.stringify(prPayload());
    assert.equal(verifyGithubSignature(SECRET, body, sign(body)), true);
  });
  it('rejects a wrong signature', () => {
    const body = JSON.stringify(prPayload());
    assert.equal(verifyGithubSignature(SECRET, body, 'sha256=deadbeef'), false);
  });
  it('rejects when secret or header missing (fail closed)', () => {
    const body = '{}';
    assert.equal(verifyGithubSignature(undefined, body, sign(body)), false);
    assert.equal(verifyGithubSignature(SECRET, body, undefined), false);
  });
  it('rejects a tampered body under a valid-for-other-body signature', () => {
    const good = JSON.stringify(prPayload());
    const tampered = JSON.stringify(prPayload({ action: 'closed' }));
    assert.equal(verifyGithubSignature(SECRET, tampered, sign(good)), false);
  });
});

describe('GitHub webhook — parse + gate', () => {
  it('parses the PR fields we gate on', () => {
    const ev = parsePrEvent(prPayload());
    assert.equal(ev?.pr_number, 16);
    assert.equal(ev?.repo, 'permission-protocol/mcp-guard');
    assert.equal(ev?.head_sha, 'abc123def456');
    assert.deepEqual(ev?.labels, ['needs-authority', 'enhancement']);
  });
  it('returns null for non-PR payloads', () => {
    assert.equal(parsePrEvent({ action: 'push' }), null);
  });
  it('gates opened/labeled events carrying the trigger label', () => {
    assert.equal(shouldGate(parsePrEvent(prPayload({ action: 'opened' }))!), true);
    assert.equal(shouldGate(parsePrEvent(prPayload({ action: 'labeled' }))!), true);
  });
  it('does NOT gate without the trigger label', () => {
    const noLabel = prPayload();
    noLabel.pull_request.labels = [{ name: 'enhancement' }];
    assert.equal(shouldGate(parsePrEvent(noLabel)!), false);
  });
  it('does NOT gate irrelevant actions (closed)', () => {
    assert.equal(shouldGate(parsePrEvent(prPayload({ action: 'closed' }))!), false);
  });
  it('derives the merge scope binding for the PR', () => {
    const sc = scopeForPr(parsePrEvent(prPayload())!);
    assert.equal(sc.scope, 'github:merge');
    assert.equal(sc.scope_ref, 'refs/pull/16/merge');
    assert.equal(sc.scope_sha, 'abc123def456');
  });
});

describe('External decision enqueue', () => {
  beforeEach(() => _resetQueue());
  it('enqueues a webhook PR as a pending Decide item with scope', () => {
    const ev = parsePrEvent(prPayload())!;
    const sc = scopeForPr(ev);
    const enrichment: PendingEnrichment = { lane: 'decide', reversibility: 'reversible', summary: 'Merge #16', args_preview: JSON.stringify({ pr_number: 16 }) };
    const a = addExternalDecision({ toolName: 'merge_pr', agentId: 'github-webhook', ruleId: 'pr-needs-authority', enrichment, ...sc });
    assert.equal(a.external, true);
    assert.equal(a.lane, 'decide');
    assert.equal(a.scope_ref, 'refs/pull/16/merge');
    assert.equal(getPending().length, 1);
    assert.equal(getAction(a.id)?.scope, 'github:merge');
  });
});
