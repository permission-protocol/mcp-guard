import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { postCommitStatus, authorizedStatus } from '../github-status.js';

describe('GitHub commit status', () => {
  it('POSTs to the correct statuses endpoint with auth + payload', async () => {
    let captured: any = null;
    const stub = async (url: string, init: any) => { captured = { url, init }; return { ok: true, status: 201 }; };
    const res = await postCommitStatus(
      'permission-protocol/mcp-guard', 'abc123',
      { state: 'success', context: 'Permission Deck Receipt Gate', description: 'ok', target_url: 'https://x/r/1' },
      'tok_123', stub,
    );
    assert.equal(res.ok, true);
    assert.equal(res.status, 201);
    assert.equal(captured.url, 'https://api.github.com/repos/permission-protocol/mcp-guard/statuses/abc123');
    assert.equal(captured.init.method, 'POST');
    assert.equal(captured.init.headers.Authorization, 'Bearer tok_123');
    const body = JSON.parse(captured.init.body);
    assert.equal(body.state, 'success');
    assert.equal(body.context, 'Permission Deck Receipt Gate');
    assert.equal(body.target_url, 'https://x/r/1');
  });

  it('reports a non-2xx as not ok', async () => {
    const stub = async () => ({ ok: false, status: 403 });
    const res = await postCommitStatus('o/r', 'sha', { state: 'success', context: 'c' }, 'tok', stub as any);
    assert.equal(res.ok, false);
    assert.equal(res.status, 403);
  });

  it('truncates over-long descriptions to GitHub\'s limit', async () => {
    let body: any = null;
    const stub = async (_u: string, init: any) => { body = JSON.parse(init.body); return { ok: true, status: 201 }; };
    await postCommitStatus('o/r', 'sha', { state: 'success', context: 'c', description: 'x'.repeat(300) }, 'tok', stub);
    assert.ok(body.description.length <= 140);
  });

  it('authorizedStatus builds the canonical green status', () => {
    const s = authorizedStatus('rod', 'rcpt_9', 'https://x/r/9');
    assert.equal(s.state, 'success');
    assert.equal(s.context, 'Permission Deck Receipt Gate');
    assert.match(s.description || '', /rod/);
    assert.match(s.description || '', /rcpt_9/);
    assert.equal(s.target_url, 'https://x/r/9');
  });
});
