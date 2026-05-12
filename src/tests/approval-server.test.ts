import { once } from 'node:events';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { startApprovalServer } from '../approval-server.js';

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close(err => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function withApprovalServer(
  approvalToken: string,
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const server = startApprovalServer(0, approvalToken);
  try {
    await once(server, 'listening');
    const address = server.address() as AddressInfo;
    await fn(`http://127.0.0.1:${address.port}`);
  } finally {
    await closeServer(server);
  }
}

describe('approval server', () => {
  it('requires the approval token for API routes', async () => {
    await withApprovalServer('test-approval-token', async baseUrl => {
      const noToken = await fetch(`${baseUrl}/api/pending`);
      assert.equal(noToken.status, 401);
      assert.equal(noToken.headers.get('access-control-allow-origin'), null);
      assert.deepEqual(await noToken.json(), { error: 'Unauthorized' });

      const withToken = await fetch(`${baseUrl}/api/pending`, {
        headers: { 'X-MCP-Guard-Approval-Token': 'test-approval-token' },
      });
      assert.equal(withToken.status, 200);
      assert.deepEqual(await withToken.json(), []);
    });
  });

  it('serves the approval UI with authenticated API fetches', async () => {
    await withApprovalServer('ui-token', async baseUrl => {
      const res = await fetch(`${baseUrl}/`);
      assert.equal(res.status, 200);

      const html = await res.text();
      assert.match(html, /X-MCP-Guard-Approval-Token/);
      assert.match(html, /ui-token/);
    });
  });
});
