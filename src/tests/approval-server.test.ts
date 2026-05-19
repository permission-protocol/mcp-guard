import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { startApprovalServer } from '../approval-server.js';

describe('Approval Server', () => {
  let server: Server;
  let baseUrl: string;

  before(async () => {
    server = startApprovalServer(0);
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const address = server.address();
    assert.equal(typeof address, 'object');
    assert.ok(address);
    baseUrl = `http://127.0.0.1:${(address as AddressInfo).port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it('requires the page token for approval APIs', async () => {
    const unauthorized = await fetch(`${baseUrl}/api/pending`);
    assert.equal(unauthorized.status, 403);

    const page = await fetch(baseUrl);
    assert.equal(page.status, 200);
    const html = await page.text();
    const token = html.match(/const APPROVAL_TOKEN = "([^"]+)"/)?.[1];
    assert.ok(token);

    const authorized = await fetch(`${baseUrl}/api/pending`, {
      headers: { 'X-MCP-Guard-Approval-Token': token },
    });
    assert.equal(authorized.status, 200);
    assert.deepEqual(await authorized.json(), []);
  });
});
