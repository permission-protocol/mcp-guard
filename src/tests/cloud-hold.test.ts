import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ReplayCache } from '../verify-core.js';
import { CloudApiError, type CloudClient, type CreateRequestBody } from '../cloud/client.js';
import { fingerprintOfCall } from '../cloud/fingerprint.js';
import { decideInCloud, MAX_PREVIEW_BYTES, type CloudHoldInput, type CloudOutcome } from '../cloud/hold.js';
import { mintCloudReceipt, testPpIssuer, type MintOptions } from './cloud-helpers.js';

/**
 * The hold flow against a scripted Permission Protocol: every way it can end. Only a
 * verified receipt followed by a successful redeem releases; time is virtual.
 */

const issuer = testPpIssuer();
const ARGS = { path: '/srv/data/report.csv', token: 'not-sent-as-args' };
const FINGERPRINT = fingerprintOfCall('filesystem', 'delete_file', ARGS);
const REQUEST_ID = `mcpreq_${'c'.repeat(32)}`;

type Step = Record<string, unknown> | Error;

function script(steps: { create?: Step; reads?: Step[]; redeem?: Step }) {
  const calls = { create: [] as CreateRequestBody[], reads: 0, redeems: 0 };
  const reads = [...(steps.reads ?? [])];
  const play = (step: Step | undefined, fallback: Step): Record<string, unknown> => {
    const value = step ?? fallback;
    if (value instanceof Error) throw value;
    return value;
  };
  const client: CloudClient = {
    async create(body) { calls.create.push(body); return play(steps.create, pending()); },
    async read() { calls.reads += 1; return play(reads.length > 1 ? reads.shift() : reads[0], pending()); },
    async redeem() { calls.redeems += 1; return play(steps.redeem, { requestId: REQUEST_ID, receiptId: 'rcpt_1', fingerprint: FINGERPRINT, redeemedAt: new Date().toISOString() }); },
  };
  return { client, calls };
}

const pending = (over: Record<string, unknown> = {}) => ({ requestId: REQUEST_ID, fingerprint: FINGERPRINT, status: 'pending', approvalUrl: `https://pp.test/sign/1`, receipt: null, ...over });
const approved = (mint: Partial<MintOptions> = {}, over: Record<string, unknown> = {}) => ({
  requestId: REQUEST_ID, fingerprint: FINGERPRINT, status: 'approved', approvalUrl: null,
  receipt: { id: 'rcpt_1', url: 'https://pp.test/r/rcpt_1', artifact: mintCloudReceipt(issuer, { fingerprint: FINGERPRINT, requestId: REQUEST_ID, receiptId: 'rcpt_1', ...mint }) },
  ...over,
});
const denied = (mint: Partial<MintOptions> | null, reason = 'Approval was denied: no') => ({
  requestId: REQUEST_ID, fingerprint: FINGERPRINT, status: 'denied', approvalUrl: null, reason,
  receipt: mint === null ? null : { id: 'rcpt_d', url: 'https://pp.test/r/rcpt_d', artifact: mintCloudReceipt(issuer, { fingerprint: FINGERPRINT, requestId: REQUEST_ID, receiptId: 'rcpt_d', status: 'DENIED', ...mint }) },
});
const http = (status: number, code?: string) => new CloudApiError('HTTP', `Permission Protocol answered ${status}`, status, code);
const down = () => new CloudApiError('UNREACHABLE', 'Permission Protocol is unreachable: connect ECONNREFUSED');

async function run(client: CloudClient, over: Partial<CloudHoldInput> = {}): Promise<{ outcome: CloudOutcome; slept: number[]; pendingSeen: unknown[] }> {
  let clock = 1_700_000_000_000;
  const slept: number[] = [];
  const pendingSeen: unknown[] = [];
  const outcome = await decideInCloud({
    client,
    keySet: issuer.keySet,
    trust: issuer.trust,
    replayCache: new ReplayCache(),
    server: 'filesystem',
    tool: 'delete_file',
    args: ARGS,
    agentId: 'claude-code',
    environment: 'production',
    timeoutSeconds: 600,
    onPending: (info) => pendingSeen.push(info),
    // Virtual time for the deadline; real time for receipt expiry.
    now: () => clock,
    sleep: async (ms) => { slept.push(ms); clock += ms; },
    ...over,
  });
  return { outcome, slept, pendingSeen };
}

describe('released: a verified receipt, redeemed once', () => {
  it('creates, polls with backoff, verifies, redeems, releases', async () => {
    const { client, calls } = script({ reads: [pending(), pending(), pending(), approved()] });
    const { outcome, slept, pendingSeen } = await run(client, { now: undefined });
    assert.equal(outcome.kind, 'released');
    if (outcome.kind !== 'released') return;
    assert.equal(outcome.receipt.receiptId, 'rcpt_1');
    assert.equal(outcome.receipt.decider.display, 'Maria Signer');
    assert.equal(outcome.receiptUrl, 'https://pp.test/r/rcpt_1');
    assert.equal(outcome.fingerprint, FINGERPRINT);
    assert.deepEqual(slept, [1000, 1500, 2250, 3375]);
    assert.equal(calls.redeems, 1);
    assert.deepEqual(pendingSeen, [{ requestId: REQUEST_ID, approvalUrl: 'https://pp.test/sign/1' }]);
  });

  it('sends the hash and a preview, never more than the cap', async () => {
    const { client, calls } = script({ reads: [approved()] });
    await run(client, { now: undefined });
    const body = calls.create[0];
    assert.equal(body.argsHash.startsWith('sha256:'), true);
    assert.deepEqual({ tool: body.tool, server: body.server, agentId: body.agentId, env: body.env, timeoutSec: body.timeoutSec }, { tool: 'delete_file', server: 'filesystem', agentId: 'claude-code', env: 'production', timeoutSec: 600 });
    // Masked before upload: the path stays readable, the value under "token" does not leave.
    assert.deepEqual(JSON.parse(body.argsPreview!), { path: ARGS.path, token: '[masked]' });
    assert.equal(Object.prototype.hasOwnProperty.call(body, 'args'), false);

    const big = { blob: 'x '.repeat(25_000) };
    const large = script({ create: pending({ fingerprint: fingerprintOfCall('filesystem', 'delete_file', big) }) });
    await run(large.client, { args: big, timeoutSeconds: 30 });
    assert.ok(Buffer.byteLength(large.calls.create[0].argsPreview!, 'utf8') <= MAX_PREVIEW_BYTES);
    assert.equal(MAX_PREVIEW_BYTES, 2048);
  });

  it('polling never waits longer than five seconds between reads, nor past the deadline', async () => {
    const { client } = script({ reads: [pending()] });
    const { outcome, slept } = await run(client, { timeoutSeconds: 60 });
    assert.equal(outcome.kind, 'expired');
    assert.equal(Math.max(...slept), 5000);
    assert.equal(slept.reduce((a, b) => a + b, 0), 60_000);
  });
});

describe('expired: nobody signed in time', () => {
  it('the guard stops at its own timeout', async () => {
    const { client, calls } = script({ reads: [pending()] });
    const { outcome } = await run(client, { timeoutSeconds: 30 });
    assert.equal(outcome.kind, 'expired');
    assert.equal(calls.redeems, 0);
  });

  it('Permission Protocol reports the request expired', async () => {
    const { client } = script({ reads: [{ requestId: REQUEST_ID, fingerprint: FINGERPRINT, status: 'expired', reason: 'Approval expired before decision', receipt: null }] });
    const { outcome } = await run(client);
    assert.deepEqual({ kind: outcome.kind, reason: outcome.kind === 'expired' ? outcome.reason : '' }, { kind: 'expired', reason: 'Approval expired before decision' });
  });
});

describe('denied', () => {
  it('a person rejected it: the signed DENIED receipt is kept', async () => {
    const { client, calls } = script({ reads: [denied({})] });
    const { outcome } = await run(client);
    assert.equal(outcome.kind, 'denied');
    if (outcome.kind !== 'denied') return;
    assert.equal(outcome.receipt?.receiptId, 'rcpt_d');
    assert.equal(outcome.receipt?.status, 'DENIED');
    assert.equal(outcome.reason, 'Approval was denied: no');
    assert.equal(calls.redeems, 0);
  });

  it('a frozen workspace answers the create with a signed DENIED', async () => {
    const frozen = denied({ deciderId: 'system/pp-engine', deciderDisplay: null, deciderAuthMethod: null, expiresAt: null }, 'Global freeze is active');
    const { client, calls } = script({ create: frozen });
    const { outcome, slept } = await run(client);
    assert.equal(outcome.kind, 'denied');
    if (outcome.kind !== 'denied') return;
    assert.equal(outcome.reason, 'Global freeze is active');
    assert.equal(outcome.receipt?.decider.id, 'system/pp-engine');
    assert.equal(calls.reads, 0);
    assert.equal(calls.redeems, 0);
    assert.deepEqual(slept, []);
  });

  it('a denial whose receipt does not verify is still a denial, recorded without a receipt', async () => {
    const forged = denied({});
    (forged.receipt as any).artifact.signature_b64 = Buffer.alloc(64, 7).toString('base64');
    const { outcome } = await run(script({ reads: [forged] }).client);
    assert.equal(outcome.kind, 'denied');
    if (outcome.kind === 'denied') assert.equal(outcome.receipt, null);
    const unsigned = await run(script({ reads: [denied(null)] }).client);
    assert.equal(unsigned.outcome.kind, 'denied');
  });
});

describe('blocked: the API is down or cannot be trusted', () => {
  const expectBlocked = async (steps: Parameters<typeof script>[0], code: string | RegExp, over: Partial<CloudHoldInput> = {}) => {
    const { client, calls } = script(steps);
    const { outcome } = await run(client, over);
    assert.equal(outcome.kind, 'blocked', JSON.stringify(outcome));
    if (outcome.kind === 'blocked') {
      if (typeof code === 'string') assert.equal(outcome.code, code);
      else assert.match(outcome.code, code);
    }
    return calls;
  };

  it('API down at create', async () => {
    const calls = await expectBlocked({ create: down() }, 'API_UNREACHABLE');
    assert.equal(calls.reads + calls.redeems, 0);
  });

  it('any error answer at create: 401, 403, 429, 500, 503', async () => {
    for (const status of [400, 401, 403, 429, 500, 503]) {
      await expectBlocked({ create: http(status, 'X') }, `API_${status}_X`);
    }
    await expectBlocked({ create: new CloudApiError('BAD_RESPONSE', 'not json') }, 'API_BAD_RESPONSE');
    await expectBlocked({ create: new Error('boom') }, 'API_ERROR');
  });

  it('a create answer the guard cannot use', async () => {
    await expectBlocked({ create: { status: 'pending' } }, 'BAD_RESPONSE');
    await expectBlocked({ create: pending({ fingerprint: `sha256:${'0'.repeat(64)}` }) }, 'FINGERPRINT_MISMATCH');
    await expectBlocked({ create: pending({ status: 'error' }) }, 'REQUEST_NOT_DECIDABLE');
    await expectBlocked({ create: pending({ status: 'released' }) }, 'REQUEST_NOT_DECIDABLE');
  });

  it('API down for the whole wait: retried until the deadline, then refused, never released', async () => {
    const { client, calls } = script({ reads: [down()] });
    const { outcome } = await run(client, { timeoutSeconds: 30 });
    assert.equal(outcome.kind, 'expired');
    assert.equal(calls.redeems, 0);
    assert.ok(calls.reads >= 5);
  });

  it('a transient failure mid-wait does not lose a signature given afterwards', async () => {
    const { client } = script({ reads: [down(), http(503), http(429), approved()] });
    const { outcome } = await run(client, { now: undefined });
    assert.equal(outcome.kind, 'released');
  });

  it('a status read that says the request is gone or the token is refused blocks at once', async () => {
    for (const status of [401, 403, 404]) {
      const calls = await expectBlocked({ reads: [http(status, 'NOPE')] }, `API_${status}_NOPE`);
      assert.equal(calls.reads, 1);
    }
  });

  it('a status read for another request or fingerprint', async () => {
    await expectBlocked({ reads: [pending({ requestId: `mcpreq_${'d'.repeat(32)}` })] }, 'FINGERPRINT_MISMATCH');
    await expectBlocked({ reads: [approved({}, { fingerprint: `sha256:${'9'.repeat(64)}` })] }, 'FINGERPRINT_MISMATCH');
  });

  it('"approved" without a receipt, or with one that does not verify: nothing is redeemed', async () => {
    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ ...approved(), receipt: null }, /^RECEIPT_MALFORMED$/],
      [approved({ expiresAt: new Date(Date.now() - 1000).toISOString() }), /^RECEIPT_EXPIRED$/],
      [approved({ fingerprint: fingerprintOfCall('filesystem', 'delete_file', { path: '/other' }) }), /^RECEIPT_FINGERPRINT_MISMATCH$/],
      [approved({ requestId: `mcpreq_${'e'.repeat(32)}` }), /^RECEIPT_REQUEST_MISMATCH$/],
      [approved({ status: 'DENIED' }), /^RECEIPT_NOT_APPROVED$/],
      [approved({ deciderId: 'system/pp-engine', deciderAuthMethod: null }), /^RECEIPT_DECIDER_NOT_HUMAN$/],
      [approved({ scope: 'demo' }), /^RECEIPT_DEMO_RECEIPT$/],
    ];
    for (const [view, code] of cases) {
      const calls = await expectBlocked({ reads: [view] }, code, { now: undefined });
      assert.equal(calls.redeems, 0, String(code));
    }
    const forged = approved();
    (forged.receipt as any).artifact.signature_b64 = Buffer.alloc(64, 1).toString('base64');
    assert.equal((await expectBlocked({ reads: [forged] }, 'RECEIPT_SIGNATURE_INVALID', { now: undefined })).redeems, 0);
    const stranger = testPpIssuer('pp-unpinned');
    const foreign = { ...approved(), receipt: { id: 'rcpt_1', artifact: mintCloudReceipt(stranger, { fingerprint: FINGERPRINT, requestId: REQUEST_ID, receiptId: 'rcpt_1' }) } };
    assert.equal((await expectBlocked({ reads: [foreign] }, 'RECEIPT_KEY_NOT_FOUND', { now: undefined })).redeems, 0);
  });

  it('a verified receipt that cannot be redeemed: already used, expired, frozen, unreachable', async () => {
    await expectBlocked({ reads: [approved()], redeem: http(409, 'ALREADY_REDEEMED') }, 'REDEEM_API_409_ALREADY_REDEEMED', { now: undefined });
    await expectBlocked({ reads: [approved()], redeem: http(410, 'RECEIPT_EXPIRED') }, 'REDEEM_API_410_RECEIPT_EXPIRED', { now: undefined });
    await expectBlocked({ reads: [approved()], redeem: http(423, 'REDEEM_BLOCKED') }, 'REDEEM_API_423_REDEEM_BLOCKED', { now: undefined });
    await expectBlocked({ reads: [approved()], redeem: down() }, 'REDEEM_API_UNREACHABLE', { now: undefined });
    await expectBlocked({ reads: [approved()], redeem: { requestId: REQUEST_ID, receiptId: 'rcpt_other', fingerprint: FINGERPRINT } }, 'REDEEM_MISMATCH', { now: undefined });
  });

  it('the same receipt offered for a second held call is refused before any redeem', async () => {
    const replayCache = new ReplayCache();
    const first = script({ reads: [approved()] });
    assert.equal((await run(first.client, { replayCache, now: undefined })).outcome.kind, 'released');
    const second = script({ reads: [approved()] });
    const { outcome } = await run(second.client, { replayCache, now: undefined });
    assert.equal(outcome.kind, 'blocked');
    if (outcome.kind === 'blocked') assert.equal(outcome.code, 'RECEIPT_REPLAYED');
    assert.equal(second.calls.redeems, 0);
  });
});
