import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseFrame, isPassthrough, stripAgentMetadata, toolCallTarget, PARSE_ERROR, INVALID_REQUEST } from '../frame.js';

describe('JSON-RPC framing (fail closed)', () => {
  it('rejects a line that is not JSON with -32700', () => {
    const f = parseFrame('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x","arguments":{"v":NaN}}}');
    assert.equal(f.kind, 'invalid');
    assert.equal(f.kind === 'invalid' && f.code, PARSE_ERROR);
  });

  it('rejects batches with -32600', () => {
    const f = parseFrame(JSON.stringify([{ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'x' } }]));
    assert.equal(f.kind, 'invalid');
    assert.equal(f.kind === 'invalid' && f.code, INVALID_REQUEST);
  });

  it('rejects malformed frames with -32600', () => {
    for (const bad of [
      '"just a string"',
      '42',
      'null',
      '{"id":1,"method":"tools/call"}',
      '{"jsonrpc":"1.0","id":1,"method":"tools/call"}',
      '{"jsonrpc":"2.0","id":1,"method":7}',
      '{"jsonrpc":"2.0","id":{"x":1},"method":"tools/call"}',
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"str"}',
      '{"jsonrpc":"2.0"}',
    ]) {
      const f = parseFrame(bad);
      assert.equal(f.kind, 'invalid', bad);
      assert.equal(f.kind === 'invalid' && f.code, INVALID_REQUEST, bad);
    }
  });

  it('keeps the id on an invalid frame when it is valid', () => {
    const f = parseFrame('{"jsonrpc":"1.0","id":9,"method":"x"}');
    assert.equal(f.kind === 'invalid' && f.id, 9);
  });

  it('classifies requests, notifications and responses', () => {
    assert.equal(parseFrame('{"jsonrpc":"2.0","id":1,"method":"ping"}').kind, 'request');
    assert.equal(parseFrame('{"jsonrpc":"2.0","method":"notifications/initialized"}').kind, 'notification');
    assert.equal(parseFrame('{"jsonrpc":"2.0","id":1,"result":{}}').kind, 'response');
    assert.equal(parseFrame('{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x"}}').kind, 'response');
  });

  it('last duplicate key wins, and the guard forwards that same object', () => {
    const f = parseFrame('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","name":"deploy"}}');
    assert.equal(f.kind, 'request');
    const t = f.kind === 'request' ? toolCallTarget(f.msg.params) : null;
    assert.deepEqual(t, { name: 'deploy', args: undefined });
  });

  it('passes plumbing through and gates everything else', () => {
    for (const m of ['initialize', 'ping', 'tools/list', 'resources/list', 'resources/templates/list', 'prompts/list', 'logging/setLevel', 'completion/complete', 'notifications/initialized', 'notifications/cancelled']) {
      assert.equal(isPassthrough(m), true, m);
    }
    for (const m of ['tools/call', 'resources/read', 'prompts/get', 'resources/subscribe', 'sampling/createMessage', 'x/unknown']) {
      assert.equal(isPassthrough(m), false, m);
    }
  });

  it('validates tools/call params', () => {
    assert.ok('error' in toolCallTarget(undefined));
    assert.ok('error' in toolCallTarget({ name: 5 }));
    assert.ok('error' in toolCallTarget({ name: 'x', arguments: [1] }));
    assert.deepEqual(toolCallTarget({ name: 'x', arguments: { a: 1 } }), { name: 'x', args: { a: 1 } });
  });

  it('strips _pp from tool arguments only', () => {
    const msg = { jsonrpc: '2.0' as const, id: 1, method: 'tools/call', params: { name: 'spend', arguments: { amount: 5, _pp: { confidence: 9 } } } };
    assert.deepEqual(stripAgentMetadata(msg).params, { name: 'spend', arguments: { amount: 5 } });
    assert.deepEqual(msg.params.arguments._pp, { confidence: 9 }, 'original untouched');
  });
});
