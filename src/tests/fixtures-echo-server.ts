// Test fixture: a stdio MCP-ish server that logs every line it receives and echoes requests.
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const log = process.env.ECHO_LOG!;
createInterface({ input: process.stdin }).on('line', (line) => {
  appendFileSync(log, line + '\n');
  let m: any;
  try { m = JSON.parse(line); } catch { return; }
  if (m && !Array.isArray(m) && m.id != null && m.method) {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { echoed: m.method, params: m.params ?? null } }) + '\n');
  }
});
