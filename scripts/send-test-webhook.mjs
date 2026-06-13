#!/usr/bin/env node
// Fire a signed GitHub-style PR webhook at a running deck so a "needs-authority"
// merge card appears live in the Decide lane.
//   PP_WEBHOOK_SECRET=... node scripts/send-test-webhook.mjs [port] [pr_number]
import crypto from 'node:crypto';

const PORT = process.argv[2] || '7700';
const PR = Number(process.argv[3] || 4242);
const SECRET = process.env.PP_WEBHOOK_SECRET || 'deck-webhook-secret';

const body = JSON.stringify({
  action: 'labeled',
  repository: { full_name: 'permission-protocol/mcp-guard' },
  pull_request: {
    number: PR,
    title: 'feat: wire real email adapter behind a flag',
    head: { sha: crypto.randomBytes(20).toString('hex') },
    html_url: `https://github.com/permission-protocol/mcp-guard/pull/${PR}`,
    labels: [{ name: 'needs-authority' }],
  },
});
const sig = 'sha256=' + crypto.createHmac('sha256', SECRET).update(body).digest('hex');

const res = await fetch(`http://localhost:${PORT}/api/github/webhook`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Hub-Signature-256': sig },
  body,
});
console.log(res.status, await res.text());
