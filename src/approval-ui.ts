export function getApprovalHTML(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Guard — Approval Queue</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: #0d1117; color: #c9d1d9; line-height: 1.5;
    padding: 24px; max-width: 900px; margin: 0 auto;
  }
  h1 { color: #58a6ff; font-size: 24px; margin-bottom: 4px; }
  .subtitle { color: #8b949e; font-size: 14px; margin-bottom: 24px; }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 12px;
    font-size: 12px; font-weight: 600; text-transform: uppercase;
  }
  .badge-pending { background: #d29922; color: #0d1117; }
  .badge-approved { background: #238636; color: #fff; }
  .badge-denied { background: #da3633; color: #fff; }
  .badge-allowed { background: #238636; color: #fff; }
  .badge-blocked { background: #da3633; color: #fff; }
  .badge-held_for_approval { background: #d29922; color: #0d1117; }
  .card {
    border: 1px solid #30363d; border-radius: 8px; padding: 16px;
    margin-bottom: 12px; background: #161b22;
  }
  .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .tool-name { font-size: 18px; font-weight: 700; color: #f0f6fc; }
  .meta { font-size: 13px; color: #8b949e; margin-bottom: 8px; }
  .meta span { margin-right: 16px; }
  .args-toggle {
    background: none; border: 1px solid #30363d; color: #58a6ff;
    padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 12px;
    margin-bottom: 8px;
  }
  .args-toggle:hover { border-color: #58a6ff; }
  .args-content {
    display: none; background: #0d1117; border: 1px solid #30363d;
    border-radius: 4px; padding: 12px; margin-bottom: 12px;
    font-family: 'SF Mono', Consolas, monospace; font-size: 13px;
    overflow-x: auto; white-space: pre-wrap; word-break: break-all;
  }
  .args-content.open { display: block; }
  .actions { display: flex; gap: 8px; }
  .btn {
    padding: 6px 16px; border-radius: 6px; border: none;
    font-size: 14px; font-weight: 600; cursor: pointer; transition: opacity 0.15s;
  }
  .btn:hover { opacity: 0.85; }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-approve { background: #238636; color: #fff; }
  .btn-deny { background: #da3633; color: #fff; }
  .empty {
    text-align: center; padding: 40px; color: #8b949e;
    border: 1px dashed #30363d; border-radius: 8px; margin-bottom: 24px;
  }
  h2 { color: #c9d1d9; font-size: 18px; margin: 24px 0 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px; border-bottom: 2px solid #30363d; color: #8b949e; font-weight: 600; }
  td { padding: 8px; border-bottom: 1px solid #21262d; }
  .pulse { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #3fb950; margin-right: 8px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
  .status-bar { display: flex; align-items: center; font-size: 12px; color: #8b949e; margin-bottom: 16px; }
</style>
</head>
<body>
<h1>MCP Guard — Approval Queue</h1>
<p class="subtitle">Human-in-the-loop approval for AI tool calls</p>
<div class="status-bar"><span class="pulse"></span> Polling every 3s</div>

<div id="pending"></div>
<h2>Recent Decisions</h2>
<div id="receipts"></div>

<script>
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function toggleArgs(btn) {
  const c = btn.nextElementSibling;
  c.classList.toggle('open');
  btn.textContent = c.classList.contains('open') ? '▾ Hide arguments' : '▸ Show arguments';
}

async function act(id, action) {
  const btns = document.querySelectorAll('[data-id="'+id+'"]');
  btns.forEach(b => b.disabled = true);
  try {
    const r = await fetch('/api/' + action + '/' + id, { method: 'POST' });
    if (!r.ok) { const e = await r.text(); alert('Error: ' + e); }
  } catch(e) { alert('Network error'); }
  refresh();
}

async function refresh() {
  try {
    const [pRes, rRes] = await Promise.all([
      fetch('/api/pending'), fetch('/api/receipts')
    ]);
    const pending = await pRes.json();
    const receipts = await rRes.json();

    const pEl = document.getElementById('pending');
    if (pending.length === 0) {
      pEl.innerHTML = '<div class="empty">No pending approvals</div>';
    } else {
      pEl.innerHTML = pending.map(p => \`
        <div class="card">
          <div class="card-header">
            <span class="tool-name">\${esc(p.tool_name)}</span>
            <span class="badge badge-pending">pending</span>
          </div>
          <div class="meta">
            <span>Agent: <strong>\${esc(p.agent_id)}</strong></span>
            <span>Rule: <strong>\${esc(p.rule_id)}</strong></span>
            <span>\${esc(new Date(p.timestamp).toLocaleTimeString())}</span>
          </div>
          <button class="args-toggle" onclick="toggleArgs(this)">▸ Show arguments</button>
          <div class="args-content">\${esc(JSON.stringify(p.tool_args, null, 2))}</div>
          <div class="actions">
            <button class="btn btn-approve" data-id="\${p.id}" onclick="act('\${p.id}','approve')">✅ Approve</button>
            <button class="btn btn-deny" data-id="\${p.id}" onclick="act('\${p.id}','deny')">❌ Deny</button>
          </div>
        </div>
      \`).join('');
    }

    const rEl = document.getElementById('receipts');
    if (receipts.length === 0) {
      rEl.innerHTML = '<div class="empty">No recent decisions</div>';
    } else {
      rEl.innerHTML = \`<table>
        <thead><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Agent</th><th>Rule</th></tr></thead>
        <tbody>\${receipts.map(r => \`<tr>
          <td>\${esc(new Date(r.timestamp).toLocaleTimeString())}</td>
          <td><strong>\${esc(r.tool_name)}</strong></td>
          <td><span class="badge badge-\${r.decision}">\${esc(r.decision)}</span></td>
          <td>\${esc(r.agent_id)}</td>
          <td>\${esc(r.rule_id || '—')}</td>
        </tr>\`).join('')}</tbody>
      </table>\`;
    }
  } catch(e) { /* retry next cycle */ }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>`;
}
