/**
 * The built-in approval page. It is static and holds no secret: the access token
 * arrives in the URL fragment (`#t=…`, never sent to any server), is kept in
 * sessionStorage for this tab, and is sent as `Authorization: Bearer` on every call.
 */
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
  .badge-pending, .badge-held_for_approval { background: #d29922; color: #0d1117; }
  .badge-allowed { background: #238636; color: #fff; }
  .badge-blocked { background: #da3633; color: #fff; }
  .card {
    border: 1px solid #30363d; border-radius: 8px; padding: 16px;
    margin-bottom: 12px; background: #161b22;
  }
  .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .tool-name { font-size: 18px; font-weight: 700; color: #f0f6fc; }
  .meta { font-size: 13px; color: #8b949e; margin-bottom: 8px; }
  .meta span { margin-right: 16px; }
  .summary { margin-bottom: 8px; }
  .args-content {
    background: #0d1117; border: 1px solid #30363d;
    border-radius: 4px; padding: 12px; margin-bottom: 12px;
    font-family: 'SF Mono', Consolas, monospace; font-size: 13px;
    overflow-x: auto; white-space: pre-wrap; word-break: break-all;
  }
  .actions { display: flex; gap: 8px; }
  .btn {
    padding: 6px 16px; border-radius: 6px; border: none;
    font-size: 14px; font-weight: 600; cursor: pointer; transition: opacity 0.15s;
  }
  .btn:hover { opacity: 0.85; }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-approve { background: #238636; color: #fff; }
  .btn-deny { background: #da3633; color: #fff; }
  .empty, .notice {
    text-align: center; padding: 40px; color: #8b949e;
    border: 1px dashed #30363d; border-radius: 8px; margin-bottom: 24px;
  }
  .notice { color: #d29922; border-color: #d29922; }
  h2 { color: #c9d1d9; font-size: 18px; margin: 24px 0 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px; border-bottom: 2px solid #30363d; color: #8b949e; font-weight: 600; }
  td { padding: 8px; border-bottom: 1px solid #21262d; }
  .status-bar { display: flex; align-items: center; font-size: 12px; color: #8b949e; margin-bottom: 16px; }
</style>
</head>
<body>
<h1>MCP Guard — Approval Queue</h1>
<p class="subtitle">Human-in-the-loop approval for AI tool calls</p>
<div class="status-bar" id="status">Connecting…</div>

<div id="pending"></div>
<h2>Recent Decisions</h2>
<div id="receipts"></div>

<script>
(function () {
  var token = null;
  var m = location.hash.match(/(?:^#|&)t=([^&]+)/);
  if (m) {
    token = decodeURIComponent(m[1]);
    try { sessionStorage.setItem('mcp-guard-token', token); } catch (e) {}
    history.replaceState(null, '', location.pathname + location.search);
  } else {
    try { token = sessionStorage.getItem('mcp-guard-token'); } catch (e) {}
  }

  var statusEl = document.getElementById('status');
  var pEl = document.getElementById('pending');
  var rEl = document.getElementById('receipts');

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function api(path, method) {
    return fetch(path, { method: method || 'GET', headers: { Authorization: 'Bearer ' + token }, cache: 'no-store' });
  }

  function noToken(msg) {
    pEl.textContent = '';
    pEl.appendChild(el('div', 'notice', msg));
    statusEl.textContent = 'Not connected';
  }

  async function act(id, verb, btns) {
    btns.forEach(function (b) { b.disabled = true; });
    try {
      var r = await api('/api/' + verb + '/' + id, 'POST');
      if (!r.ok) statusEl.textContent = 'Could not ' + verb + ' (HTTP ' + r.status + ')';
    } catch (e) { statusEl.textContent = 'Network error'; }
    refresh();
  }

  function renderPending(pending) {
    pEl.textContent = '';
    if (pending.length === 0) { pEl.appendChild(el('div', 'empty', 'No pending approvals')); return; }
    pending.forEach(function (p) {
      var card = el('div', 'card');
      var head = el('div', 'card-header');
      head.appendChild(el('span', 'tool-name', p.tool_name));
      head.appendChild(el('span', 'badge badge-pending', p.acted ? 'ran · confirm' : 'pending'));
      card.appendChild(head);
      var meta = el('div', 'meta');
      meta.appendChild(el('span', null, 'Agent: ' + p.agent_id));
      meta.appendChild(el('span', null, 'Rule: ' + (p.rule_id || 'default action')));
      meta.appendChild(el('span', null, new Date(p.created_at).toLocaleTimeString()));
      if (p.countdown_remaining != null) meta.appendChild(el('span', null, 'Auto-releases in ' + p.countdown_remaining + 's'));
      card.appendChild(meta);
      card.appendChild(el('div', 'summary', p.summary));
      if (p.scope) {
        card.appendChild(el('div', 'meta', 'Approving signs for: ' + p.scope.scope
          + (p.scope.ref ? ' · ' + p.scope.ref : '') + (p.scope.sha ? ' @ ' + p.scope.sha : '')));
      }
      card.appendChild(el('div', 'args-content', p.args_full || p.args_preview));
      var actions = el('div', 'actions');
      var approve = el('button', 'btn btn-approve', p.acted ? 'Acknowledge' : 'Approve');
      var btns = [approve];
      approve.addEventListener('click', function () { act(p.id, 'approve', btns); });
      actions.appendChild(approve);
      if (!p.acted) {
        var deny = el('button', 'btn btn-deny', 'Deny');
        btns.push(deny);
        deny.addEventListener('click', function () { act(p.id, 'deny', btns); });
        actions.appendChild(deny);
      }
      card.appendChild(actions);
      pEl.appendChild(card);
    });
  }

  function renderReceipts(receipts) {
    rEl.textContent = '';
    if (receipts.length === 0) { rEl.appendChild(el('div', 'empty', 'No recent decisions')); return; }
    var table = el('table');
    var thead = el('thead'); var hr = el('tr');
    ['Time', 'Action', 'Decision', 'Approved by', 'Rule', 'Receipt'].forEach(function (h) { hr.appendChild(el('th', null, h)); });
    thead.appendChild(hr); table.appendChild(thead);
    var tbody = el('tbody');
    receipts.forEach(function (r) {
      var e = r.envelope || {};
      var tr = el('tr');
      tr.appendChild(el('td', null, new Date(e.issued_at).toLocaleTimeString()));
      tr.appendChild(el('td', null, e.tool || e.method));
      var td = el('td'); td.appendChild(el('span', 'badge badge-' + e.decision, e.decision)); tr.appendChild(td);
      tr.appendChild(el('td', null, e.approval ? e.approval.kind + ': ' + e.approval.id : '—'));
      tr.appendChild(el('td', null, e.rule_id || '—'));
      tr.appendChild(el('td', null, e.receipt_id));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    rEl.appendChild(table);
  }

  async function refresh() {
    if (!token) { noToken('Open the approval URL printed in the terminal. It ends with #t=… and carries the access token.'); return; }
    try {
      var res = await Promise.all([api('/api/pending'), api('/api/receipts')]);
      if (res[0].status === 401) { noToken('The access token is missing or wrong. Open the URL printed in the terminal again.'); return; }
      renderPending(await res[0].json());
      renderReceipts(await res[1].json());
      statusEl.textContent = 'Live · refreshes every 3s';
    } catch (e) { statusEl.textContent = 'Disconnected · retrying'; }
  }

  refresh();
  setInterval(refresh, 3000);
})();
</script>
</body>
</html>`;
}
