# Guarding built-in tools with hooks

A coding agent's most dangerous actions are its own tools, a shell and file edits, which never pass through an MCP proxy. `mcp-guard hook` runs the same policy over them through the agent's pre-tool hook: the same `pp.config.yaml`, the same rules and detectors, the same receipts log, and the same signed-approval path for held calls.

Claude Code is supported. The adapter interface (`src/hook/adapter.ts`) is built so Cursor and Codex can be added without touching the decision path (`src/hook/decide.ts`).

```bash
npm install --save-dev @permission-protocol/mcp-guard
npx mcp-guard keys init               # once per machine: every decision is signed
npx mcp-guard hook install            # writes .claude/settings.json in the current project
npx mcp-guard hook uninstall          # removes only the mcp-guard entry
```

## The Claude Code hook contract (verified)

Verified on 2026-11-12 against the official reference, **https://code.claude.com/docs/en/hooks**. Claude Code changes; re-check this page before relying on a detail below.

| What | Verified behaviour |
|------|--------------------|
| Input | One JSON object on stdin. Common fields include `session_id`, `cwd`, `permission_mode`, `hook_event_name`; PreToolUse adds `tool_name`, `tool_input`, `tool_use_id`. |
| `tool_input` | `Bash` / `PowerShell`: `command`, `description`, `timeout`, `run_in_background`. `Write`: `file_path`, `content`. `Edit`: `file_path`, `old_string`, `new_string`, `replace_all`. `Read`: `file_path`, `offset`, `limit`. For `Write`, `Edit`, `Read`, `file_path` is always absolute. |
| JSON answer | Exit 0 and print one JSON object: `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow" \| "deny" \| "ask" \| "defer", "permissionDecisionReason": "..."}}`. The `deny` reason is shown to Claude. Stdout must hold nothing but that object. |
| `allow` | Skips the permission prompt (with documented exceptions). The user's deny and ask permission rules are still evaluated whatever the hook returns. |
| No output, exit 0 | No decision: the call continues through the normal permission flow. |
| Exit 2 | Blocks the tool call; stderr is the reason Claude sees. JSON on stdout is still read but cannot override the block. |
| Other exit codes, crash, timeout, unparseable JSON | A *non-blocking* failure: **the call goes ahead**, unless the handler sets `"onFailure": "block"` (Claude Code v2.1.295 or later), in which case the failure blocks the call. |
| `timeout` | Per handler, in seconds. Default 600 for `command` hooks. On a timeout the hook is cancelled and its output discarded. |
| Settings | `~/.claude/settings.json` (all projects), `.claude/settings.json` (project, can be committed), `.claude/settings.local.json` (project, gitignored). Format: `hooks.PreToolUse[]` of `{ matcher, hooks: [{ type: "command", command, timeout, onFailure, statusMessage }] }`. |
| Matcher | `"*"`, `""` or omitted match all tools. Only letters, digits, `_`, `-`, spaces, `,` and `|`: exact names, `|`- or `,`-separated. Anything else: an unanchored JavaScript regex. |
| `${CLAUDE_PROJECT_DIR}` | The project root where the session started. |
| Several hooks | Precedence `deny` > `defer` > `ask` > `allow`. |

**Not verified:** behaviour against a real Claude Code install (the tests feed the documented event shape to the real CLI; no Claude Code binary was run); the `tool_input` shapes of `NotebookEdit` and `MultiEdit` (not in the reference's tables; they are guarded with their input passed as-is); what Claude Code shows the user while a hook waits (only that `statusMessage` exists); whether versions older than v2.1.295 ignore the `onFailure` key or reject it; the hook's working directory (the event carries `cwd`).

## What the hook answers

| Policy outcome | Hook answer |
|----------------|-------------|
| `allowed` | **No decision** (exit 0, empty stdout). Claude Code's own permission prompt and rules still apply. The guard only ever adds restrictions; it never turns a prompt off for a call no person approved. A signed policy receipt is logged. |
| `blocked` | `deny`, exit 2. Reason: `mcp-guard: blocked by rule "<id>" (<detector>: <kind>).` A signed policy receipt is logged. |
| `held_for_approval`, signed and verified | Opens a Permission Protocol request through the same `decideInCloud` the proxy uses, polls, verifies the receipt offline against the pinned keys (`cloud/verify.ts`), redeems it once, re-checks the fingerprint against the call Claude Code will run, then answers `allow` naming the receipt and the signer. |
| `held_for_approval`, anything else | `deny`, exit 2: rejected, frozen, expired, wait ran out, API unreachable, receipt refused, redeem failed, no install token, no `cloud:` section (local-only holds cannot wait for the local approval UI). |
| Policy unreadable, malformed stdin, wrong event, no signing key | `deny`, exit 2, for every call, including calls the policy would allow. |

A deny is answered twice: the JSON decision on stdout and exit 2 with the reason on stderr, so the call stays blocked even if stdout is polluted (for example by a shell profile). While deciding, the guard's own diagnostics (receipt lines, the signing link) are held back; on a deny, stderr is exactly the reason; otherwise they are written after the decision and land in Claude Code's debug log.

Reasons name rule ids, detector names and kinds, error codes and the signing link. Raw arguments never reach the reason, stderr, the receipts log or the resume file. As in the proxy, Permission Protocol receives the argument hash and a preview it redacts.

**`mode: observe`** (or `--mode observe`) behaves as in the proxy: everything goes through with no decision, policy decisions are signed and logged, holds are recorded and not sent for signature, and stderr says what would have been blocked or held.

## What the policy sees

The engine evaluates `tools/call` with the Claude Code tool name and these arguments:

| Tool | Arguments the policy reads and the signer approves |
|------|----------------------------------------------------|
| `Bash`, `PowerShell` | `{ command }` only. The model's `description`, `timeout` and `run_in_background` do not change what runs and are left out, so a retried call keeps its fingerprint. |
| Everything else | `tool_input` as it arrives (`Write`: `file_path`, `content`; `Edit`: `file_path`, `old_string`, `new_string`, `replace_all`; ...). |

Receipts and fingerprints use the server label `claude-code` and agent id `claude-code`, so a signer sees `claude-code / Bash`. A tool with no rule follows `default_action`.

```yaml
# pp.config.yaml, usable by the proxy and the hook at once
default_action: block
rules:
  - { id: no-secrets, tool: "*", detect: { detector: secret_read, args: [command, file_path] }, action: block }
  - { id: destructive-shell, tool: "*", detect: { detector: shell_destructive, args: [command] }, action: require_approval }
  - { id: infra, tool: "*", detect: { detector: terraform_destroy, args: [command] }, action: require_approval }
  - { id: cloud, tool: "*", detect: { detector: cloud_delete, args: [command] }, action: require_approval }
  - { id: bash, tool: Bash, action: allow }
  - { id: write, tool: Write, action: allow }
  - { id: edit, tool: Edit, action: allow }
cloud:
  approval_timeout_seconds: 600
```

`default_action: block` with the hook installed blocks every matched tool that has no rule. The install matcher only covers `Bash|PowerShell|Write|Edit|NotebookEdit`, so reads and searches are not sent to the guard. MCP tools (`mcp__...`) are not matched: wrap those servers with the proxy instead.

## Wait and timeout

- The hook waits `--wait` seconds (default **240**) for a signature, capped at the policy's `cloud.approval_timeout_seconds`.
- `hook install` writes `"timeout": wait + 60` (default **300**) and `"onFailure": "block"`. The margin covers the last status read and the redeem (each HTTP call is capped at 10 s). Claude Code's default would be 600 s; a shorter explicit value keeps a held call from freezing the session for ten minutes.
- The guard also answers `deny` on its own at `wait + 25` seconds, before Claude Code's timeout, because on Claude Code versions without `onFailure` a timed-out hook lets the call through.
- The approval request itself stays open for the full `cloud.approval_timeout_seconds`. When the wait runs out first, the denial names the request and its signing link and says: sign it, then run exactly the same call again. The guard remembers the open request by fingerprint (request id and expiry only, in `~/.config/mcp-guard/hook-requests.json`, mode 0600, or `PP_HOOK_STATE_PATH`) and the next identical call resumes it instead of opening a new one. A resumed request is checked exactly like a new one: its fingerprint must be this call's, and its receipt must verify, name this request, and redeem once.
- `--wait 0` opens the request and denies at once with the link; the retry after signing releases it.

The signing link is printed to stderr while the hook waits, but Claude Code does not show a running hook's stderr. Signers see pending requests in Permission Protocol; the denial carries the link when the wait runs out.

## Install

```bash
npx mcp-guard hook install [--project <dir>] [--config pp.config.yaml] [--wait 240] [--matcher "Bash|PowerShell|Write|Edit|NotebookEdit"] [--launcher "npx --no-install mcp-guard"]
```

It adds to `<project>/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Write|Edit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "npx --no-install mcp-guard hook --config \"${CLAUDE_PROJECT_DIR}\"/pp.config.yaml --wait 240",
            "timeout": 300,
            "onFailure": "block",
            "statusMessage": "mcp-guard: checking policy (a held call waits for a Permission Protocol signature)"
          }
        ]
      }
    ]
  }
}
```

- Idempotent: a second run changes nothing. A run with other options replaces the mcp-guard entry in place.
- Every other key, matcher group and hook is kept as it was.
- A settings file that is not valid JSON, or whose `hooks` / `hooks.PreToolUse` is not the documented shape, is refused and left untouched.
- `npx --no-install` never downloads: if the package is not installed, the hook fails to start and `onFailure: block` blocks the call. Install it as a dev dependency so the whole team runs the same version, or pass `--launcher`.
- `.claude/settings.json` is the shared, committed project file. Committing it guards every teammate's session in this repo.
- `hook uninstall` removes only handlers that run `mcp-guard ... hook --config`, and empty groups it leaves behind.

The receipts log is `pp-receipts.jsonl` in the hook's working directory, or `PP_SHARED_RECEIPTS_PATH`, as for the proxy.

## Limits

- A hook guards what the agent runs through its tools. Detectors are heuristics, not a sandbox (see [detectors](detectors.md#known-limits)).
- Anyone who can edit the project's or their own Claude Code settings can remove the hook, and commands run outside the agent are not seen. `hook install` writes only the project file.
- Requires Claude Code v2.1.295 or later for `onFailure`. On older versions, a hook that cannot start (package missing, Node missing) lets calls through; the guard's own watchdog still answers before the timeout.
