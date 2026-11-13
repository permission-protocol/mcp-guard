# Guarding built-in tools with hooks

A coding agent's most dangerous actions are its own tools, a shell and file edits, which never pass through an MCP proxy. `mcp-guard hook` runs the same policy over them through the agent's pre-tool hook: the same `pp.config.yaml`, the same rules and detectors, the same receipts log, and the same signed-approval path for held calls.

Claude Code is supported. The adapter interface (`src/hook/adapter.ts`) is built so Cursor and Codex can be added without touching the decision path (`src/hook/decide.ts`).

The one-command path, in the project:

```bash
npx @permission-protocol/mcp-guard init --preset coding-agent   # policy, hook, local hook check, first signed receipt
```

By hand, with a policy you write:

```bash
npm install --save-dev @permission-protocol/mcp-guard
npx mcp-guard keys init               # once per machine: every decision is signed
npx mcp-guard hook install            # writes .claude/settings.json in the current project
npx mcp-guard hook uninstall          # removes only the mcp-guard entry
```

## Set up with `init --preset coding-agent`

`init --preset coding-agent` installs the hook when the project directory (the current directory, or `--project <dir>`) is a Claude Code project, meaning it has a `.claude/` directory or a `CLAUDE.md`. `--hook claude-code` installs it in any directory; `--no-hook` skips it. `--hook` needs `--preset coding-agent`. Without `--preset`, init does exactly what it did before and never touches `.claude/`.

Before the device login, so that a refusal changes nothing, init checks:

- `<project>/pp.config.yaml`: if absent, init writes the preset. If present and it loads under the strict loader, it is **kept byte for byte**, whether it is the preset, an edited preset or your own policy (init says which), and the hook reads it. If present and it does not load, init refuses with the loader's message: it never overwrites a policy.
- `<project>/.claude/settings.json`: the same checks as `hook install` (valid JSON, documented `hooks` shape), run as a dry run. A file that fails them is refused and left untouched (`SETTINGS_INVALID_JSON`, `SETTINGS_UNEXPECTED_SHAPE`).
- The launcher, chosen in this order and printed with the reason: `--launcher <cmd>` if given; `npx --no-install mcp-guard` if `@permission-protocol/mcp-guard` is installed in the project or a directory above it; otherwise `npx -y @permission-protocol/mcp-guard@<version>`, the exact version of the running package (never a range or `latest`). `<launcher> hook --help` must then run from the project directory under `sh`. If it does not (offline, a version not on the registry, a bad `--launcher`), the installed hook would block every guarded call, so init stops before changing anything.
- An MCP server to wrap is optional with the hook. With none (or every one already wrapped), init sets up the hook alone.
- With no MCP server and no Claude Code project, `init --preset coding-agent` installs nothing unasked: it exits 1 and says to pass `--hook claude-code` to guard Claude Code's own tools in that directory, or to add an MCP server.

Each item is decided on its own. With the hook only (no server to wrap), a stored install token is reused instead of logging in again; a missing token means a login. A missing signing key is created; a policy and a hook entry already in place are left as they are. A teammate who has the committed `pp.config.yaml` and `.claude/settings.json` but no token is logged in and gets a key, and neither file changes. When all four were in place, init runs the hook self-test, says `Already set up` and exits 0. (When an MCP server is wrapped, init logs in as before.)

**The `npx -y` launcher.** The first guarded call in a session may download the package (a few seconds); later calls use npx's cache. The version is pinned in the committed `.claude/settings.json` and changes only when someone re-runs init or `hook install`. If npx cannot start the package (offline with an empty cache, the registry unreachable), the fail-closed wrapper below blocks the call; its fixed reason suggests installing the package as a dev dependency, which also removes the download.

**Windows.** init's hook step and the installed command need Git Bash (`sh`). Without it, init's launcher check cannot run and init refuses the hook step and says so (`--no-hook` skips it).

Then, after the login: it writes `pp.config.yaml` (the preset plus the `cloud:` section; created only if still absent), installs the hook with the same code as `hook install` (idempotent: a second run never adds a second entry), wraps the MCP server if there is one, and runs the **hook self-test**:

| Check | Event | Command run | Expected |
|-------|-------|-------------|----------|
| allowed | `Bash` `git status` (or `ls`, `pwd`: the first one the project's policy allows, checked in-process first) | the command exactly as installed in `.claude/settings.json`, with the project's policy | no decision (exit 0, empty stdout). Not run if the policy allows none of them outright, so a held test call can never open a request |
| held | `Bash` `terraform destroy -auto-approve` | the same launcher, `hook --config <temporary copy of the preset without cloud:> --wait 0` (the preset, not your policy, so the rule id is known) | `deny`, exit 2, naming rule `terraform-destroy` |

Nothing is sent to Permission Protocol and nothing runs: the hook only decides, an allowed call touches no network, and with no `cloud:` section a hold is denied locally instead of opening a signing request. The self-test's receipts go to `~/.config/mcp-guard/self-test-receipts.jsonl`, not the project's log. If a check fails, the hook stays installed and fails closed (guarded calls are blocked), init says so with the undo command and exits 1. `--skip-self-test` skips only the signed-receipt self-test that follows, not the hook check.

The hook's receipts log is `pp-receipts.jsonl` beside `pp.config.yaml`, in the project root: add it to `.gitignore` if you commit the project's guard files.

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
| `${CLAUDE_PROJECT_DIR}` | The project root where the session started; also exported as an environment variable to the hook. |
| Execution | **Shell form** (no `args`): the `command` string runs under `sh -c` on macOS and Linux, Git Bash on Windows, or PowerShell on Windows when Git Bash is not installed; the `shell` field (`"bash"` or `"powershell"`) overrides it. **Exec form** (`args` present): `command` is spawned directly with no shell; on Windows it must be a real executable, not an npm `.cmd` shim. |
| Working directory | "Handlers run in the current directory with Claude Code's environment", falling back to the session's start directory, the project root, home or temp if that directory was deleted. |
| Windows without Git Bash | A failing shell-form PreToolUse hook with `onFailure` unset blocks the call: only exit 0 or 2 counts as a verdict. |
| Several hooks | Precedence `deny` > `defer` > `ask` > `allow`. |

**Not verified:** behaviour against a real Claude Code install (the tests feed the documented event shape to the real CLI; no Claude Code binary was run); the `tool_input` shapes of `NotebookEdit` and `MultiEdit` (not in the reference's tables; they are guarded with their input passed as-is); what Claude Code shows the user while a hook waits (only that `statusMessage` exists); whether versions older than v2.1.295 ignore the `onFailure` key or reject it; the wrapper below under Git Bash or PowerShell on a real Windows machine (it was tested under `sh` on Linux only).

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

**`observe: true` rules** behave as in the proxy: when one matches (the preset's `secret-read`), the call's outcome is what it would be without that rule, stderr says `OBSERVE: Matched rule "<id>" (<detector>: <kind>) would hold "<tool>"; not enforced (observe: true)`, and the receipts log gets an unsigned `{"observed": ...}` line with the rule id, detector, kind, tool, agent and input hash. Never the arguments or the path that was read.

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

## Fail closed when the guard cannot run

Claude Code counts any exit other than 0 or 2 as a non-blocking failure, so a missing package (`127`), a crash (`1`) or a signal (`128+n`) would let the call through on versions without `onFailure`. The installed command is shell form and wraps the launcher in POSIX `sh`:

```sh
npx --no-install mcp-guard hook --config "${CLAUDE_PROJECT_DIR}"/pp.config.yaml --wait 240; c=$?; case $c in 0|2) exit $c;; esac; echo 'mcp-guard: the guard did not run (missing package, crash or bad exit); call blocked. Fix: npm install --save-dev @permission-protocol/mcp-guard' >&2; exit 2
```

- Exit 0 and exit 2 pass through unchanged; stdout is the guard's own. Every other exit becomes 2 with that fixed reason.
- Works under `sh -c` (macOS, Linux) and Git Bash (Windows), the shells Claude Code uses for shell form.
- **Not portable to PowerShell** (Windows without Git Bash): the `case` syntax does not parse there. That case is still blocked: Claude Code documents that without Git Bash a failing PreToolUse hook blocks even with `onFailure` unset, and `onFailure: "block"` is the second layer everywhere.
- It cannot help when Claude Code itself kills the hook at its timeout; the guard's own watchdog (below) and `onFailure: "block"` cover that.

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
            "command": "npx --no-install mcp-guard hook --config \"${CLAUDE_PROJECT_DIR}\"/pp.config.yaml --wait 240; c=$?; case $c in 0|2) exit $c;; esac; echo '…did not run…' >&2; exit 2",
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
- `npx --no-install` never downloads: if the package is not installed, the launcher fails, the wrapper turns that into exit 2, and `onFailure: block` backs it up. Install it as a dev dependency so the whole team runs the same version, or pass `--launcher`.
- `.claude/settings.json` is the shared, committed project file. Committing it guards every teammate's session in this repo.
- `hook uninstall` removes only handlers that run `mcp-guard ... hook --config` (wrapped or not, so entries from earlier versions are found too), and empty groups it leaves behind.

**Receipts log.** `PP_SHARED_RECEIPTS_PATH` if set; otherwise `pp-receipts.jsonl` **beside the policy file** (the directory of the resolved `--config` path), not in the working directory: Claude Code runs hooks in its current directory, which moves as the session `cd`s, and a cwd-relative log would scatter. The proxy keeps its own default (the working directory).

## Limits

- A hook guards what the agent runs through its tools. Detectors are heuristics, not a sandbox (see [detectors](detectors.md#known-limits)).
- Anyone who can edit the project's or their own Claude Code settings can remove the hook, and commands run outside the agent are not seen. `hook install` writes only the project file.
- Each guarded tool call (`Bash`, `Write`, `Edit`, ...) starts a new process through the launcher, which adds process-start latency to every one. Measured locally (Linux, 2 vCPU, Node 22.23, an allowed `Bash` call through the installed wrapper, average of 10 runs): **about 310-320 ms per call** with the default `npx --no-install mcp-guard`; about 90 ms with `--launcher '"${CLAUDE_PROJECT_DIR}"/node_modules/.bin/mcp-guard'` (bare `node -e 0` is about 26 ms). Held calls add the signing wait.
- Requires Claude Code v2.1.295 or later for `onFailure`. On older versions the installed command's exit-code wrapper still turns a missing package or crash into exit 2, and the guard's own watchdog answers before the timeout; a hook killed at Claude Code's timeout is not covered.
