# Guarding built-in tools with hooks

A coding agent's most dangerous actions are its own tools, a shell and file edits, which never pass through an MCP proxy. `mcp-guard hook` runs the same policy over them through the agent's pre-tool hook: the same `pp.config.yaml`, the same rules and detectors, the same receipts log, and the same signed-approval path for held calls.

Claude Code is supported. The adapter interface (`src/hook/adapter.ts`) is built so Cursor and Codex can be added without touching the decision path (`src/hook/decide.ts`).

The one-command path, in the project:

```bash
npx -y @permission-protocol/mcp-guard init --preset coding-agent --hook claude-code   # policy, hook, local hook check, first signed receipt
```

By hand, with a policy you write:

```bash
npm install --save-dev @permission-protocol/mcp-guard
npx mcp-guard keys init               # once per machine: every decision is signed
npx mcp-guard hook install            # writes .claude/settings.json in the current project
npx mcp-guard hook uninstall          # removes only the mcp-guard entry
```

## Set up with `init --preset coding-agent`

`init --preset coding-agent` installs the hook when the project directory (the current directory, or `--project <dir>`) is a Claude Code project, meaning it has a `.claude/` directory or a `CLAUDE.md`. `--hook claude-code` installs it in any directory; `--no-hook` skips it. `--hook` needs `--preset coding-agent`. Without `--preset`, init does exactly what it did before and never touches `.claude/`. `init --help` lists every option.

In order, init: checks everything that can refuse (below); connects in the browser; creates a signing key if there is none, writes the policy and installs the hook; runs the local hook self-test; and holds a do-nothing call for your first signature.

Before the device login, so that a refusal changes nothing, init checks:

- `<project>/pp.config.yaml`: if absent, init writes the preset. If present and it loads under the strict loader, it is **kept byte for byte**, whether it is the preset, an edited preset or your own policy (init says which), and the hook reads it. If present and it does not load, init refuses with the loader's message: it never overwrites a policy.
- `<project>/.claude/settings.json`: the same checks as `hook install` (valid JSON, documented `hooks` shape), run as a dry run. A file that fails them is refused and left untouched (`SETTINGS_INVALID_JSON`, `SETTINGS_UNEXPECTED_SHAPE`).
- The launcher, chosen in this order and printed with the reason: `--launcher <cmd>` if given; `npx --no-install mcp-guard` if `@permission-protocol/mcp-guard` is installed in the project or a directory above it; otherwise `npx -y @permission-protocol/mcp-guard@<version>`, the exact version of the running package (never a range or `latest`). `<launcher> hook --help` must then run from the project directory under `sh`. If it does not (offline, a version not on the registry, a bad `--launcher`), the installed hook would block every guarded call, so init stops before changing anything.
- On Windows, Git Bash (below).
- MCP servers: with the hook, init wraps an MCP server only when `--server <name>` names one, and asks nothing about MCP servers otherwise. Without `--server` it changes no MCP config file; if it finds servers that are not wrapped yet (in `.mcp.json`, `~/.claude.json`, `.cursor/mcp.json` or `~/.cursor/mcp.json`), its summary says under `Guarded now:` that they are not guarded by this setup, lists each with its config file, and prints the command that wraps one: `npx @permission-protocol/mcp-guard@<this version> init --preset coding-agent --server <name>` (plus `--project`, `--mcp-config`, `--launcher` and a non-production `--api-url` when this run had them). That command logs in again, copies the client config aside, and wraps that server; the hook and `pp.config.yaml` stay as they are. A server listed at the top level of `~/.claude.json` (not under a project) is used by every Claude Code session on the machine, so wrapping it changes all of them. With `--server`, the client will start the guard with `npx -y @permission-protocol/mcp-guard@<this version>`, or `--wrap-launcher <cmd>`, and init checks that this command reports this exact version. `--wrap-launcher` without `--server` is refused.
- With no MCP server and no Claude Code project, `init --preset coding-agent` installs nothing unasked: it exits 1 and says to pass `--hook claude-code` to guard Claude Code's own tools in that directory, or to add an MCP server.

Each item is decided on its own. With the hook only (no `--server`), a stored install token is reused instead of logging in again; a missing token means a login. A missing signing key is created; a policy and a hook entry already in place are left as they are. A teammate who has the committed `pp.config.yaml` and `.claude/settings.json` but no token is logged in and gets a key, and neither file changes. When all four were in place, init runs the hook self-test, says `Already set up` and exits 0, whether or not unwrapped MCP servers exist. (When `--server` names an MCP server to wrap, init logs in as before.)

**The `npx -y` launcher.** The first guarded call in a session may download the package (a few seconds); later calls use npx's cache. The version is pinned in the committed `.claude/settings.json` and changes only when someone re-runs init or `hook install`. If npx cannot start the package (offline with an empty cache, the registry unreachable), the fail-closed wrapper below blocks the call; its fixed reason suggests installing the package as a dev dependency, which also removes the download. Installing it in the project (`npm install --save-dev @permission-protocol/mcp-guard`) before running init avoids the download from the start.

**Windows.** The installed command is shell form, which Claude Code runs through Git Bash on Windows, so init runs its launcher check and self-test through Git Bash too. It does not need Git's `bin` on PATH; it looks, in this order, at:

1. `CLAUDE_CODE_GIT_BASH_PATH`, if it names a file. This is the override Claude Code documents for finding Git Bash (https://code.claude.com/docs/en/setup, "Set up on Windows", checked 2026-11-12);
2. `sh.exe` or `bash.exe` on PATH (never `C:\Windows\System32\bash.exe`, which is WSL);
3. `Git\bin\bash.exe` under `%ProgramFiles%`, `%ProgramFiles(x86)%` and `%LocalAppData%\Programs`;
4. beside `git.exe` on PATH (`Git\cmd\git.exe` gives `Git\bin\bash.exe`).

If none is found, init refuses the hook step before changing anything and lists every place it looked (`--no-hook` skips the step). **Not verified:** the setup page documents only the override, not the order in which Claude Code itself searches, so this order is init's own; a Git Bash that init finds and Claude Code does not (or the reverse) is possible. Set `CLAUDE_CODE_GIT_BASH_PATH` in Claude Code's settings `env` to make both use the same one.

Policy paths in the hook command: a relative `--config` is joined to `"${CLAUDE_PROJECT_DIR}"`; an absolute one is used as given, including a drive-letter (`C:\...`, `C:/...`) or UNC (`\\server\share\...`) path on Windows. A drive-relative path (`C:pp.yaml`) is refused.

**The login.** init prints a Permission Protocol link and a pairing code, and opens the link in your browser when it runs in a terminal, under the same conditions as a held call (below): not when `CI` is set, in an SSH session, on Linux without a display, with `MCP_GUARD_OPEN_BROWSER=off`, or when the project's kept `pp.config.yaml` sets `cloud.open_browser: false`. Then it prints the link with `No browser was opened (<reason>). Open the link above.` `--no-browser` only prints it. Check that the page shows the same code and choose Connect (you need the owner or admin role in the workspace). In a terminal, init then asks you to confirm the workspace name. The install token goes to the OS keychain, or to a file restricted to your user ([where](../README.md#where-the-token-and-keys-are-kept)), and is never printed. If the code expires first, init stops with `The login expired before it was completed. Run the command again.`

Then, after the login: it writes `pp.config.yaml` (the preset plus the `cloud:` section; created only if still absent), installs the hook with the same code as `hook install` (idempotent: a second run never adds a second entry), wraps the MCP server that `--server` names, if any, and runs the **hook self-test**:

| Check | Event | Command run | Expected |
|-------|-------|-------------|----------|
| allowed | `Bash` `git status` (or `ls`, `pwd`: the first one the project's policy allows, checked in-process first) | the command exactly as installed in `.claude/settings.json`, with the project's policy | no decision (exit 0, empty stdout). Not run if the policy allows none of them outright, so a held test call can never open a request |
| held | `Bash` `terraform destroy -auto-approve` | the same launcher, `hook --config <temporary copy of the preset without cloud:> --wait 0` (the preset, not your policy, so the rule id is known) | `deny`, exit 2, naming rule `terraform-destroy` |

Nothing is sent to Permission Protocol and nothing runs: the hook only decides, an allowed call touches no network, and with no `cloud:` section a hold is denied locally instead of opening a signing request. The self-test's receipts go to `~/.config/mcp-guard/self-test-receipts.jsonl`, not the project's log. If a check fails, init exits 1 and says which of two things happened: **the self-test could not run** (no shell, or its temporary policy could not be written or read), which says nothing about the installed hook; or **the installed hook did not answer as expected**, in which case it stays installed and fails closed, so guarded calls may be blocked until it works. Both print the undo command, using the launcher the hook was installed with (`<launcher> hook uninstall --project <dir>`), so it works without a local install. `--skip-self-test` skips only the signed-receipt self-test that follows, not the hook check.

**First signature.** init then holds a do-nothing call through the real approval path, prints a signing link and opens it in your browser, under the same conditions as the login link. Sign it in Permission Protocol; init prints the signed receipt and the command that verifies it again. `--skip-self-test` skips this step, and it is not run when everything was already set up.

**What init prints at the end**, in this order: what is guarded and where the policy is (and the MCP servers it found and left unwrapped, with the command that wraps one); what happens the next time an agent tries something destructive; the restart line; `mcp-guard report` and the receipt verify command; how to undo each change (`To undo:`); and the setup details (`Set up:`).

Restart Claude Code so it loads the hook. Commit `pp.config.yaml` and `.claude/settings.json` to guard every teammate's session. The hook's receipts log is `pp-receipts.jsonl` beside `pp.config.yaml`, in the project root: add it to `.gitignore`.

## The Claude Code hook contract (verified)

Verified on 2026-11-12 against the official reference, **https://code.claude.com/docs/en/hooks**. Claude Code changes; re-check this page before relying on a detail below.

| What | Verified behaviour |
|------|--------------------|
| Input | One JSON object on stdin. Common fields include `session_id`, `cwd`, `permission_mode`, `hook_event_name`; PreToolUse adds `tool_name`, `tool_input`, `tool_use_id`. |
| `tool_input` | `Bash` / `PowerShell`: `command`, `description`, `timeout`, `run_in_background`. `Write`: `file_path`, `content`. `Edit`: `file_path`, `old_string`, `new_string`, `replace_all`. `Read`: `file_path`, `offset`, `limit`. For `Write`, `Edit`, `Read`, `file_path` is always absolute. |
| JSON answer | Exit 0 and print one JSON object: `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow" \| "deny" \| "ask" \| "defer", "permissionDecisionReason": "..."}}`. The `deny` reason is shown to Claude; an `allow` reason is written to the debug log only. Stdout must hold nothing but that object. |
| `additionalContext` | Inside `hookSpecificOutput`: a string Claude Code adds to Claude's context next to the tool result, as a system reminder. Not shown as a chat message. |
| `systemMessage` | Top level: a message shown to the user. |
| `statusMessage` | On the handler: a custom spinner message shown while the hook runs. Fixed text from the settings file. A hook's output is read only when it ends, so nothing the hook prints can be shown during the wait. |
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

**Not verified:** behaviour against a real Claude Code install (the tests feed the documented event shape to the real CLI; no Claude Code binary was run); the `tool_input` shapes of `NotebookEdit` and `MultiEdit` (not in the reference's tables; they are guarded with their input passed as-is); exactly how Claude Code renders `statusMessage` and `systemMessage` (only that the first is a spinner message and the second is shown to the user); whether versions older than v2.1.295 ignore the `onFailure` key or reject it; the wrapper below under Git Bash or PowerShell on a real Windows machine (it was tested under `sh` on Linux only); opening the signing page with `/usr/bin/open` on a real Mac or `rundll32` on a real Windows machine (the opener and its arguments are tested with a stand-in for spawn only).

## What the hook answers

| Policy outcome | Hook answer |
|----------------|-------------|
| `allowed` | **No decision** (exit 0, empty stdout). Claude Code's own permission prompt and rules still apply. The guard only ever adds restrictions; it never turns a prompt off for a call no person approved. A signed policy receipt is logged. |
| `blocked` | `deny`, exit 2. Reason: `mcp-guard: blocked by rule "<id>" (<detector>: <kind>).` A signed policy receipt is logged. |
| `held_for_approval`, signed and verified | Opens a Permission Protocol request through the same `decideInCloud` the proxy uses, opens the signing page in the browser (below), polls, verifies the receipt offline against the pinned keys (`cloud/verify.ts`), redeems it once, re-checks the fingerprint against the call Claude Code will run, then answers `allow` naming the receipt and the signer. `additionalContext` (for Claude) and `systemMessage` (for the person) say `Approved by <signer> through Permission Protocol. Receipt: <link>`: the signer from the verified receipt only, the link only if it is an `https:` page of `cloud.api_url`, else the verified receipt id. |
| `held_for_approval`, anything else | `deny`, exit 2: rejected, frozen, expired, wait ran out, API unreachable, receipt refused, redeem failed, no install token, no `cloud:` section (local-only holds cannot wait for the local approval UI). |
| Policy unreadable, malformed stdin, wrong event, no signing key | `deny`, exit 2, for every call, including calls the policy would allow. |

A deny is answered twice: the JSON decision on stdout and exit 2 with the reason on stderr, so the call stays blocked even if stdout is polluted (for example by a shell profile). While deciding, the guard's own diagnostics (receipt lines, the signing link) are held back; on a deny, stderr is exactly the reason; otherwise they are written after the decision and land in Claude Code's debug log.

Reasons name rule ids, detector names and kinds, error codes and the signing link. Arguments never reach the reason, stderr, the receipts log or the resume file.

**What is sent for a held call** (hook and proxy alike): the tool name, the server label, the agent id, the environment label, the SHA-256 hash of the arguments (`argsHash`), and a preview of the arguments that the guard masks and caps at 2,048 bytes before sending (`argsPreview`; omitted with `cloud.args_preview: false`). Nothing else: not the rule id, not what a detector found. For `Bash` and `PowerShell` the arguments are `{command}` (the model's `description` is not part of the call), so the preview carries the masked command; for `Write`, `Edit` and `NotebookEdit` it carries the path and as much masked content as fits after it. Masking (`src/cloud/preview.ts`): values under credential-like keys, private key blocks, credentials in URLs, Bearer / Basic / Token values, known token formats (GitHub, GitLab, npm, Slack, OpenAI, Anthropic, Stripe, Google, AWS key ids, JWTs, Permission Protocol keys), `password=` / `token=` / `.env`-style `SECRET_NAME=value` assignments, `--password value` style flags, and any run of 32 or more letters, digits, `_` or `-`. Short fields go first, so the cap cuts file content, not the path. Permission Protocol masks and caps the preview again on receipt. What masking does not catch: a short secret with no telling name around it (for example `mysql -pS3cret`). The signature covers `argsHash`, the exact arguments, never the preview. With `cloud.args_preview: false` the signer sees the tool, server, agent and environment but not what the call does.

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

The signing link is printed to stderr while the hook waits, but Claude Code does not show a running hook's stderr. So, while it waits:

- **The signing page opens in the browser** (`src/cloud/open-browser.ts`), the same in the proxy. Only an `https:` URL with no user name or password, on the origin of `cloud.api_url`, is opened; any other link is not opened and the hold goes on unchanged. The opener gets the URL as one argument with no shell: `/usr/bin/open` on macOS, `%SystemRoot%\System32\rundll32.exe url.dll,FileProtocolHandler <url>` on Windows, `xdg-open` elsewhere; detached, no stdio, started in the guard's config directory, errors ignored. At most once per request id; never for a resumed request. It cannot change the decision, delay the poll or throw. Off when `CI` is set, when `SSH_CONNECTION`, `SSH_CLIENT` or `SSH_TTY` is set, on Linux with neither `DISPLAY` nor `WAYLAND_DISPLAY`, with `MCP_GUARD_OPEN_BROWSER=off` (or `0`, `false`, `no`), with `cloud.open_browser: false`, and in init's self-tests. init's own pairing and self-test links follow the same conditions.
- **The hook's `statusMessage`**, `mcp-guard: checking this call. A held call waits here until a named person signs it.`, is shown beside Claude Code's spinner. It is the spinner text on every checked call, held or not, so it is short.

When the wait runs out, the denial gives Claude the link and says to run the same call again, for example:

```
mcp-guard: held by rule "terraform-destroy" (terraform_destroy: destroy) for a Permission Protocol signature; nobody signed within the hook's 240-second wait. Request <id> stays open for up to 600 seconds: sign it at <link>. After it is signed, run exactly the same call again; the guard resumes that request instead of opening a new one.
```

Its `systemMessage` shows the person the link and that the same call can be retried after someone signs. The retry resumes the same request and does not open a second tab. A retry with changed arguments does not match the signed receipt and is denied.

## Fail closed when the guard cannot run

Claude Code counts any exit other than 0 or 2 as a non-blocking failure, so a missing package (`127`), a crash (`1`) or a signal (`128+n`) would let the call through on versions without `onFailure`. The installed command is shell form and wraps the launcher in POSIX `sh`:

```sh
npx --no-install mcp-guard hook --config "${CLAUDE_PROJECT_DIR}"/pp.config.yaml --wait 240; c=$?; case $c in 0|2) exit $c;; 127) echo 'mcp-guard: the hook launcher was not found on the PATH Claude Code gave this hook (exit 127); call blocked. Start Claude Code from a terminal where npx works. To remove the hook, run the hook uninstall command init printed from that terminal, or delete the mcp-guard entry under hooks.PreToolUse in .claude/settings.json.' >&2; exit 2;; esac; echo 'mcp-guard: the guard did not run (missing package, crash or bad exit); call blocked. Fix: npm install --save-dev @permission-protocol/mcp-guard' >&2; exit 2
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
            "command": "npx --no-install mcp-guard hook --config \"${CLAUDE_PROJECT_DIR}\"/pp.config.yaml --wait 240; c=$?; case $c in 0|2) exit $c;; 127) echo '…not found on the PATH…' >&2; exit 2;; esac; echo '…did not run…' >&2; exit 2",
            "timeout": 300,
            "onFailure": "block",
            "statusMessage": "mcp-guard: checking this call. A held call waits here until a named person signs it."
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
- **The launcher must be on the PATH Claude Code runs hooks with.** Hooks run with Claude Code's environment. Started from the macOS Dock, Spotlight or an IDE, Claude Code may have a PATH without `npx` (for example without `/opt/homebrew/bin` or a version manager's directory). The shell then cannot find the launcher (exit 127), and the wrapper blocks every checked call with its own fixed message: the launcher was not found on that PATH, start Claude Code from a terminal where `npx` works, and remove the hook with `hook uninstall` from that terminal or by deleting the mcp-guard entry under `hooks.PreToolUse` in `.claude/settings.json` (uninstall itself needs the launcher). How the launcher is resolved is unchanged.
- **Claude Code before v2.1.295** (still in use; 2.1.86 was tested by hand on Windows) does nothing with `onFailure: "block"`. There the shell wrapper is the fail-closed layer: it turns a missing package, a crash or a signal into exit 2, which blocks. The one remaining case: a hook that Claude Code kills at its own timeout is not a block on those versions; the guard's watchdog denies at `wait + 25` seconds, before that timeout (`wait + 60`). init prints one line when `claude --version` reports an older version (read with a 5-second timeout; if it cannot be read, nothing is printed and init carries on).
