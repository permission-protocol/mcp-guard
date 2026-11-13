# MCP Guard

MCP Guard is a free guard for coding agents. It checks each shell command and file edit that Claude Code is about to run: destructive ones wait until a named person signs them in Permission Protocol, and only a verified, signed receipt lets them run. Everything else runs as before.

## Install for Claude Code

In your project folder, run:

```bash
npx -y @permission-protocol/mcp-guard init --preset coding-agent --hook claude-code
```

This works in any folder. In a folder that already has `.claude/` or `CLAUDE.md`, you can leave out `--hook claude-code`.

### What you need

- A free Permission Protocol account with the owner or admin role in a workspace. Sign up at https://app.permissionprotocol.com/guard. If you have no passkey yet, your first signature sets one up.
- Node.js with `npx`.
- On Windows, Git for Windows: Claude Code runs the hook through Git Bash.

### What the command does

1. It prints a pairing code and opens a Permission Protocol page in your browser. Over SSH, in CI or on Linux without a display it prints the link instead and says why. Check that the page shows the same code and choose Connect.
2. It writes the `coding-agent` policy to `pp.config.yaml` and adds the hook to `.claude/settings.json`.
3. It runs a local self-test of the hook. Nothing is sent and nothing runs.
4. It holds one do-nothing test call and opens its signing page. Sign it to get your first receipt.
5. It tells you to restart Claude Code, which then loads the hook.

It also stores an install token (in the OS keychain, or in a file restricted to your user) and creates a local signing key under `~/.config/mcp-guard/`. An existing `pp.config.yaml` that loads is kept as it is. It does not change any MCP server: init lists the ones it found that are not wrapped yet and prints the command that guards one (`init --preset coding-agent --server <name>`). The checks that can refuse run before the login, so a refusal changes nothing. Every step in detail: [docs/hooks.md](docs/hooks.md#set-up-with-init---preset-coding-agent).

### What a held call looks like

- The signing page opens in your browser. It does not open over SSH, in CI, on Linux without a display, or when you switch it off ([details](#no-browser-opened)). Waiting calls are also listed at https://app.permissionprotocol.com/guard.
- A named person chooses Sign or Reject. A rejected call is denied.
- After a signature, the receipt is verified offline against keys pinned in the package and redeemed once, and the call runs. Claude is told `Approved by <name> through Permission Protocol. Receipt: <link>`, and you see the same line.
- If nobody signs within 240 seconds, the call is denied with the signing link. Sign it, then retry the same call.

### See what it did

In the project folder:

```bash
npx -y @permission-protocol/mcp-guard report
```

It reads the local log only and sends nothing ([details](#what-it-decided-mcp-guard-report)).

### Remove it

In the project folder:

```bash
npx -y @permission-protocol/mcp-guard hook uninstall
```

This removes only the mcp-guard entry from `.claude/settings.json`. At the end of its run, init prints the exact command for your setup under `To undo:`. What else init changed:

- `pp.config.yaml` (unless one was already there) and, once calls are checked, the log `pp-receipts.jsonl` beside it. Delete them if you no longer want them.
- The install token and the signing key stay on this machine for other projects ([where](#where-the-token-and-keys-are-kept)). To disconnect the machine, revoke its token in your workspace under Settings > Developer access.
- If you ran init with `--server <name>`, `To undo:` names the backup to copy back over that MCP config file.

### More

- [What is guarded](#what-is-guarded)
- [What it does not catch](#what-it-does-not-catch)
- What leaves this machine: [for a held call](#what-is-sent-to-permission-protocol-for-a-held-call), and the [daily usage heartbeat](#usage-heartbeat), which is on by default
- [MCP servers: the proxy](#mcp-servers-the-proxy)
- [Troubleshooting](#troubleshooting)

## What is guarded

The hook sees Claude Code's `Bash`, `PowerShell`, `Write`, `Edit` and `NotebookEdit` calls. The `coding-agent` preset holds these for a signature (the same rules apply to MCP tools when the preset guards a wrapped server):

| Rule | Holds |
|------|-------|
| `destructive-shell` | `rm -rf` outside the working tree, force pushes and pushes to `main`, disk writes, destructive SQL through `psql -c` and similar |
| `destructive-sql` | `DROP`, `TRUNCATE`, `DELETE` / `UPDATE` without `WHERE`, in the SQL argument of an MCP database tool (`sql`, `query`, ...) |
| `terraform-destroy` | `terraform destroy`, `apply -destroy`, `apply -auto-approve` without a saved plan |
| `cloud-delete` | Cloud and Kubernetes deletes of databases, volumes, buckets, snapshots, clusters, namespaces |
| `production-target` | Any call naming a production target you list under `targets:` (empty by default, so it matches nothing until you add names) |
| `guard-tamper*` | Changes to the guard itself: its policy, receipt log, keys, install token, the hook entry and Claude Code settings files, killing it |

Secret reads (`cat .env`, `printenv`, token printers) are recorded only (`secret-read` has `observe: true`) until you delete that line. A command the detectors cannot read (`eval`, `python -c`, `curl | sh`) is held. Everything else runs, and Claude Code's own permission prompts still apply to it: the guard only adds restrictions.

## What it does not catch

The detectors are heuristics that stop mistakes. They are not a sandbox.

- **Scripts in files.** Anything run from a file (`./cleanup.sh`, `python x.py`, `make`, `npm run`) is not read. An agent can write a file in one call and run it in the next.
- **Removing the hook.** An agent running as the same OS user can, by a route the detectors do not read (a script, for example), edit the settings file or the policy and switch the guard off. Run untrusted agents as a separate OS user that cannot write the guard's files.
- **Tools the hook does not see.** Reads and searches are not sent to the guard. MCP tools (`mcp__...`) are not matched by the hook; wrap those servers with the proxy (below).
- **Context that needs I/O**: the current git branch, the current kube context, what a variable or glob expands to, plan files and manifests.
- **Claude Code before 2.1.295** ignores the hook's `onFailure: "block"`. The installed command's own wrapper still blocks when the guard cannot run; the one case left is a hook that Claude Code kills at its own timeout, which on those versions lets the call through, and the guard's watchdog denies before that timeout ([troubleshooting](#claude-code-older-than-21295)).
- **The first guarded call may download the package** with the default `npx -y` launcher ([how the launcher is chosen](docs/hooks.md#set-up-with-init---preset-coding-agent)).
- Each guarded call starts a process through the launcher, which adds latency ([measured in docs/hooks.md](docs/hooks.md#limits)).

The full lists: [docs/presets.md](docs/presets.md) and [docs/detectors.md](docs/detectors.md#known-limits).

## Troubleshooting

### Every guarded call is blocked: "the hook launcher was not found"

```
mcp-guard: the hook launcher was not found on the PATH Claude Code gave this hook (exit 127); call blocked. Start Claude Code from a terminal where npx works. To remove the hook, run the hook uninstall command init printed from that terminal, or delete the mcp-guard entry under hooks.PreToolUse in .claude/settings.json.
```

Claude Code was started with a `PATH` that has no `npx`, for example from the macOS Dock, Spotlight or an IDE. Quit it and start it from a terminal where `npx` works. To remove the hook instead, run `hook uninstall` from such a terminal ([Remove it](#remove-it)), or delete the mcp-guard entry under `hooks.PreToolUse` in `.claude/settings.json` (uninstall itself needs the launcher).

### Every guarded call is blocked: "the guard did not run"

```
mcp-guard: the guard did not run (missing package, crash or bad exit); call blocked. Fix: npm install --save-dev @permission-protocol/mcp-guard
```

The launcher ran but the guard did not: for example, `npx` could not fetch the package (offline with an empty npx cache, or the registry unreachable), or the guard crashed. Install it in the project with `npm install --save-dev @permission-protocol/mcp-guard`, then run init again: the hook then starts the guard with `npx --no-install mcp-guard`, which never downloads.

### init stops: the launcher did not start mcp-guard

```
[mcp-guard] "<launcher>" did not start mcp-guard from <project> (exit <n>). The hook would block every guarded call, so init stopped before changing anything. ...
```

Nothing was changed. Check the network (npx fetches the package once), or install the package in the project as above, then run init again.

### Windows: "Git Bash was not found"

```
[mcp-guard] Git Bash was not found (looked at: ...). The Claude Code hook runs through Git Bash on Windows: install Git for Windows (https://git-scm.com/downloads/win), or set CLAUDE_CODE_GIT_BASH_PATH to its bash.exe, then run init again. Or pass --no-hook. ...
```

Nothing was changed. Install Git for Windows, or set `CLAUDE_CODE_GIT_BASH_PATH`, and run the command again. Where init looks: [docs/hooks.md](docs/hooks.md#set-up-with-init---preset-coding-agent).

### "The login expired before it was completed"

```
[mcp-guard] The login expired before it was completed. Run the command again.
```

The pairing code lasts 10 minutes. Run the install command again to get a new one.

### Nobody signed in time

Claude is told:

```
mcp-guard: held by rule "<rule>" (...) for a Permission Protocol signature; nobody signed within the hook's 240-second wait. Request <id> stays open for up to 600 seconds: sign it at <link>. After it is signed, run exactly the same call again; the guard resumes that request instead of opening a new one.
```

You see `mcp-guard: a held "<tool>" call is still waiting for a signature. After someone signs, the same call can be retried. Signing link: <link>`. Sign it, then have Claude run exactly the same call again. After the request expires (600 seconds with the default policy), the same call opens a new request.

### No browser opened

The signing page is not opened, and neither are init's own links, when `CI` is set, in an SSH session, on Linux with neither `DISPLAY` nor `WAYLAND_DISPLAY`, with `MCP_GUARD_OPEN_BROWSER=off`, or with `open_browser: false` under `cloud:`. Find the waiting call at https://app.permissionprotocol.com/guard and sign it there. Claude Code shows nothing from the hook until it ends, so otherwise the link arrives with the denial after 240 seconds.

### No email arrives when a call is held

Hold emails are sent by Permission Protocol, not by the guard. None arrives when your Permission Protocol account has no email address, or when hold emails are turned off. Check Settings > Notifications at https://app.permissionprotocol.com/c/settings#hold-emails.

### Claude Code older than 2.1.295

init prints:

```
Note: Claude Code <version> is older than 2.1.295 and ignores the hook's onFailure: "block" setting. ...
```

The hook still works: its wrapper blocks a guard that fails to run, and the guard denies a held call before Claude Code's own timeout. Update Claude Code to close the one remaining case, a hook that Claude Code kills at its timeout ([details](docs/hooks.md#limits)).

## What is sent to Permission Protocol for a held call

Only for a held call that waits for a signature (allowed and blocked calls send nothing): the tool name, the server label (`claude-code` for the hook), the agent id, the environment label, the SHA-256 hash of the arguments, and a **preview of the arguments that the guard masks and caps before sending**. Nothing else: not the rule id, not what a detector found. For a `Bash` call the preview is the command; for `Write` or `Edit`, the file path and as much file content as fits.

- Masked on this machine: values under credential-like keys, private key blocks, credentials in URLs, Bearer and Basic values, common token formats (GitHub, OpenAI, Anthropic, AWS key ids, Stripe, Slack, JWTs and others), `password=` / `token=` / `.env`-style assignments with secret-looking names, and long opaque strings. Pattern-based: a short secret with no telling name (`mysql -pS3cret`) is not recognised.
- Short fields first, then capped at 2,048 bytes, so the cap cuts file content, not the path.
- Permission Protocol masks and caps it again before storing it. The signature covers the hash of the exact arguments, never the preview.
- To send the hash only, put `args_preview: false` under `cloud:`. The signer then sees the tool, server, agent and environment, not what the call does.

Details: [docs/hooks.md](docs/hooks.md#what-the-hook-answers).

## Usage heartbeat

**On by default.** With a `cloud:` section in the policy (init writes one) and an install token, the guard sends Permission Protocol the day's totals so far, at most one attempt every 10 minutes (the last one per UTC day counts), from a separate process that cannot allow, block or delay a call. It carries only: the guard version, a fixed client label (`claude-code`, `mcp-proxy` or `mcp-guard`), the mode, the day, six counts (`allowed`, `blocked`, `held`, `approved`, `denied`, `expired`), and how many calls each **built-in** rule id (the `coding-agent` preset's) blocked or held. Your own rule ids, arguments, commands, paths, file contents, tool, server and target names, hostnames and usernames are never sent.

```bash
npx @permission-protocol/mcp-guard heartbeat --show   # print exactly what would be sent today; sends nothing
```

Turn it off with `MCP_GUARD_HEARTBEAT=off` in the guard's environment, or with `heartbeat: false` under `cloud:` in the policy. Details: [docs/heartbeat.md](docs/heartbeat.md).

## What it decided: `mcp-guard report`

```bash
npx @permission-protocol/mcp-guard report               # last 7 days of the log beside ./pp.config.yaml
npx @permission-protocol/mcp-guard report --config path/to/pp.config.yaml --json
```

Per UTC day and in total: allowed, blocked, held, approved, denied, expired, the rules that blocked or held most, and observe-only matches. It reads the local receipt log only (`PP_SHARED_RECEIPTS_PATH` if set, else `pp-receipts.jsonl` beside the policy), sends nothing, and never prints arguments.

## MCP servers: the proxy

The same policy also runs as a stdio proxy between an MCP client and an MCP server. Every `tools/call`, `resources/read`, `prompts/get` and unknown method goes through the rules; only protocol plumbing (`initialize`, `ping`, list calls, notifications) passes untouched. Blocked calls get `-32001`; held calls wait for a signature (with a `cloud:` section) or for the local approval UI.

```bash
npm install @permission-protocol/mcp-guard
npx mcp-guard keys init            # once: every decision is signed; the guard never creates a key itself

cat > pp.config.yaml << 'EOF'
default_action: allow
rules:
  - { id: block-delete, tool: delete_user_data, action: block }
  - { id: hold-deploy, tool: deploy_production, action: require_approval }
EOF

npx mcp-guard --config pp.config.yaml -- node my-mcp-server.js
```

`npx @permission-protocol/mcp-guard init` (without `--preset`) does this for an MCP server already configured in Claude Code or Cursor: it connects to Permission Protocol, wraps the server you pick (the client config is copied aside first), writes a policy that holds one tool, and holds a test call for your first signature. With `--preset coding-agent` in a Claude Code project, init sets up the hook and wraps a server only when `--server <name>` names one. The client then starts the guard with `npx -y @permission-protocol/mcp-guard@<this version>`; init checks that command reports this version before changing anything. To start it another way (a project install, a source checkout), pass `--wrap-launcher "<command>"`, for example `--wrap-launcher "node <checkout>/bin/mcp-guard"`: words are split on spaces, double quotes group a path with spaces, and the client runs it without a shell.

Proxy options: `--config <path>`, `--agent-id <id>`, `--operator <name>`, `--mode enforce|observe`, `--approval-port <port>` (local approval UI on 127.0.0.1, with a per-process token in the printed URL). Without a `cloud:` section the guard is local-only and says so: approvals are made on this machine and name `--operator`, not a signed-in person.

<p align="center">
  <img src="assets/demo.gif" alt="MCP Guard proxy demo" width="700">
</p>

`npx @permission-protocol/mcp-guard demo` runs the proxy demo with a throwaway demo key; gates refuse its receipts.

## Policy reference

```yaml
# pp.config.yaml
default_action: block        # allow | block | require_approval, when no rule matches
mode: enforce                # enforce (default) | observe: record, never block
server_label: github-mcp     # names the MCP server in receipts (default "mcp-server")
cloud:                       # held calls need a named person's signature in Permission Protocol
  environment: production    # development | staging | production: a label for the signer
  approval_timeout_seconds: 600
  # heartbeat: false         # turn the usage heartbeat off
  # args_preview: false      # held calls send the argument hash only, no masked preview
  # open_browser: false      # a held call does not open the signing page in this machine's browser
targets:
  databases: [prod-db.internal]
rules:
  - { id: hold-deploy, tool: deploy_production, action: require_approval }
  - { id: hold-reads, method: resources/read, action: require_approval }
  - { id: shell, tool: "*", detect: { detector: shell_destructive, args: [command] }, action: require_approval }
  - { id: prod-sql, tool: run_sql, match: { database: { equals: prod } }, action: block }
  - { id: prod, tool: "*", mentions_target: { args: [command, sql] }, action: require_approval }
  - { id: secrets, tool: "*", detect: { detector: secret_read, args: [command] }, action: block, observe: true }
```

Rules are tried in order and the first match wins. The loader is strict: an unknown key, a duplicate rule or an unreachable rule fails at startup. Other keys: `approval_ttl_seconds`, `receipt_ttl_seconds`, `scoped_receipt_ttl_seconds`, `signing`, and per rule `reversibility`, `countdown_seconds`, `cap_usd` with `amount_arg`, `receipt_ttl_seconds`. Argument rules and detectors: [docs/detectors.md](docs/detectors.md). Targets, `observe` and the preset: [docs/presets.md](docs/presets.md).

## Receipts and verification

Every final decision (allowed, blocked, approved, denied, released by countdown, expired) is an Ed25519-signed receipt in the Permission Protocol receipt standard (`jcs_v2`), appended to `pp-receipts.jsonl` as `{ "artifact": ..., "record": ... }`. The signed record names the tool, method, server label, rule, scope and who decided; arguments are bound only by `inputHash`, never stored. A held call is recorded unsigned until it is decided; a Permission Protocol signature is logged as a `{"cloud": ...}` line with the signed receipt.

```bash
npx @permission-protocol/mcp-guard keys show            # key id, keys.json path, the --trust value (also: keys init | rotate | revoke <key id>)
npx @permission-protocol/mcp-guard receipt verify <receipt id> --receipts-path pp-receipts.jsonl   # re-check a logged Permission Protocol receipt offline
npx @permission-protocol/mcp-guard verify --receipt-file receipt.json --keys .pp/keys.json \
  --trust "$MCP_GUARD_TRUST" --scope deploy:production --scope-sha "$GITHUB_SHA"
```

`verify` trusts only the key set you give it (and, with `--trust`, only the pinned key), requires a signed, unexpired `APPROVED` status, and matches scope exactly: a receipt naming a `scope.ref` or commit the gate did not ask for is refused, so pass `--scope-ref` when receipts carry one. It refuses demo-key receipts (`--allow-demo`), receipts no person approved for a scoped action (`--allow-policy-approval`) and 0.2 receipts (`--accept-legacy --pubkey <pem>`). `--call call.json` (`{"tool", "operation", "resource", "input"}`, `resource` required) binds the receipt to one exact call; `--require-call` makes it mandatory. Exit 0 authorized, 1 refused, 2 missing input. `npx @permission-protocol/verify` checks the same artifact.

## Where the token and keys are kept

| | macOS | Linux | Windows |
|---|---|---|---|
| Install token | Keychain | Secret Service (`secret-tool`), else a 0600 file `install-token` | The file `install-token` (below) |
| Private signing key | 0600 file | 0600 file | A file (below) |

- Files live under `~/.config/mcp-guard/` (`$XDG_CONFIG_HOME/mcp-guard/` if set; keys in `keys/`, or `$PP_KEYS_DIR`); on Windows that is `%USERPROFILE%\.config\mcp-guard\`. `PP_INSTALL_TOKEN` in the environment takes precedence over both stores.
- On macOS and Linux the guard refuses a token file or private key that other users can read.
- **Windows uses a file for the token because the guard has no Windows keychain (Credential Manager) integration.** File modes do not apply there, so after writing the token and the private key, the guard runs `icacls` to remove inherited permissions and grant only the current user. init prints whether that worked; if `icacls` is missing or fails, the files are protected only by the permissions of your user profile folder. The Windows path has been tested with a stand-in for `icacls` only, not on a real Windows machine.
- The token has the single scope `mcp:guard`: it can open, read and redeem this install's own approval requests, and cannot approve anything. The wrapped MCP server is started without any `PP_*` variable.

## CI gate

`templates/github-actions/receipt-gate.yml` is a deploy workflow that verifies a receipt before deploying, taking the verifier, key set, pin and receipt only from trusted places. Commit the key set (`cp ~/.config/mcp-guard/keys/keys.json .pp/keys.json`), set the `MCP_GUARD_TRUST` repository variable to the `--trust` value from `mcp-guard keys show`, and copy the workflow. A `github:merge` receipt binds the PR's head commit: gate it with `--scope github:merge --scope-ref refs/pull/<n>/merge --scope-sha <head sha>`.

## CLI

```
mcp-guard init [--preset coding-agent] [--hook claude-code | --no-hook] [--wrap-launcher <cmd>] [options]   # see init --help
mcp-guard hook [install | uninstall]          # docs/hooks.md
mcp-guard report [--config <path>] [--receipts <path>] [--json]
mcp-guard heartbeat --show | --send           # docs/heartbeat.md
mcp-guard [--config <path>] [--agent-id <id>] [--operator <name>] [--mode enforce|observe] [--approval-port <port>] -- <server command>
mcp-guard keys init [--demo] | keys rotate [--demo] | keys revoke <key id> | keys show
mcp-guard receipt verify <receipt id> [--receipts-path <file>] [--config <policy.yaml>]
mcp-guard verify --receipt-file <path> --keys <keys.json> --trust ID=sha256:<hex> --scope s [--scope-ref r] [--scope-sha h]
mcp-guard export-key [out.pem]                # legacy 0.2 public key only, for --accept-legacy
mcp-guard demo
mcp-guard --version
```

Security reports: [SECURITY.md](SECURITY.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## License

MIT
