# Changelog

## 0.5.1: a held call is hard to miss

In a real test on Windows, a held `rm -rf` waited 240 seconds and timed out because the person never saw the signing link while the hook was waiting. This release opens the signing page, says in the session what is waiting, and tells Claude who approved. The approval request body is exactly 0.5.0's.

### Added

- **A held call opens the signing page in your browser** while the guard keeps waiting (hook and proxy). Only an `https:` link on the origin of the configured `cloud.api_url`, with no user name or password, is opened; any other link is not opened and the hold goes on as before. The opener gets the link as one argument with no shell: `/usr/bin/open` on macOS, `rundll32 url.dll,FileProtocolHandler` on Windows (no `cmd.exe`), `xdg-open` elsewhere; detached, no stdio, errors ignored. It opens at most once per approval request, and never for a request resumed from an earlier hook run. Opening the browser never changes the decision or delays the poll. **Off** when `CI` is set, in an SSH session (`SSH_CONNECTION`, `SSH_CLIENT` or `SSH_TTY`), on Linux without `DISPLAY` or `WAYLAND_DISPLAY`, with `MCP_GUARD_OPEN_BROWSER=off` (or `0`, `false`, `no`), with the new policy key `cloud.open_browser: false`, and in init's own self-tests.
- **Claude is told who approved a held call.** After a verified, redeemed receipt releases a call, the hook answers with `additionalContext` (which Claude Code gives to Claude) and `systemMessage` (which it shows to the person): `Approved by <signer> through Permission Protocol. Receipt: <link>`. The signer comes from the verified receipt only. The link is used only if it is an `https:` page of the configured API; otherwise the verified receipt id is named. On an `allow`, Claude Code writes `permissionDecisionReason` to its debug log only, so before this release Claude saw nothing.

### Changed

- The hook's `statusMessage`, which Claude Code shows beside its spinner while the hook runs: `mcp-guard: checking this call. A held call waits here until a named person signs it.` It is shown on every checked call, so it is short. Run `init` or `hook install` again to update an installed hook. Claude Code reads hook output only when the hook ends, so the signing link itself cannot be shown while the hook waits.
- When the hook's wait runs out, the denial also carries a `systemMessage` for the person with the signing link and the fact that the same call can be retried after someone signs. The reason Claude gets is unchanged: it already named the link and said to run the same call again.
- **Shorter `init` output.** During the run it prints only what needs you (the login, the self-test link) and one line per self-test. Then, in this order: what is guarded and where the policy is; what happens the next time an agent tries something destructive; `mcp-guard report` and the receipt verify command; how to undo each change; the setup details (token, key, policy, launcher, wrapped command). A failing step still prints its full detail, and every failure after a change prints how to undo it.
- **A launcher that is not found gets its own message.** When the shell cannot find the hook's launcher (exit 127), for example because Claude Code was started from the macOS Dock or an IDE with a PATH that lacks `npx`, the installed command now says so, blocks the call (exit 2 as before), and says to start Claude Code from a terminal where `npx` works or to delete the mcp-guard entry under `hooks.PreToolUse` in `.claude/settings.json`. Before, it advised `npm install`, which does not fix a PATH. Run `init` or `hook install` again to update an installed hook.
- **Detached children start outside the project.** The heartbeat sender (hook and proxy), the browser opener and init's self-test guard now start in the guard's config directory (`~/.config/mcp-guard`, or the parent of `PP_KEYS_DIR`), else the home directory, with the guard's path variables made absolute. On Windows a process whose working directory is the project kept that folder from being deleted. The wrapped MCP server still starts where the client starts the guard.
- init's own browser opener uses the same no-shell opener. On Windows it ran `cmd /c start "" <url>` before, which `cmd.exe` parses.
- The receipt-gate template pins the verifier to 0.5.1.

## 0.5.0: a guard for coding agents

The first release on npm since 0.3.1. 0.4.0 was never published, so everything in the 0.4.0 section below ships for the first time in 0.5.0.

In one command (`npx @permission-protocol/mcp-guard init --preset coding-agent`), Claude Code's own shell and file tools are checked before they run: destructive commands, SQL, infrastructure and cloud deletes, and changes to the guard itself wait for a named person to sign in Permission Protocol, and only a verified, signed receipt releases the call. Upgrading from 0.3.1: read **Breaking** first.

### Added

- **Claude Code hook** (`mcp-guard hook`, `hook install`, `hook uninstall`): the same policy, rules, receipts and signed approvals for Claude Code's `Bash`, `PowerShell`, `Write`, `Edit` and `NotebookEdit` calls, through its `PreToolUse` hook. Blocked and unsigned held calls are denied; allowed calls get no answer, so Claude Code's own prompts still apply; every error denies. See [docs/hooks.md](docs/hooks.md).
- **`init --preset coding-agent`**: the `coding-agent` policy written to `<project>/pp.config.yaml`, the hook installed and checked locally (one allowed and one held synthetic call), then one do-nothing call held for your first signature. In a Claude Code project (`.claude/` or `CLAUDE.md`) the hook is installed by default; `--hook claude-code` installs it anywhere, `--no-hook` skips it. An existing policy that loads is kept byte for byte. See [docs/presets.md](docs/presets.md).
- **Argument rules**: `match` (`equals`, `contains`, `pattern`) on named arguments, `detect` with the detectors `sql_destructive`, `shell_destructive`, `terraform_destroy`, `cloud_delete`, `secret_read` and `guard_tamper`, and `tool: "*"` (only with `match` or `detect`). Text a detector cannot read is held. See [docs/detectors.md](docs/detectors.md).
- **Production targets**: a `targets:` section and the `mentions_target` condition hold a call whose arguments name a database, cloud account, Kubernetes context or git branch you list.
- **`observe: true` on a rule**: records what the rule would have done (an unsigned `{"observed": ...}` line, no argument text) and decides as if the rule were absent.
- **`mcp-guard report`**: the last 7 days of the local receipt log, per day and in total (allowed, blocked, held, approved, denied, expired), the rules that blocked or held most, and observe-only matches. Text, or `--json`. Read-only: it sends nothing and prints no argument text.
- **Usage heartbeat** and `mcp-guard heartbeat --show | --send` (below).
- `cloud.args_preview: false` (new policy key, `true` or `false`): a held call sends the argument hash only, no preview. The signer then sees the tool, server, agent and environment, not what the call does.
- `init --wrap-launcher "<command>"`: how the MCP client starts the guard for a wrapped server, instead of `npx -y @permission-protocol/mcp-guard@<version>` (a project install, a source checkout). Words split on spaces, double quotes group; no shell.
- `mcp-guard --version`.

### Changed

- **Usage heartbeat, on by default** for installs whose policy has a `cloud:` section and that have an install token. Once per UTC day (at most one attempt every 10 minutes), a separate process sends `POST /api/mcp/heartbeat` to Permission Protocol with the install token. The body is exactly: the guard version, a fixed client label (`claude-code`, `mcp-proxy` or `mcp-guard`), the mode (`enforce` or `observe`), the UTC day, the six counts `allowed`, `blocked`, `held`, `approved`, `denied`, `expired`, and up to 20 rule ids **shipped with the guard** (the `coding-agent` preset's) with how many calls each blocked or held. Your own rule ids, arguments, commands, paths, file contents, tool, server and target names, hostnames and usernames are never sent. It cannot allow, block or delay a call, and `mcp-guard init`'s self-tests are not counted. `mcp-guard heartbeat --show` prints the exact body without sending it. **To turn it off**, either set `MCP_GUARD_HEARTBEAT=off` (or `0`, `false`, `no`) in the guard's environment, or put `heartbeat: false` under `cloud:` in the policy. Local-only installs (no `cloud:` section) and installs without a token never send it. See [docs/heartbeat.md](docs/heartbeat.md).
- `mcp-guard init` without `--preset` writes the same policy as before and never touches `.claude/`.
- **init checks the wrap launcher before the login.** The command the client will run for a wrapped server must report this exact version (`<launcher> --version`, no shell, a 60-second timeout, no `PP_*` variables); otherwise init stops with nothing changed. Before, init run from an unpublished build wrote a pinned `npx -y @permission-protocol/mcp-guard@<version>` the client could not start, and reported success.
- The `receipt verify` command init prints is pinned to the running version (`npx @permission-protocol/mcp-guard@<version> ...`), never `latest`.
- **init's hook step on Windows finds Git Bash** without Git's `bin` on PATH: `CLAUDE_CODE_GIT_BASH_PATH`, then `sh.exe` / `bash.exe` on PATH (not WSL's), then Git for Windows' standard folders, then beside `git.exe`. If none is found it refuses before changing anything and lists where it looked.
- **The hook self-test says which failure it was**: "could not run" (no shell, its temporary policy not written or read) is reported apart from "the installed hook did not answer as expected". Before, both said the installed hook blocks every call.
- init prints one line when `claude --version` is older than 2.1.295, where `onFailure: "block"` does nothing (optional; never fails init).
- The undo hint is printed with the launcher the hook was installed with (`npx -y @permission-protocol/mcp-guard@<version> hook uninstall --project <dir>`), so it works without a local install.
- Local-only mode is labelled `local-only, unsigned by Permission Protocol` at startup and on every held call.
- The receipt-gate template (`templates/github-actions/receipt-gate.yml`) pins the verifier to 0.5.0.

### Breaking

From the verifier hardening. Each fails closed; none can be switched off.

- **Enforcement module: policies with `required_approvals` above 1 are refused** at load and at verification (`PP_POLICY_UNSUPPORTED`), until real multi-signature exists. One token carries one signature, so N names inside it are not N approvals.
- **Role policies (`allowed_roles`) refuse a token with more than one signer** (`PP_ROLE_NOT_BOUND`). `allowed_signers` and `allowed_roles` must be lists.
- **`verify --call` files must name `resource`** (the MCP server label the receipt signed), or the receipt is refused (`PP_RESOURCE_MISMATCH`). Add `"resource"` to existing call files.
- **A gate without `--scope-ref` refuses a receipt that carries a ref.** `verify` matches scope exactly: a receipt naming a `scope.ref` or commit the gate did not ask for is refused. Pass `--scope-ref` (for `github:merge`, `refs/pull/<n>/merge`).
- `verify` refuses receipts signed by any demo key (`mcpg-demo-*`, `pp-demo-*`) whatever scope they claim (`--allow-demo` accepts them), and refuses `--call` / `--require-call` on a legacy 0.2 receipt.

### Security

- **Held calls uploaded unmasked argument text.** 0.4.0's code sent `argsPreview` as the arguments' JSON cut to 8,192 characters: for a held `Bash` call the command, for a held `Write` or `Edit` up to 8 KB of file content, credentials included (Permission Protocol masked it only after receiving it). The guard now masks the preview before upload (credential-keyed values, private keys, URL credentials, Bearer and Basic values, common token formats, `password=` / `token=` / `.env` assignments, long opaque strings), orders short fields first so the path survives, and caps it at 2,048 bytes. A held call sends exactly: the tool name, server label, agent id, environment label, the arguments' hash, and that preview (none with `cloud.args_preview: false`). The hash, the fingerprint and what the signature covers are unchanged. Statements that raw arguments never leave the machine were wrong and are corrected.
- **Windows: init's hook self-test joined an absolute temporary policy path to the project directory** (`<project>/C:\Users\...\pp.config.yaml`), failed, and said the installed hook blocks every call, which was false. Drive-letter and UNC paths are now absolute in the hook command (`path.win32` rules).
- **Windows: the install token and private signing key were plain files, and init said "owner-only".** File modes do not apply on Windows. After writing each file the guard now runs `icacls` (inheritance removed, the current user granted full control; exec form, the path as its own argument) and init prints whether it worked; if not, it says the file is protected only by the user profile folder's permissions. Not yet run on a real Windows machine.
- init printed `npx mcp-guard hook uninstall ...` as the undo command. Without a local install, `npx mcp-guard` resolves to an unrelated npm package of that name; the undo command now uses the launcher the hook was installed with, and `receipt verify` names `@permission-protocol/mcp-guard@<version>`.

Also fixed in this release (detail under 0.4.0 below):

- One key could satisfy an N-of-M approval policy, and `allowed_roles` was checked against one token-wide roles list for every signer (enforcement module). Found through a private report.
- `verify` refused a demo-key receipt only when it signed `scope: "demo"`; it now refuses any `mcpg-demo-` or `pp-demo-` key. Thanks tmkmaj (#18).
- A gate could silently skip exact-call binding; `--require-call` makes `--call` mandatory, and the gate template no longer takes the call from its dispatch input. Thanks tmkmaj (#19).
- `verify --call` did not bind the MCP server, so a receipt approved for one server verified for the same call to another. Thanks Yingjie Shang (#20).
- The enforcement module accepted tokens and payloads issued in the future or not before their expiry, and applied `max_ttl_seconds` to the token only, so a future `signed_at` could stretch an authorization past the policy TTL; `verify` did not match scope exactly. Thanks ket4min-susan (#21).

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

### Known limits

- The detectors are heuristics that stop mistakes, not a sandbox: a script written to a file and then run is not read, and an agent running as the same OS user can remove the hook. See [docs/detectors.md](docs/detectors.md#known-limits).
- The hook on Windows needs Git Bash (Git for Windows). The Windows changes in this release were tested with stand-ins (`path.win32`, an injected `icacls` and file lookup, POSIX `sh` in place of Git Bash), not on a Windows machine.
- On Claude Code before 2.1.295 a hook that Claude Code kills at its own timeout is not a block; the guard denies before that timeout.
- Preview masking is pattern-based: a short secret with no telling name around it (for example `mysql -pS3cret`) is not recognised. Use `cloud.args_preview: false` to send none.

## 0.4.0 (never published; shipped in 0.5.0): signed approvals by a named human

A held call can now be released by a receipt that a signed-in person signed in Permission Protocol, verified offline by the guard. Before this release every approval was local: decided on the guard's machine, with the approver's name taken from `--operator`.

Requires Permission Protocol's MCP approval API (permission-protocol/app#1030) and, for `init`, its device login endpoints. Until those are live in production, cloud mode against the production API gets an error answer and every held call is blocked, and `init` cannot log in.

### Added

- `cloud:` policy section (`api_url`, `environment`, `approval_timeout_seconds`, `trust_keys`). Absent, nothing changes except the label below.
- Hold, request, verify, release: the guard computes the call's fingerprint locally (SHA-256 over canonical JSON of `{argsHash, server, tool}`), opens an approval request, polls with backoff, verifies the receipt against the pinned Permission Protocol key, redeems it once, then forwards. The request carries the argument hash and an argument preview (in 0.4.0's code unmasked, up to 8,192 characters; 0.5.0 masks and caps it before upload, see Security above).
- Offline receipt verification for the formats the app signs (`jcs_v2`, `jcs_v3`, `jcs_v4`): signature, canonical bytes, fingerprint equals the held call's, request id, human decider, approval, production scope, expiry, replay.
- Permission Protocol's production signing keys pinned in the release (`src/cloud/pinned-keys.ts`). No key is fetched at decision time.
- `PP_INSTALL_TOKEN` (or `~/.config/mcp-guard/install-token`, owner-only): a workspace API key with the single scope `mcp:guard`.
- `{"cloud": ...}` lines in the receipts file: each cloud decision with its receipt id, receipt URL, signer and the signed receipt.
- Error `-32007`: signed approvals are on but Permission Protocol could not be reached or trusted. Nothing was forwarded.
- `mcp-guard init`: device login in the browser (no secret is copied by hand), the install token stored in the OS keychain (macOS Keychain, or the Secret Service on Linux via `secret-tool`; otherwise a 0600 file, always on Windows), detection of Claude Code and Cursor MCP configs, one server wrapped (the config file is copied aside first), one hold rule written, then a self-test that holds a do-nothing call for a signature and prints the receipt, how to verify it, and the time from start to first signed receipt.
- `mcp-guard receipt verify <receipt id>`: re-checks a logged Permission Protocol receipt offline against the pinned keys.

### Changed

- Local-only mode is labelled. Startup prints `Mode: local-only, unsigned by Permission Protocol`, and a held call's `-32002` message and stderr line carry the same label. Local receipts are still signed with the machine's own key, as in 0.3; the label says that no Permission Protocol signature and no authenticated approver stands behind them.

### Security fixes

- **One key could satisfy an N-of-M approval policy (enforcement module).** Reported privately. An authorization token has one signature under one `key_id`, but `required_approvals: N` was met by N distinct names listed inside it, and `allowed_roles` was checked against the token's single `roles` list for every signer. A policy with `required_approvals` above 1 is now refused at load and at verification (`PP_POLICY_UNSUPPORTED`; `interceptToolCall` denies); names are never counted as approvals. `allowed_roles` is enforced only on a token with exactly one signer; a multi-signer token under a role policy is refused (`PP_ROLE_NOT_BOUND`). `allowed_signers` / `allowed_roles` must be lists (a string was matched as a substring). **Breaking:** policies with `required_approvals` above 1 stop working until real multi-signature exists.
- **Demo keys were refused only by the scope they signed.** `mcp-guard verify` refused a demo-key receipt only when it signed `scope: "demo"`. It now refuses any `mcpg-demo-` or `pp-demo-` key whatever scope it claims (`--allow-demo` still accepts them), and the cloud release path now refuses `mcpg-demo-` keys as well as `pp-demo-` ones. Thanks tmkmaj (#18).
- **`--require-call`** makes `verify --call` mandatory, so a gate cannot silently skip exact-call binding. `--call` / `--require-call` on a legacy 0.2 receipt, which signs no input hash, is now refused instead of ignored. Thanks tmkmaj (#19). The receipt-gate template does not take the call from its dispatch input: whoever supplies the receipt could supply a matching call.
- **Exact-call verification did not bind the server.** `verify --call` checked tool, operation and input but not the signed `action.resource`, so a receipt approved for one MCP server verified for the same call to another. The call file now requires `resource` (`PP_RESOURCE_MISMATCH`). Thanks Yingjie Shang (#20). **Breaking** for existing `--call` files without `resource`.
- **Timestamp, TTL and scope bounds.** The enforcement module refuses tokens and payloads whose issue time is in the future or not before their expiry, and applies `max_ttl_seconds` to the payload as well as the token, so a future `signed_at` cannot stretch an authorization past the policy TTL. `verify` now matches scope exactly: a receipt naming a `scope.ref` or commit the gate did not ask for is refused (**breaking** for gates that omit `--scope-ref` while their receipts carry one). Thanks ket4min-susan (#21); its per-signer role mapping was replaced by the refusal above.

### Fail closed

A rejection, a frozen workspace (signed DENIED), a timeout, an API error, a receipt that fails any check, changed arguments, or a failed redeem all block the call. No environment variable disables verification. In enforce mode the guard refuses to start in cloud mode without a token.

### Not in this release

- Signed approvals do not use countdowns or the local approval UI.
- `init` wraps stdio servers only, and one per run.
- No Windows Credential Manager support: on Windows the token is kept in an owner-only file.

## 0.3.1 — security fixes

Four medium-severity findings from independent review of permission-protocol/mcp-guard#16. No receipt format change; gates need no new pin.

### Fixed

- **A held call could be released with another held call's receipt.** The release check bound scope and single use but not the call itself, so a valid receipt for one held call released a different held call with other arguments (shown at the internal release API; no external route to substitute the receipt was found). A release now verifies that the receipt is for this queue item (`idemKey`, `PP_DECISION_MISMATCH`) and that its signed `inputHash` recomputes from the exact line forwarded to the server (`INPUT_HASH_MISMATCH`), before the receipt is consumed.
- **A `keys.json` others could write was trusted.** keys.json selects the signing key and records revocations, but only the key directory and private key were permission-checked, so another local user who could write an exposed keys.json could undo a revocation. The guard now refuses a group- or world-writable keys.json (`SIGNING_KEY_INVALID`). Keys created by `keys init` were not affected.
- **A countdown that could not sign ended the held call.** The item became `auto_released` before signing, so a revoked or missing key left it final, unreleased and impossible to approve later. Countdowns now sign first; if signing is refused, the countdown stops and the call stays held for an operator decision or expiry.
- **The signer used key-set entries its own verifier rejects.** A key whose entry named another `alg`, or a key id listed twice, still signed receipts that every verifier, including the guard's own release check, refused; policy-allowed calls still went through in enforce mode. The signer now applies the verifier's key-set rules and refuses such entries with `SIGNING_KEY_INVALID`.

## 0.3.0 — receipts in the org receipt standard (breaking)

mcp-guard now signs the same receipt format the Permission Protocol app issues (`jcs_v2`, receipt-spec), so one verifier reads both. Design: Permission Protocol F-10 design note, "mcp-guard signing alignment".

### Breaking changes and migration

1. **Create a signing key before the first run.** The guard no longer creates one:
   ```bash
   npx @permission-protocol/mcp-guard keys init
   ```
   Without a key the guard exits at startup with `SIGNING_KEY_MISSING` (enforce mode). Your 0.2 key (`signing.private.pem`) is not reused: 0.3 key ids are `mcpg-<16 hex of sha256(public key)>`, so a key can never pass as another.
2. **Re-pin your gates.** Gates verify against a key set and a fingerprint pin instead of a PEM:
   ```bash
   npx @permission-protocol/mcp-guard keys show   # prints the keys.json path and the --trust value
   cp ~/.config/mcp-guard/keys/keys.json .pp/keys.json
   ```
   In `templates/github-actions/receipt-gate.yml`: the key set is read from `.pp/keys.json` on the default branch, the pin comes from the `MCP_GUARD_TRUST` repository variable, and the verifier is pinned to 0.3.0. Remove `.pp/mcp-guard.pub.pem` once no gate needs 0.2 receipts.
3. **0.2 receipts are refused by default** (`LEGACY_RECEIPT_REFUSED`). Re-approve the action, or pass `--accept-legacy --pubkey <0.2 pem>`; such a receipt verifies labelled legacy. `mcp-guard export-key` now only exports an existing 0.2 public key, for that case.
4. **Receipt lines changed.** Each line of `pp-receipts.jsonl` is `{ "artifact": …, "record": … }`; held calls are `{ "hold": … }` lines and are never signed. `GET /api/receipts` returns the same objects. Anything that read `envelope`, `signature` or `display` must read `record` (the signed fields) or verify `artifact`.
5. **Receipt expiry defaults changed:** 1 hour for unscoped actions (`receipt_ttl_seconds`, was 15 minutes), 15 minutes for merge / migration / deploy receipts (`scoped_receipt_ttl_seconds`). Rules can set `receipt_ttl_seconds`; no receipt lives longer than a day.

### Added

- `mcp-guard keys init | rotate | revoke <id> | show`. Rotation keeps older keys in `keys.json` so their receipts still verify; revocation invalidates every receipt the key signed. `--demo` creates an `mcpg-demo-` key whose receipts carry `scope: "demo"`.
- Every final decision is signed: allowed, blocked, console approve and deny, countdown release, and expiry. Denials are signed receipts too (`status: DENIED`).
- The decider is signed: rules, caps and countdowns as `system/mcp-guard-policy` (`policy`); console decisions as `local:<operator>` (`local_console`, `heuristic`). A console approval with no operator is refused (`UNATTRIBUTED_PRODUCTION_DECIDER`) and the call stays held.
- Signed `reasonCodes` from a fixed set (`RULE_MATCHED:<id>`, `DEFAULT_ACTION`, `COUNTDOWN_AUTO_RELEASE`, `OPERATOR_APPROVED`, `OPERATOR_DENIED`, `APPROVAL_EXPIRED`) and `policyVersion` = `mcp-guard-config:sha256:<config hash>`.
- Config: `server_label` (names the server in receipts), `signing: required | off` (`off` writes unsigned records no gate accepts), `scoped_receipt_ttl_seconds`, per-rule `receipt_ttl_seconds`.
- `verify --call <call.json>` recomputes `inputHash` from the call (`INPUT_HASH_MISMATCH`); `verify` refuses demo-key receipts unless `--allow-demo`.
- JSON-RPC error `-32006`: the decision could not be signed, nothing was forwarded.
- `mcp-guard verify` checks org-standard artifacts (`--keys`, `--trust`), following the receipt-spec order, then gate checks read only from the signed payload. Cross-checked against `@permission-protocol/verify`.
- CI job `Audit regression`: replays the October 2026 audit attacks against the pre-fix commit (all must succeed) and the current code (all must be stopped) on every run.

### Changed

- Receipts never carry raw arguments or the server command line: the signed request names the tool, method, server label, rule and scope, and binds arguments only by `inputHash` (`pp.hashable_payload.v1`).
- The signer reloads its key for each receipt: a key revoked or removed while the guard runs stops signing at once. Allowed calls are then refused (`-32006`), held calls stay held, and in observe mode calls are forwarded with records marked `signingFailed`.
- The release path verifies its own receipt against the guard's pinned key, scope and replay cache before forwarding.
- The demo command and demo scripts sign with a throwaway demo key in a temporary directory.
- Workflows and the receipt-gate template use `actions/checkout@v5` and `actions/setup-node@v5`.

## 0.2.1 — security fix

### Fixed

- **Used authorizations could be replayed.** 0.2.0 capped its replay cache at 10,000 entries and evicted the oldest even when unexpired, so an approved authorization could be accepted again after 10,000 others (receipt release path and the enforcement module). Used authorizations are now kept until they expire, plus a 60-second grace; when the cache is full of unexpired entries, new authorizations are refused (`PP_REPLAY_CACHE_FULL`) instead of forgetting a used one. Reported in human review of permission-protocol/mcp-guard#12.
- The exposed-signing-key end-to-end test is skipped on Windows, where POSIX file modes do not apply (the signer's own permission tests were already skipped there).

## 0.2.0 — security hardening (breaking)

Fixes the findings of the October 2026 MCP Guard audit.

### Breaking changes and migration

- **Strict config.** Unknown keys, duplicate rules, `countdown_seconds` on a rule that is not `reversibility: reversible`, and `cap_usd` without `amount_arg` now fail at startup. Remove any `tools:` block (it was never read) and add `amount_arg` to capped rules:
  ```yaml
  - { id: spend, tool: spend, action: require_approval, cap_usd: 50, amount_arg: amount_usd }
  ```
- **Spend caps read only `amount_arg`.** `_pp.amount_usd` and the `amount_usd`/`amount` fallbacks are gone. A missing or non-numeric amount is a hard stop.
- **All methods are gated.** `resources/read`, `prompts/get`, `resources/subscribe` and unknown methods now follow the rules and `default_action` (a `default_action: block` policy blocks them unless a `method:` rule allows them). Plumbing still passes through.
- **Malformed input is refused.** Unparseable lines get `-32700`; JSON-RPC batches and malformed frames get `-32600`. Nothing is forwarded raw.
- **Approval UI needs its token.** It listens on 127.0.0.1 only; open the URL printed at startup (`…/#t=<token>`). API clients send `Authorization: Bearer <token>`; `PP_APPROVAL_TOKEN` (32+ characters) supplies it. Cross-origin access (`?api=` on another origin) no longer works.
- **Post-release undo is removed** (`/api/undo` returns 404). Use Hold before a countdown releases. Verify-lane items can only be acknowledged.
- **Receipt v2.** New signed envelope; v1 receipts are rejected by the verifier. Receipts carry `args_sha256` and argument names, never raw arguments.
- **Keys moved** from `./.keys` to `~/.config/mcp-guard/keys` (or `$PP_KEYS_DIR`). Key ids are now `pp-dev-<fingerprint>`. Re-export and re-pin the public key: `mcp-guard export-key`.
- **`verify` requires `--pubkey` and `--scope`.** The verifier no longer generates or discovers a key, and empty `--scope-*` values are errors.
- **GitHub commit-status poster removed** (`PP_GITHUB_TOKEN`). Gate merges with the Permission Protocol GitHub App's `permission-protocol/approval` check.

### Added

- `mcp-guard verify` and `mcp-guard export-key` subcommands.
- `--operator <name>`: approvals record `{kind: human, id, via: local-token}`; countdown and standing-rule releases record `{kind: policy}`.
- `approval_ttl_seconds` and `receipt_ttl_seconds` config keys (default 900 each). Expired held requests answer the agent with `-32004`; denials with `-32003`.
- The approval UI and the Permission Deck show every argument the server will receive (`args_full`) and the scope an approval signs for (`scope`).
- The wrapped server no longer inherits `PP_*` environment variables (approval token, webhook secret, receipt token).
- `merge_pr` scope ref is derived only from the PR number; `_pp.requires_input` no longer moves an irreversible hold out of the Decide lane.
- GitHub webhook deduplicates `X-GitHub-Delivery`.
- `templates/github-actions/receipt-gate.yml`: a deploy gate that takes its verifier, key and receipt only from trusted sources.
- CI workflow running build, tests and the end-to-end demo drivers.

### Fixed

- Approval API: no authentication, all interfaces, `Access-Control-Allow-Origin: *`.
- Spend-cap bypass through `_pp.amount_usd`.
- Receipt signatures that covered only part of the receipt and could be re-split across fields.
- Self-gate CI that trusted the key, receipt and verifier from the pull request (workflow removed).
- Fail-open forwarding of unparseable lines and batches.
- Approving a webhook PR after it was denied (and approving repeatedly).
- Countdown releases producing receipts indistinguishable from human approval.
- Raw tool arguments in stderr, receipts and the CORS-open receipts API.
- Enforcement module: a missing or invalid policy meant "nothing protected"; duplicate signer names counted as separate approvals.
