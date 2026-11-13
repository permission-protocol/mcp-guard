# Presets

A preset is a ready policy. `mcp-guard init --preset coding-agent` writes it in place of the single hold rule `init` writes by default, then adds `server_label` and the `cloud:` section as usual. It asks nothing extra. The policy text is in [`src/presets/coding-agent.ts`](../src/presets/coding-agent.ts).

Where `init` writes it:

- For a wrapped MCP server: `~/.config/mcp-guard/policies/<server>.yaml`, as before (an existing different file is copied aside first).
- For Claude Code's own tools, in a Claude Code project (`.claude/` or `CLAUDE.md`) or with `--hook claude-code`: `<project>/pp.config.yaml`, and the Claude Code hook is installed to read it. An existing `pp.config.yaml` that differs is never overwritten: init stops before logging in. `--no-hook` skips this. See [hooks](hooks.md#set-up-with-init---preset-coding-agent).

Edit the written files; the loader refuses anything it does not recognise.

The preset is built from the [detectors](detectors.md). **Detectors are heuristics that stop mistakes, not a sandbox.** Everything in [Known limits](detectors.md#known-limits) applies.

## `coding-agent`

For Claude Code, Cursor, Codex and other coding agents whose tools run shell commands, SQL and file edits. `default_action: allow`, `mode: enforce`. Every rule is `require_approval` or observe-only: there is no allow rule, so the order of the rules decides only which rule id a hold names, never whether a call is held.

### Held from day one

| Rule | What it holds | Arguments scanned |
|------|---------------|-------------------|
| `guard-tamper` | Changes to the guard itself (below), from a shell command | `command`, `cmd`, `commands`, `script`, `shell_command`, `bash_command` |
| `guard-tamper-<tool>` | The same, from a file tool: `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `write_file`, `edit_file`, `edit_block`, `move_file`, `delete_file` | `path`, `file_path`, `target_file`, `notebook_path`, `filename`, `source`, `destination` |
| `guard-tamper-apply-patch` | A Codex `apply_patch` whose `*** Update/Add/Delete File:` or `*** Move to:` line names a guard file | `input` |
| `destructive-sql` | `sql_destructive`: `DROP`, `TRUNCATE`, `DELETE`/`UPDATE` without `WHERE`, ... | `sql`, `query`, `statement`, `statements`, `sql_query` |
| `destructive-shell` | `shell_destructive`: `rm -rf` outside the tree, force pushes and pushes to `main`, disk writes, SQL through `psql -c`, ... | shell arguments |
| `terraform-destroy` | `terraform_destroy` | shell arguments |
| `cloud-delete` | `cloud_delete`: databases, volumes, buckets, snapshots, clusters, namespaces | shell arguments |
| `production-target` | Any call whose arguments name a production target you listed (below) | shell arguments, `sql`, `query`, `statement`, `database`, `host`, `connection_string`, `project_id`, `context`, `namespace`, `branch` |

A command a detector cannot read (`eval`, `python -c`, `curl | sh`, a non-text argument) is held, as everywhere else.

### Observed, not enforced

| Rule | What it records |
|------|-----------------|
| `secret-read` | `secret_read` over the shell arguments and `path`, `file_path`, `target_file`: `.env` files, cloud credentials, SSH keys, environment dumps, token printers |

The rule has `observe: true`. When it matches, through the proxy or the Claude Code hook, the call proceeds, stderr says `OBSERVE: Matched rule "secret-read" (secret_read: secret_file) would hold "Bash"; not enforced (observe: true)`, and the receipts file gets an unsigned `{"observed": ...}` line with the rule id, detector, kind, tool, agent and input hash. Never the arguments, never the path that was read.

It stays observed until you delete `observe: true` from the rule. Nothing switches it automatically.

### `observe: true` on any rule

A `block` or `require_approval` rule with `observe: true` is evaluated and recorded as what it would have done, then evaluation goes on to the next rule **as if the rule were absent**. So an observed rule never lets through a call that a later rule or the default would hold, and an observed rule never shadows a later one. `observe` is refused on `allow` rules. `mode: observe` (the whole policy) still works as before; per-rule observe is separate from it.

### Production targets

```yaml
targets:
  databases: [prod-db.internal, app_production]
  cloud_accounts: [acme-prod, "012345678901"]
  kube_contexts: [prod-eu-1]
  git_branches: [release]
rules:
  - { id: production-target, tool: "*", mentions_target: { args: [command, sql, database] }, action: require_approval }
  # or only some kinds:
  - { id: prod-db, tool: "*", mentions_target: { in: [databases], args: [command, sql] }, action: block }
```

The preset ships the four lists empty and the `production-target` rule active: it matches nothing until you add a name.

Schema, checked at startup:

- `targets` keys are exactly `databases`, `cloud_accounts`, `kube_contexts`, `git_branches`. Each is a list (or empty / absent). Unknown keys are errors.
- A name is a **literal string**, 2 to 128 characters of letters, digits and `. _ - : / @`, starting with a letter or digit. No patterns. At most 64 per kind. Duplicates (case-insensitive) are errors. Quote account ids: a bare `012345678901` is a YAML number and is refused.
- `mentions_target: { args, in }`: `args` lists up to 16 top-level argument names (not `_pp*`); `in` is optional, a list of kinds, default all. A rule with `mentions_target` needs a `targets:` section and cannot be `allow`.

Matching:

- Case-insensitive, whole word: the name must not be preceded or followed by a letter or digit. `acme-prod` matches `--project=acme-prod` and `acme-prod.iam.gserviceaccount.com`, not `acme-production`. Punctuation such as `-`, `_` and `.` counts as a boundary, so `prod` matches `prod-replica`: list exact names.
- The text is read as written and again with quotes and backslashes removed, so `'acme'"-prod"` matches.
- A string, a number (read as its digits) or a list of strings and numbers is read. Absent, `null` and booleans carry no text. An object, a mixed list, or text over 64 KB cannot be read: the rule **holds** (`parsed: false`).
- The decision's `effect` is `{ detector: "production_target", kind: <list>, target: <the name from your policy> }`. Only rule ids, kinds and reasons reach the receipt log, stderr and client errors.

Not caught: a name built at run time (`$PROJECT`, `$(cat project.txt)`), encoded (URL- or base64-encoded), read from a file or an environment variable the agent set earlier, or implied by a default (the current `kubectl` context, `gcloud`'s configured project, `PGHOST`). A connection made by a program the agent runs. Arguments not listed in the rule.

## Self-protection (`guard_tamper`)

The agent the guard watches must not be able to switch it off. `guard_tamper` is a detector with the usual conventions: fixed kinds, a sanitized target, fail-safe on unreadable shell text.

| Kind | What it catches |
|------|-----------------|
| `edit_policy` | `pp.config.yaml` / `pp.config.yml` anywhere; anything under `mcp-guard/policies/` (where `init` writes policies) |
| `edit_receipts` | Any file whose name ends in `receipts.jsonl` (`pp-receipts.jsonl`, `self-test-receipts.jsonl`, and `PP_SHARED_RECEIPTS_PATH` if it is named that way) |
| `edit_keys` | `mcp-guard/keys/`, `mcp-guard/install-token`, the `~/.config/mcp-guard` directory, and `~/.config` itself |
| `edit_hook_state` | `hook-requests.json` anywhere (the hook's open-request state, `~/.config/mcp-guard/hook-requests.json` by default) |
| `edit_client_config` | `.mcp.json`, `.claude.json`, `claude_desktop_config.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings.json` and `.claude/settings.local.json` (project and `~/.claude/`), `.codex/config.toml`, `.gemini/settings.json`, `.codeium/windsurf/mcp_config.json`, and the `.cursor`, `.claude`, `.codex`, `.gemini`, `.codeium`, `.vscode` directories |
| `kill_guard` | `pkill` / `killall` of `mcp-guard` or `node` (or a pattern of only wildcards), `taskkill` / `Stop-Process` of `node` or mcp-guard, `kill` whose pid comes from `pgrep` / `pidof` naming them, `kill -9 -1` |
| `guard_cli` | `mcp-guard keys init|rotate|revoke` and `mcp-guard init`, also through `npx`, `bunx`, `pnpm dlx`, `yarn dlx` |

What counts as modifying: `rm`, `rmdir`, `unlink`, `shred`, `truncate`, `chmod`, `chown`, `chgrp`, `chattr`, `setfacl`, `tee` (with or without `-a`), `sponge`, `patch`, editors (`vi`, `vim`, `nvim`, `nano`, `emacs`, `micro`, `hx`, `ed`, `ex`, `code`, `cursor`, `subl`, `gedit`); `mv` (source or destination); `cp`, `install`, `ln`, `rsync`, `scp`, `ditto` and `dd of=` (destination only, including `-t DIR` and a source's name inside a destination directory written as `dir/`, `.` or `~`); `sed -i`, `perl -i`, `awk -i inplace`, `yq -i`; `>`, `>>`, `>|`, `&>`, `<>` redirects; `find <protected> -delete` or `-exec rm|mv|...`; `git rm|mv|restore|checkout`. PowerShell `Remove-Item`, `del`, `Set-Content`, `Add-Content`, `Clear-Content`, `Out-File`, `Move-Item`, `Rename-Item` (every path) and `Copy-Item` (destination). Globs that could match a protected name are held (`rm *.jsonl`, `rm -rf ~/.c*`). For file tools, the path argument of the write tools listed above.

**Claude Code through the hook.** The hook (`mcp-guard hook`) passes Claude Code's own tools to the same engine: `Bash` and `PowerShell` with `{ command }`, `Write` with `{ file_path, content }`, `Edit` with `{ file_path, old_string, new_string, replace_all }`, `NotebookEdit` (shape unverified; the rule scans `file_path`, `notebook_path` and the other path names above). The shell rules cover `Bash` and `PowerShell`; the `guard-tamper-write`, `guard-tamper-edit` and `guard-tamper-notebookedit` rules cover the file tools. The hook entry lives in `.claude/settings.json` / `.claude/settings.local.json` / `~/.claude/settings.json`: removing it, narrowing its matcher or adding `--mode observe` to its command switches the guard off. So **every** write or edit to those files is held, not only changes to the hook entry. Edits to them are rare, so this costs little; sign the ones you meant.

**How paths are compared** (lexically, no I/O): lower-cased, so it over-matches on case-sensitive file systems and never under-matches on case-insensitive ones; `\` read as `/`; `~`, `./`, repeated and trailing separators dropped; `a/../b` resolved to `b`. Relative and absolute paths both match, because protected entries are matched against the end of the path (`.claude/settings.json` matches `/any/project/.claude/settings.json`). A file-tool path is read as a path first, so Windows drive paths and paths with spaces (`Application Support`) are handled. A written path with an unknown part (`> "$CFG"`, `rm $TMPFILE`, `cp x $DIR/settings.json`) **fails safe** (held, `dynamic_argument`) unless its static end rules a protected file out (`> "$OUT/build.log"` is not held). Not resolved, because that needs I/O: symlinks, hard links, bind mounts, the working directory (a relative path is matched by its own segments, whatever directory it is in), `..` above the start of a relative path, 8.3 short names and other aliases on Windows.

Named non-matches, by design: **reading is fine.** `cat pp.config.yaml`, `grep ... policies/x.yaml`, `tail pp-receipts.jsonl`, `cp pp.config.yaml /tmp/copy.yaml`, `git diff pp.config.yaml`, `read_file` / `Read` of any of these files, `mcp-guard keys show`, `mcp-guard receipt verify`. `kill $(lsof -ti:3000)` and `kill 1234` are not held.

Not caught:

- **Custom locations.** A policy passed with `--config` under a name other than `pp.config.y(a)ml` and outside `mcp-guard/policies/`, a receipts file not ending in `receipts.jsonl`, `PP_KEYS_DIR` pointing elsewhere. Use the default names, or add a `match` rule with `contains` on your path.
- **Indirection.** A path built by a program (`> $(echo pp.config.yaml)` fails safe; a script that computes it does not), reached through a symlink or a `cd` made earlier, or written by a script, a program or inline interpreter code (inline code fails safe; a script file does not). A path in a variable fails safe, as above.
- **PowerShell syntax.** The reader is POSIX: in a `PowerShell` command a `\` is read as an escape, so `Remove-Item .claude\settings.json` is not matched (write `/`), and PowerShell variables, pipelines into `Set-Content` and `-LiteralPath` quoting are not modelled.
- **Processes by pid.** `kill <pid>` with a literal pid, `kill $PPID`, `pkill` with a regular expression that matches the guard without naming it (`pkill -f 'mcp.guard'`), stopping the client, `systemctl`, closing the terminal.
- **Tools the preset does not list.** A file-write tool under another name, or with its path under another argument name, is not checked. Exact-tool rules are needed for those, because a `tool: "*"` rule over `path` would also hold reads.
- **Other ways to unwrap.** Changing `PATH` so `mcp-guard` resolves to something else, editing the npm cache or `node_modules/@permission-protocol/mcp-guard`, editing a client config the list above does not name, or a client that re-reads its config from somewhere else.
- **Running unwrapped.** An agent that can start an MCP server or a shell outside the guard is not stopped by the guard at all. Run untrusted agents as a separate OS user that cannot write the guard's files.

## What the preset misses overall

The detectors' [Known limits](detectors.md#known-limits): code run from files, two-step state, arguments not listed, tools that are destructive by name (`delete_database` as an MCP tool: add exact-tool rules), containers and remote shells, context that needs I/O (the current branch, the current kube context). Plus, for this preset: `default_action: allow`, so every call the rules above do not match runs. Use `default_action: require_approval` for a server whose every call should be signed.
