# Argument rules and detectors

A rule can look at a call's arguments, not only its tool name. This is how MCP Guard stops a coding agent from dropping a database, destroying infrastructure, deleting volumes or backups, wiping a disk or reading credentials: the danger is in the SQL text, the shell command or the cloud operation, not in the name of the tool that carries it.

**Detectors are heuristics that stop mistakes. They are not a sandbox.** An agent that is trying to get around them can (see [Known limits](#known-limits)). They catch the destructive commands agents actually run by accident, and they fail safe on text they cannot read. Run untrusted agents as a separate OS user, with credentials scoped to what they need, and keep backups.

## Rule schema

```yaml
default_action: allow
rules:
  # Exact tool + argument conditions.
  - id: block-prod-drop
    tool: run_sql
    match:
      database: { equals: prod, ignore_case: true }
      sql: { pattern: "\\b(drop|truncate)\\b", ignore_case: true }
    action: block

  # Any tool + a detector over the listed arguments.
  - id: hold-destructive-shell
    tool: "*"
    detect: { detector: shell_destructive, args: [command, cmd] }
    action: require_approval
```

| Key | Meaning |
|-----|---------|
| `tool: "*"` | Any tool. Allowed only with `match` or `detect`: a bare wildcard is rejected so a rule cannot catch every call by accident. |
| `match` | Conditions on named top-level arguments. All must hold. Each condition has exactly one of `equals`, `contains`, `pattern` (a JavaScript regular expression, at most 512 characters, compiled at startup), plus optional `ignore_case: true`. |
| `detect` | `{ detector, args, kinds, except_kinds }`. The rule matches when the detector fires on any listed argument that is present. At most 16 arguments. `kinds` (count only these kinds) or `except_kinds` (count every kind but these), not both, narrow which definite findings count; only `shell_destructive` takes them, and only its kinds (listed below). Text the detector cannot read still matches, whatever the filter. In a command chain a finding that does not count is skipped and the next command is read, so `except_kinds: [git_push_protected]` still matches `git push origin main && rm -rf ~/x`. |
| `mentions_target` | `{ args, in }`. The rule matches when a listed argument names a production target from the top-level `targets:` section. See [presets.md](presets.md#production-targets). |
| `observe` | `true`: record what the rule would do, then decide as if it were absent. See [presets.md](presets.md#observe-true-on-any-rule). |

`match` and `detect` can be combined (both must hold). They apply only to `tools/call` rules. A `detect` rule cannot have `action: allow`. Argument names starting with `_pp` (agent metadata) are rejected. Unknown keys, unknown detectors, invalid or overlong patterns are startup errors.

How arguments are read:

- Only top-level arguments, by exact name. List every name the server accepts for the command (`command`, `cmd`, `script`, ...).
- `match` on a missing argument does not hold. Write policies so the default is safe; do not rely on an argument being present.
- When a `match` condition cannot be decided (the argument is not a string, or is over 64 KB), it **holds** for `block` / `require_approval` rules and **fails** for `allow` rules.
- A detector reads a string, or a list of strings (as an argv; for `sql_destructive`, as statements). A number, boolean or null carries no text and is skipped. Any other shape (an object, a mixed list) fails safe.

### Ordering

Rules are tried in order and **the first match wins**, as before. Consequences:

- Put narrow rules before broad ones. An `allow` rule for `tool: shell` placed before `tool: "*"` + `detect: shell_destructive` lets every shell command through unchecked.
- A conditional rule after an unconditional rule for the same tool can never match; the loader rejects it.
- A wildcard rule after an unconditional exact rule still applies to other tools, but not to that one.

Recommended shape: detector rules first, then exact allow rules, then the default.

```yaml
default_action: require_approval
rules:
  - { id: no-secrets,  tool: "*", detect: { detector: secret_read,       args: [command, path] }, action: block }
  - { id: shell,       tool: "*", detect: { detector: shell_destructive, args: [command] },       action: require_approval }
  - { id: infra,       tool: "*", detect: { detector: terraform_destroy, args: [command] },       action: require_approval }
  - { id: cloud,       tool: "*", detect: { detector: cloud_delete,      args: [command] },       action: require_approval }
  - { id: sql,         tool: "*", detect: { detector: sql_destructive,   args: [sql, query] },    action: require_approval }
  - { id: run-shell,   tool: run_command, action: allow }
  - { id: run-sql,     tool: run_sql,     action: allow }
```

## Fail-safe behaviour

When a detector cannot confidently read the text it reports `matched: true, parsed: false` with a reason, and the rule applies. An unreadable command never produces "not matched" for a `block` or `require_approval` rule. Reasons:

| Reason | Example |
|--------|---------|
| `dynamic_command` | `$CMD -rf /`, `$(echo rm) -rf /` |
| `glob_command` | `/bin/r? -rf /` |
| `dynamic_argument` | `rm -rf "$DIR"`, `bash -c "$X"`, `bash <(curl ...)`, `kubectl delete -f file.yaml`, `git push origin $BRANCH` |
| `eval` | `eval "..."` |
| `interpreter_stdin` | `... \| base64 -d \| sh`, `curl ... \| bash`, `bash <<EOF`, `echo ... \| psql` |
| `inline_code` | `python -c`, `node -e`, `perl -e`, `pwsh -Command`, `env -S` |
| `ansi_c_quote` | `$'\x72m'` |
| `unbalanced_quote`, `unterminated_substitution`, `unterminated_comment` | malformed text |
| `dynamic_sql` | `EXECUTE stmt`, `EXECUTE 'DROP ' \|\| t`, `PREPARE s FROM @sql` |
| `nesting_too_deep` | more than 6 levels of `bash -c` / substitution |
| `too_long` | over 256 KB |
| `non_text_argument` | an object where a command was expected |

A definite finding in one argument wins over an unreadable one.

## What the approver and the logs see

The `Decision` carries `effect: { detector, kind, target, parsed, reason }`. `kind` and `reason` come from fixed sets. `target` (a table, path, branch, bucket) comes from the agent's text: control and format characters (including bidi overrides), Hangul fillers, blank Braille and variation selectors are removed, other space separators become a plain space, whitespace runs collapse, credentials are masked (`src/cloud/preview.ts`), and then it is cut to 120 characters. When one text has several `shell_destructive` findings, the widest is reported (the file system root, the whole home directory, a disk write or format); otherwise the first. Which finding is reported never changes whether the rule matches. It is for showing an approver and is **never** written to a receipt, the receipt log, stderr decision lines or a client error. Receipts still bind arguments only by `inputHash`. The decision reason names the rule id and the detector kind only, for example `Matched rule "shell" (shell_destructive: rm_recursive)`.

## Detectors

Shell-based detectors (`shell_destructive`, `terraform_destroy`, `cloud_delete`, `secret_read`) share one reader. It understands quoting and escapes, `$VAR` / `${VAR}` / `$(...)` / backticks / `<(...)` (substitutions are read as commands too), `;` `&&` `||` `|` `&` chains, subshells and braces, `if/then/fi`, redirections, heredocs and here-strings, comments, and line continuations. It unwraps `sudo`, `doas`, `env`, `nohup`, `time`, `nice`, `ionice`, `timeout`, `stdbuf`, `exec`, `command`, `builtin`, `busybox`, `xargs`, `watch`, `flock`, `su -c`, `runuser`, `ssh host 'cmd'`, `alias x='...'`, and `sh`/`bash`/`zsh`/`dash`/`ksh`/`fish` `-c`. Program names are matched case-insensitively by basename (`/bin/rm`, `\rm`, `"r"m`, `RM`).

### `sql_destructive`

Catches: `DROP` (any object; `drop_database`, `drop_schema`, `drop_table`, `drop_object`), `TRUNCATE`, `DELETE` / `UPDATE` without `WHERE` or with an always-true `WHERE` (`1=1`, `TRUE`, `'a'='a'`, `x = x`, `... OR 1=1`), `ALTER ... DROP` (not `DROP DEFAULT` / `DROP NOT NULL`), `MERGE ... DELETE`, `COPY ... PROGRAM`. Also inside data-modifying CTEs and subqueries, `EXPLAIN ANALYZE`, `DO` blocks, `CREATE FUNCTION/PROCEDURE/RULE` bodies, `PREPARE ... AS/FROM 'literal'` and `EXEC('literal')`.

Reading: case-insensitive; `--` comments (only when followed by whitespace, as MySQL requires), `/* */` (not nested), MySQL `/*! ... */` read as code, `#` not treated as a comment, quoted identifiers (`"x"`, `` `x` ``, `[x]`), dollar quotes, `E'..'`, `GO` separators. Strings are read twice, with and without backslash escapes, and either reading's finding counts.

Not caught: `DELETE ... WHERE id > 0` and other conditions that happen to cover every row; destructive stored procedures called with `CALL`; `DROP` via ORMs or migration files run by a tool; dialect-specific statements not listed (`DROP` equivalents like `RENAME` + recreate, `pg_terminate_backend`, `lo_unlink`). False positives: `EXPLAIN` without `ANALYZE`, `DROP INDEX`, valid MySQL strings with `\'` and valid PostgreSQL strings ending in a backslash (fail safe as `unbalanced_quote`).

### `shell_destructive`

Catches:
- `rm` with `-r`/`-R`/`--recursive` (any order, clustered, after operands, with or without `-f`) on `/`, absolute paths, `~` / `$HOME`, `..`, the working tree itself (`.`, `*`, `.*`), `.git`, or relative paths after a `cd` that left the tree; `--no-preserve-root`. A named entry under `/tmp` or `/var/tmp` is allowed (`/tmp/*` is not).
- `git push` with `--force`, `-f`, `--force-with-lease`, `--force-if-includes`, `+refspec` (`git_force_push`); `--delete`, `-d`, `--prune`, `:branch`, `:refs/tags/x` (`git_push_delete`); `--mirror` (`git_push_mirror`); `--all` / `--branches` (`git_push_all`, from 0.6.0; before, `git_push_protected`); a plain push to `main` / `master`, any refspec form (`git_push_protected`).
- `dd of=...`, `mkfs*`, `mke2fs`, `mkswap`, `wipefs`, `shred`, redirects into block devices.
- `find ... -delete`, `find ... -exec rm|shred|unlink`.
- `rm` fed by `xargs` (any flags): a definite match when the list comes from a `find` rooted outside the tree; allowed when it comes straight from a filtered `find` rooted inside the tree (`find . -name '*.o' | xargs rm`); otherwise (`cat list | xargs rm`, `xargs rm < list`, unfiltered `find . | xargs rm`, `find / | grep x | xargs rm`) it fails safe.
- `truncate` shrinking a file outside the tree (absolute, `~`, `..`); `-s +N` / `-s >N` only extend and are allowed.
- `mv` onto `/dev/null` or a block device, `cp` onto a block device.
- Overwrite redirects (`>`, `>|`, `&>`, not `>>`) and `tee` without `-a` onto absolute paths or `~` / `$HOME` paths. `/dev/*`, `/tmp/<name>` and `/var/tmp/<name>` are allowed.
- `chmod`/`chown`/`chgrp -R` on `/`, top-level system paths (depth 2 or less), `~` (depth 1 or less), `..`.
- Destructive SQL through `psql -c`, `mysql -e`, `sqlite3 db "..."`, `clickhouse-client -q`, heredocs and here-strings; SQL piped into a client fails safe.

Kinds (for `detect.kinds` / `detect.except_kinds`): `rm_recursive`, `rm_xargs`, `truncate_file`, `move_to_device`, `disk_write`, `overwrite_redirect`, `find_delete`, `git_force_push`, `git_push_delete`, `git_push_mirror`, `git_push_all`, `git_push_protected`, `recursive_permissions`, `disk_format`, `shred`, and the `sql_destructive` kinds for SQL sent through a client (`drop_database`, `drop_schema`, `drop_table`, `drop_object`, `truncate`, `delete_without_where`, `update_without_where`, `alter_drop`, `merge_delete`, `copy_program`).

Not caught: plain `git push` / `git push origin HEAD` while on `main` (the current branch is not known without I/O); overwrite redirects onto relative paths (`> ../x`) or a fully dynamic target (`> "$OUT"`); `>>` appends; `mv` or `cp` of data over another file (`mv a /etc/passwd`); `truncate` inside the tree; `git reset --hard`, `git clean -fdx`, `git branch -D`; non-recursive `rm` of single files; Windows commands (`del /s`, `Remove-Item -Recurse`); destructive scripts run from files (`./cleanup.sh`, `make clean`, `npm run reset`); `docker`/`kubectl exec` into containers; `find . -name '*.pyc' -delete` is caught (a false positive by design).

### `terraform_destroy`

Catches: `terraform destroy`, `terraform apply -destroy` / `--destroy`, `apply` of a plan file made by `plan -destroy` earlier in the same text, `apply -auto-approve` without a saved plan (a plan nobody saw), `TF_CLI_ARGS*` assignments that add `-destroy`; the same for `tofu` / `opentofu`, and `terragrunt` (including `run-all destroy`).

Not caught: `apply <planfile>` of a destroy plan made elsewhere (the guard does not read files); `terraform state rm`, `workspace delete`; resources destroyed by a normal `apply` because they were removed from configuration; wrappers such as Atlantis, Spacelift or `make apply`.

### `cloud_delete`

Catches delete operations on databases, volumes, disks, buckets, snapshots and backups, and on the projects, resource groups and clusters that contain them:
- `aws`: `delete-*` / `remove-*` / `terminate-*` operations naming a db, cluster, volume, bucket, snapshot, backup, table, file system, vault, recovery point, cache or stack; `ec2 terminate-instances`; `s3 rb`; `s3 rm --recursive`.
- `gcloud` (`delete` under sql, disks, snapshots, buckets, backups, databases, spanner, bigtable, alloydb, firestore, filestore, redis, memcache, projects, volumes, instances, clusters, images), `gcloud storage rm -r`, `gsutil rb` / `rm -r`, `bq rm`.
- `az` (`delete` / `purge` under sql, postgres, mysql, mariadb, cosmosdb, storage, disk, snapshot, backup, group, redis, netappfiles, keyvault, aks).
- `doctl` (databases, volumes, snapshots, backups, droplets, kubernetes, registry), `fly` / `flyctl` (`destroy` / `delete` of volumes, apps, postgres, storage, redis, mysql), `railway delete`, `supabase` (`projects|branches|orgs delete`, `db reset --linked|--db-url`, `storage rm -r`).
- `kubectl` / `oc`: `delete` of namespaces, PVCs, PVs, CRDs, and any `delete --all` / `-A`. `delete -f` / `-k` fails safe (the manifest is not read).

Not caught: SDK or API calls made by scripts; Terraform/Pulumi/CDK (`pulumi destroy`, `cdk destroy` are not covered); `aws s3 rm` of single objects; console actions; other CLIs (`heroku pg:reset`, `neonctl`, `planetscale`, `vercel remove`). A dynamic word among a CLI's first words (where the verb is) fails safe.

### `secret_read`

Catches:
- Reading secret files with `cat`, `head`, `tail`, `less`, `grep`, `sed`, `awk`, `jq`, `base64`, `xxd`, `cp`, `scp`, `rsync`, `tar`, `curl @file` / `-F f=@file`, `< file` and similar: `.env*` (not `.env.example` / `.sample` / `.template`), `*.env`, `~/.aws/credentials`, SSH private keys (`~/.ssh/*` except `.pub`, `known_hosts`, `config`, `authorized_keys`; `id_*` anywhere), `.netrc`, `.pgpass`, `.git-credentials`, `.npmrc`, `.pypirc`, `.vault-token`, `~/.docker/config.json`, `~/.kube/config`, gcloud and Azure credential directories, `*.pem`, `*.key`, `*.p12`, `*.pfx`, keychains, `/proc/*/environ`.
- A bare path argument that names one of those files (for `read_file`-style tools).
- Environment dumps: `printenv`, `env`, `set`, `export -p`, `declare -p/-x`; `printenv` / `echo` / `printf` of variables named like secrets (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`, `*_KEY`, `DATABASE_URL`, ...).
- Token printers and secret stores: `gcloud auth print-access-token` / `print-identity-token` / `config config-helper`, `gcloud secrets versions access`, `aws secretsmanager get-secret-value`, `aws ssm get-parameter --with-decryption`, `aws configure get *secret*` / `export-credentials`, `aws ecr get-login-password`, `aws kms decrypt`, `az account get-access-token`, `az keyvault secret show`, `gh auth token`, `vault read` / `kv get`, `op read` / `item get` / `inject`, `security find-*-password` / `dump-keychain`, `secret-tool lookup`, `pass show`, `kubectl get secret -o ...`, `doppler secrets`, `heroku config`, `railway variables`, `vercel env pull`, `git credential fill`.

Not caught: using a secret without printing it (`curl -H "Authorization: Bearer $TOKEN"` is allowed by design); `source .env`; secrets read by a program the agent runs (`node -p process.env` fails safe as inline code, `node print-env.js` does not); secret files with unusual names; reading a file via an editor or a language runtime file API exposed as its own MCP tool unless you list its path argument.

### `guard_tamper`

Changes to the guard by the agent it guards: its policy files, receipt logs, key store and install token, the MCP client configs that route a server through it, killing it, and `mcp-guard keys` / `init`. Reading those files does not match. What it catches and misses: [presets.md](presets.md#self-protection-guard_tamper).

## Known limits

These are the evasion classes the detectors do not stop. Treat the detectors as a seatbelt, not a jail.

1. **Code in files.** Anything run from a file (`./x.sh`, `python x.py`, `make`, `npm run`, `psql -f`, `kubectl apply -f`) is not read. An agent can write a file in one call and run it in the next.
2. **Two-step state.** A variable, alias or function defined in an earlier call, a `git config alias.x '!rm -rf /'`, a `PATH` change, or a symlink created earlier.
3. **Arguments not listed in the rule**, nested arguments (`{ input: { command } }`) and servers that accept alternate names.
4. **Tools that do the destructive thing natively** (`delete_database`, `drop_table` as MCP tools). Use exact-tool rules for those.
5. **Opaque runtimes.** Inline interpreter code fails safe; interpreter scripts do not. Containers (`docker exec`, `kubectl exec`) and remote shells other than `ssh host 'cmd'` are not followed.
6. **Context the guard cannot see without I/O**: the current git branch, the contents of plan files and manifests, what a path or glob expands to, which database a connection string points at.
7. **Dialects and shells not modelled**: PowerShell and `cmd.exe` syntax, fish-specific syntax, SQL dialect corners (MSSQL `EXEC` of procedures fails safe; `CALL` does not).
8. **Patterns.** `match.pattern` runs on JavaScript's backtracking regex engine on agent-controlled text (capped at 64 KB). Avoid nested quantifiers.

Report bypasses that matter to security@permissionprotocol.com.
