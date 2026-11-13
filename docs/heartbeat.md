# Usage heartbeat

When the policy has a `cloud:` section and an install token is present, MCP Guard sends Permission Protocol a small daily heartbeat: how many tool calls this install evaluated on one UTC day, and the ids of the rules that blocked or held the most calls. Permission Protocol uses it to list a workspace's installs (Settings > Developer access) and to count weekly-active installs. It is **on by default** and has an opt-out.

A heartbeat is observational. It cannot allow, block, hold or delay any call: it is built and sent by a separate process after the decision, a failed or refused heartbeat changes nothing, and nothing in Permission Protocol reads it for authorization, policy or signing.

## What is sent

`POST <cloud.api_url>/api/mcp/heartbeat` (production: `https://app.permissionprotocol.com/api/mcp/heartbeat`), with `Authorization: Bearer <install token>`, the same `mcp:guard` token that held calls use. The body has exactly these fields:

```json
{
  "guardVersion": "0.4.0",
  "clientLabel": "claude-code",
  "mode": "enforce",
  "day": "2026-11-12",
  "counts": { "allowed": 120, "blocked": 4, "held": 3, "approved": 2, "denied": 1, "expired": 0 },
  "topRules": [{ "ruleId": "no-secrets", "count": 4 }, { "ruleId": "destructive-shell", "count": 3 }]
}
```

| Field | Value |
|---|---|
| `guardVersion` | This package's version |
| `clientLabel` | A fixed label for the kind of client: `claude-code` (the hook), `mcp-proxy` (the proxy), or `mcp-guard` when one install counts both. Never a hostname, username or path |
| `mode` | `enforce` or `observe`, from the policy (or `--mode`) of the process that sends |
| `day` | The UTC day the counts are for |
| `counts` | That day's totals so far (not deltas), see [How the counts are made](#how-the-counts-are-made) |
| `topRules` | Up to 20 rule ids with how many calls each blocked or held that day. Omitted when there are none |

**Never sent:** tool arguments or any part of them, commands, file paths, file contents, tool names, server names, target names (databases, accounts, branches), agent ids, hostnames, usernames, receipt contents, or the install token anywhere but the `Authorization` header.

This is enforced in code (`src/heartbeat/contract.ts`): the body is built from an allowlist of these fields, the client label is one of the fixed values above, and before sending the body is checked against Permission Protocol's contract (exact field set, `ruleId` `^[A-Za-z0-9_.:-]{1,128}$`, `clientLabel` `^[A-Za-z0-9_.:-]{1,64}$`, the day window, counts 0 to 1,000,000, 8 KB). A rule id that does not match the pattern is **dropped**, never rewritten. A body that fails the check is not sent.

**Rule ids are written by the policy author.** They are the one free-text field that can leave the machine. If a rule id names something you do not want to share (a customer, a database, a person), rename the rule or turn the heartbeat off. Rule ids with `/`, `@`, whitespace or quotes are never sent.

## See it before it is sent

```bash
npx mcp-guard heartbeat --show                 # prints today's exact body; sends nothing, changes nothing
npx mcp-guard heartbeat --send                 # sends once now
```

Both take `--config <path>` (default `./pp.config.yaml`) and `--receipts <path>` (default `PP_SHARED_RECEIPTS_PATH`, else `pp-receipts.jsonl` beside the policy, which is where the hook writes; the proxy writes `pp-receipts.jsonl` in its working directory unless `PP_SHARED_RECEIPTS_PATH` is set). `--show` also says where it would POST and whether an install token is present (never its value).

## How often

- At most one send attempt per install every **10 minutes** (Permission Protocol accepts 12 per minute), and at least one per UTC day on which the guard runs.
- Each attempt sends today's totals, plus up to two earlier days (within the last 7) whose totals changed since Permission Protocol last accepted them, so the end of yesterday is not lost. A day whose totals have not changed since it was accepted is not sent again.
- Per install per day the last heartbeat wins, so a resend replaces the earlier one and never double-counts.
- One request at a time, a 5-second timeout, no retries. After `429` the guard waits for `Retry-After` (at most an hour); after `400`, `401`, `403` or `413` it sends nothing for 6 hours. A timeout, a refused connection or a `5xx` waits for the next 10-minute slot.

**In the hook** (one process per tool call): after the hook has answered, it reads one small state file. If a send is due, it starts `mcp-guard heartbeat --background` as a detached process with no stdio and exits without waiting. The hook process itself never opens a network connection for a heartbeat, so a policy-allowed call still makes no network request in the hook process.

**In the proxy** (long-lived): a timer starts the same sender as a child process 30 seconds after start and then every 10 minutes, one at a time. If a send fails, the proxy prints one line, `[mcp-guard] heartbeat not sent (<code>)`, with a code such as `HTTP_503` or `TIMEOUT` and nothing else.

## Turning it off

Any one of these:

- `MCP_GUARD_HEARTBEAT=off` (or `0`, `false`, `no`) in the environment of the guard;
- in the policy:

  ```yaml
  cloud:
    heartbeat: false
  ```

  (`true` or `false` only; any other value is a startup error, like every other policy key);
- no `cloud:` section (local-only mode never sends one);
- no install token.

Turning it off changes nothing else: held calls still go to Permission Protocol for a signature.

## How the counts are made

From the local receipt log, the guard's record of every decision (`src/receipt-log.ts`). Each line counts as follows:

| Line | Counts as |
|---|---|
| `{"record": ...}` receipt with reason `OPERATOR_APPROVED` or `COUNTDOWN_AUTO_RELEASE` | `approved` |
| `{"record": ...}` receipt with reason `OPERATOR_DENIED` | `denied` |
| `{"record": ...}` receipt with reason `APPROVAL_EXPIRED` | `expired` |
| any other `{"record": ...}` receipt, status `APPROVED` (a policy allow) | `allowed` |
| any other `{"record": ...}` receipt, status `DENIED` (a policy block) | `blocked`, and its rule in `topRules` |
| `{"hold": ...}` | `held`, and its rule in `topRules` |
| `{"cloud": ...}` with decision `released` / `denied` / `expired` | `approved` / `denied` / `expired` |
| `{"cloud": ...}`, any decision | also `held` (and its rule), unless it closes an open proxy `{"hold": ...}` line (below) |
| `{"cloud": ...}` with decision `blocked` (Permission Protocol unreachable, a receipt that failed verification) | no outcome |
| `{"observed": ...}` (an `observe: true` rule's would-be effect) | nothing: the call's real decision has its own line |
| unreadable lines, lines older than 7 days | nothing |

Each line is counted on the UTC day of its own time (`createdAt` or `at`).

One held call writes one `held`: the proxy without the local approval UI writes a `{"hold"}` line and then a `{"cloud"}` line for the same call, so a `{"cloud"}` line closes the oldest open `{"hold"}` line with `id: null` and the same agent, method, tool and rule written in the previous 65 minutes, and the pair counts once. Hook `{"hold"}` lines (agent `claude-code`) never pair, because a hook run writes one or the other.

Known limits of the mapping:

- In observe mode a would-be block or hold is counted as `blocked` or `held` (that is what the receipt records), with `mode: observe`.
- A hook call whose wait ran out counts `held` and `expired`; running it again after it is signed counts another `held` and an `approved`.
- A GitHub webhook hold (the local approval UI) has no `{"hold"}` line, so its approval or denial is counted without a `held`.

## State, and a large log

Counting never rereads the whole log. A state file beside the guard's other state, `heartbeat-state.json` next to the key directory (`~/.config/mcp-guard/` by default), mode 0600, keeps for each receipt log its byte offset, a hash of the last bytes counted, and per-day totals for the last 7 days; and for the install the last attempt time and a hash of the last accepted body per day. Counts and rule ids only. Each run reads only what was appended since the offset (at most 32 MB per run; the rest on the next run) and only complete lines. A log that was replaced, truncated or rewritten is recounted from its start, which gives the same totals as before for what it still holds. A missing or corrupt state file is rebuilt from the logs. A lock file beside it keeps parallel hook processes from sending twice or corrupting it.

One install token is one install, so the totals of every receipt log the install has counted in the last 8 days (for example the hook's log in two projects) are added together.
