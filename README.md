# MCP Guard

**Stop your AI agents from doing dangerous things.**

[MCP](https://modelcontextprotocol.io) (Model Context Protocol) is how AI agents call tools — like APIs, databases, or deployments. MCP has no built-in access control. MCP Guard adds that layer.

Define what's allowed, blocked, or requires approval — in a single YAML file. MCP Guard sits between your MCP client and server, enforces the rules, and records every decision as a signed receipt.

Every tool call, resource read and prompt fetch goes through your policy; only protocol plumbing (`initialize`, `ping`, list calls, notifications) passes untouched. **MCP Guard does not just log — it blocks execution before it happens.**

→ **Blocks** unsafe tool calls before they execute
→ **Holds** sensitive actions for human approval
→ **Signs** every decision as an Ed25519 receipt in the Permission Protocol receipt standard, naming who or what decided
→ **Observe mode** — audit what would be blocked before enforcing

<p align="center">
  <img src="assets/demo.gif" alt="MCP Guard Demo" width="700">
</p>

## Get Started (2 minutes)

```bash
# Install
npm install @permission-protocol/mcp-guard

# Create your signing key (once; the guard never creates one itself)
npx mcp-guard keys init

# Create a policy file
cat > pp.config.yaml << 'EOF'
default_action: allow
rules:
  - id: block-delete
    tool: delete_user_data
    action: block
  - id: hold-deploy
    tool: deploy_production
    action: require_approval
EOF

# Run your MCP server through the guard
mcp-guard --config pp.config.yaml -- node my-mcp-server.js
```

That's it. Your agent can no longer delete user data. Production deploys require approval. Every decision is signed and logged to `pp-receipts.jsonl`. Without a signing key the guard refuses to start (`SIGNING_KEY_MISSING`) rather than run unsigned.

`default_action: allow` lets any tool without a rule run, and the guard warns about it at startup. Use `block` or `require_approval` to fail closed.

## 60-Second Demo (no MCP server needed)

See MCP Guard block dangerous tool calls in real-time, no setup required:

```bash
npx @permission-protocol/mcp-guard demo
```

The demo signs with a throwaway demo key (`mcpg-demo-…`) in a temporary directory. Its receipts carry `scope: "demo"`, and gates refuse them.

## Architecture

```
┌────────────┐     stdio      ┌─────────────┐     stdio      ┌────────────┐
│  MCP Client│ ──────────────▶│  MCP Guard   │──────────────▶ │ MCP Server │
│  (Claude,  │                │  (proxy)     │                │ (your app) │
│   Cursor)  │ ◀──────────────│              │◀────────────── │            │
└────────────┘   responses    └─────────────┘   responses    └────────────┘
                                    │
                                    ▼
                              pp-receipts.jsonl
                              (audit trail)
```

MCP Guard parses every JSON-RPC message on stdin and forwards only what it parsed and evaluated, re-serialized:

1. A line that is not a single JSON-RPC 2.0 object (invalid JSON, a batch array, a malformed frame) gets an error and is never forwarded.
2. Plumbing passes through: `initialize`, `ping`, `notifications/*`, `tools/list`, `resources/list`, `resources/templates/list`, `resources/unsubscribe`, `prompts/list`, `logging/setLevel`, `completion/complete`.
3. Everything else — `tools/call`, `resources/read`, `prompts/get`, `resources/subscribe` and any method MCP Guard does not know — is decided by the rules, then `default_action`.
4. **Allowed** → forwarded (agent metadata under `_pp` is stripped first). **Blocked** → error `-32001`. **Held** → waits for a human (or returns `-32002` without an approval UI).
5. Every final decision (allowed, blocked, approved, denied, released by countdown, expired) emits a signed receipt (one stderr line + `pp-receipts.jsonl`). A held call is recorded unsigned until it is decided.

## Config Reference

```yaml
# pp.config.yaml
default_action: block        # allow | block | require_approval — when no rule matches
mode: enforce                # "enforce" (default) or "observe" (log only, never block)
approval_ttl_seconds: 900    # held requests expire after this (default 900)
receipt_ttl_seconds: 3600    # receipts for unscoped actions expire after this (default 3600)
scoped_receipt_ttl_seconds: 900  # receipts for merge / migration / deploy expire after this (default 900)
server_label: github-mcp     # names the MCP server in receipts (default "mcp-server"; never the command line)
signing: required            # required (default) | off: unsigned records that no gate accepts
# cloud: {}                  # optional: held calls need a named human's signature (see Signed approvals)

rules:
  - id: unique-rule-id       # unique identifier
    tool: tool_name          # exact tool name (tools/call rules)
    action: allow            # allow | block | require_approval

  - id: hold-reads
    method: resources/read   # govern another method (no "tool" field)
    action: require_approval

  - id: hold-email
    tool: send_email
    action: require_approval
    reversibility: reversible  # reversible | irreversible (default: irreversible)
    countdown_seconds: 300     # reversible only: auto-release unless someone holds it

  - id: spend
    tool: spend
    action: require_approval
    cap_usd: 50                # under the cap: runs now, shows in Verify; at/over: hard stop
    amount_arg: amount_usd     # required with cap_usd: the argument the tool actually charges
    receipt_ttl_seconds: 300   # optional: this rule's receipts expire sooner (any expiry is at most 86400)
```

The loader is strict: an unknown key, a duplicate rule, a countdown on an irreversible rule, or `cap_usd` without `amount_arg` fails at startup instead of being ignored. A missing or non-numeric amount is a hard stop. Agent metadata under `_pp` (`confidence`, `requires_input`) can route a card to a different lane but can never turn a held or blocked call into an allowed one, and `requires_input` never changes how an irreversible hold is presented.

### Modes

| Mode | Behavior |
|------|----------|
| `enforce` | Block/hold tool calls per rules (default) |
| `observe` | Log decisions + emit receipts, but always forward (dry-run) |

Use `observe` mode to audit what *would* be blocked before turning enforcement on. Switch via config or CLI: `--mode observe`.

### Actions

| Action | Behavior | JSON-RPC Error Code |
|--------|----------|-------------------|
| `allow` | Forward request to server | — |
| `block` | Reject immediately | `-32001` |
| `require_approval` | Hold for approval (or reject without an approval UI) | `-32002` |

Other errors the agent can receive: `-32003` denied by a human, `-32004` approval request expired, `-32005` release refused (receipt failed verification), `-32006` the decision could not be signed (missing, invalid or revoked key: nothing was forwarded), `-32007` signed approvals are on but Permission Protocol could not be reached or trusted (nothing was forwarded), `-32700` / `-32600` / `-32602` malformed input.

## Receipts

Every final decision is signed in the **Permission Protocol receipt standard** (`jcs_v2`, the format the Permission Protocol app issues and [`@permission-protocol/verify`](https://www.npmjs.com/package/@permission-protocol/verify) checks). Each line of `pp-receipts.jsonl` is:

```json
{
  "artifact": {
    "receipt_id": "rcpt_mg_mvtj9td5_63c091bfe0e7",
    "status": "APPROVED",
    "receipt_version": 2,
    "canonicalization": "jcs_v2",
    "key_id": "mcpg-3c1d2e4f5a6b7c8d",
    "alg": "ed25519",
    "signed_payload_hash": "<sha256 hex of the signed bytes>",
    "signature_b64": "<Ed25519 over that digest>",
    "payload_bytes_b64": "<the signed bytes>",
    "issued_at": "2026-10-29T15:30:00.000Z",
    "expires_at": "2026-10-29T15:45:00.000Z"
  },
  "record": {
    "id": "rcpt_mg_mvtj9td5_63c091bfe0e7",
    "agentId": "my-agent",
    "requestJson": "{\"action\":{\"operation\":\"tools/call\",\"resource\":\"infra-mcp\",\"tool\":\"deploy\"},…,\"scope\":{\"capability\":\"deploy:production\",\"commitSha\":\"a1b2c3d4\"}}",
    "inputHash": "sha256:<pp.hashable_payload.v1 of the call>",
    "status": "APPROVED",
    "policyVersion": "mcp-guard-config:sha256:<sha256 of pp.config.yaml>",
    "reasonCodes": "[\"RULE_MATCHED:deploy\",\"OPERATOR_APPROVED\"]",
    "deciderId": "local:rod",
    "deciderAuthMethod": "local_console",
    "attributionConfidence": "heuristic",
    "resolutionType": "allow_once",
    "scope": "production",
    "…": "the rest of the 24 signed fields"
  }
}
```

- **The artifact is what a gate verifies.** Its signed bytes are the record's fields, canonicalized. Verifiers read the decision, expiry, decider and scope only from the signed bytes, never from the convenience fields beside them, and a receipt never says it is "verified".
- **Who decided** is signed. A rule, a spend cap or a countdown signs `system/mcp-guard-policy` (`policy`). An approval or denial in the console signs `local:<operator>` (`--operator`, default the OS user) with `local_console` and `heuristic` confidence: the console token proves access to the guard's terminal, the name itself is configured. With no operator, a console approval is refused (`UNATTRIBUTED_PRODUCTION_DECIDER`) and the call stays held.
- **No raw arguments.** The signed request names the tool, method, server label, rule and scope; the arguments are bound only by `inputHash` (`pp.hashable_payload.v1` over `{tool, operation, input, metadata: null}`), which anyone holding the call can recompute (`verify --call`). Raw arguments appear only in the authenticated approval UI.
- **Reason codes** come from a fixed set: `RULE_MATCHED:<rule id>`, `DEFAULT_ACTION`, `COUNTDOWN_AUTO_RELEASE`, `OPERATOR_APPROVED`, `OPERATOR_DENIED`, `APPROVAL_EXPIRED`.

Receipts are written to stderr (one summary line), `pp-receipts.jsonl` (or `$PP_SHARED_RECEIPTS_PATH`), and optionally POSTed to `$PP_RECEIPT_ENDPOINT` (with `$PP_RECEIPT_TOKEN` as bearer auth).

### Signing keys

```bash
mcp-guard keys init            # first key: mcpg-<16 hex of sha256(public key)>
mcp-guard keys show            # key id, fingerprint, keys.json path, and the --trust value for gates
mcp-guard keys rotate          # new signing key; older keys stay in keys.json so their receipts still verify
mcp-guard keys revoke <key id> # every receipt that key signed stops verifying; rotate to sign again
```

Keys live in `~/.config/mcp-guard/keys` (or `$PP_KEYS_DIR`), never in the working directory: `keys.json` (the key set, in the shape served at `/.well-known/permission-protocol/keys.json`) and one `<key id>.private.pem` (0600). The guard signs with the newest key and never creates one. A missing, exposed, mismatched or revoked key stops the guard at startup in enforce mode, and if the key changes while it runs, allowed calls are refused with `-32006` and held calls stay held. In observe mode calls are still forwarded and their records say `signingFailed`.

### Verifying a receipt

```bash
# Once: commit the key set where your gate runs, and keep the --trust value it prints
mcp-guard keys show
cp ~/.config/mcp-guard/keys/keys.json .pp/keys.json

# In CI: verify offline against the pinned key
mcp-guard verify --receipt-file receipt.json --keys .pp/keys.json \
  --trust "$MCP_GUARD_TRUST" --scope deploy:production --scope-sha "$GITHUB_SHA"
```

The verifier requires `--scope`, trusts only the key set you give it (and, with `--trust`, only the pinned key), requires a signed `APPROVED` status and an unexpired signed `expiresAt`, checks scope exactly (a receipt that names a `scope.ref` or commit the gate did not ask for is refused too), and refuses:

- scoped receipts no person approved (`--allow-policy-approval` accepts them);
- receipts signed by a demo key (`--allow-demo`);
- mcp-guard 0.2 receipts (`--accept-legacy --pubkey <pem>` accepts them, labelled legacy);
- with `--call call.json` (`{"tool", "operation", "resource", "input"}`), a receipt whose signed resource differs or whose `inputHash` does not recompute from the call. `--require-call` makes `--call` mandatory. Build `call.json` from values the gate trusts, never from the input that delivers the receipt; a legacy 0.2 receipt cannot be checked this way and is refused.

Exit 0 = authorized, 1 = refused, 2 = missing input. See `templates/github-actions/receipt-gate.yml` for a deploy workflow that takes the verifier, key set, pin and receipt only from trusted places.

**Which commit a receipt binds.** A `deploy:<env>` receipt binds the commit being deployed. A `github:merge` receipt (a `merge_pr` call, or a PR approved through the webhook) binds the PR's **head** commit (`pull_request.head.sha`), not the merge commit GitHub creates: gate it with `--scope github:merge --scope-ref refs/pull/<n>/merge --scope-sha <head sha>`. A new push to the PR needs a new receipt.

The same artifact verifies with the org verifier, offline:

```bash
npx @permission-protocol/verify receipt.json --keys .pp/keys.json --trust "$MCP_GUARD_TRUST"
```

## CLI

```
mcp-guard init                   # connect to Permission Protocol, wrap one MCP server, sign a first receipt
mcp-guard [options] -- <server command>
mcp-guard receipt verify <receipt id> [--receipts-path <file>] [--config <policy.yaml>]
mcp-guard keys init [--demo] | keys rotate [--demo] | keys revoke <key id> | keys show
mcp-guard verify --receipt-file <path> --keys <keys.json> --trust ID=sha256:<hex> --scope s [--scope-ref r] [--scope-sha h]
mcp-guard export-key [out.pem]   # legacy 0.2 public key only, for --accept-legacy

Environment:
  PP_INSTALL_TOKEN        Install token for signed approvals (see Signed approvals)

Options:
  --config <path>         Path to config file (default: ./pp.config.yaml)
  --agent-id <id>         Agent identifier for receipts (default: "unknown")
  --operator <name>       Signed as the decider of console decisions (local:<name>; default: OS username)
  --mode <mode>           enforce or observe (overrides config file)
  --approval-port <port>  Enable the approval UI on 127.0.0.1:<port>
  -h, --help              Show help
```

### Example: Claude Desktop

In your Claude Desktop MCP config, replace:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["my-mcp-server.js"]
    }
  }
}
```

With:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "mcp-guard",
      "args": ["--config", "pp.config.yaml", "--agent-id", "claude-desktop", "--", "node", "my-mcp-server.js"]
    }
  }
}
```

## Approval Flow

When a call matches a `require_approval` rule, MCP Guard can hold it open and wait for a human in a local web UI instead of rejecting it.

```bash
mcp-guard --config pp.config.yaml --approval-port 3100 -- node my-mcp-server.js
# stderr: [mcp-guard] Approval UI: http://127.0.0.1:3100/#t=<token>
```

Open the exact URL printed at startup. The part after `#t=` is a per-process access token; it never leaves the browser except as the `Authorization: Bearer` header on API calls.

**How it works:**
1. Agent calls a tool that requires approval; MCP Guard holds the response open.
2. The call appears in the UI with every argument the server will receive.
3. **Approve** → MCP Guard signs a receipt naming you as the decider, verifies it against its own pinned key, then forwards the call. If it cannot sign, the call stays held and the UI shows the error code.
4. **Deny** → the agent gets error `-32003`, and the denial is signed. A decision is final: approving a denied call returns 409.
5. No decision within `approval_ttl_seconds` → the agent gets error `-32004`, and the expiry is signed as a denial.

**Security of the approval channel:** it listens on 127.0.0.1 only, rejects any other `Host` header, sends no CORS headers, and requires the token on every API route except the HMAC-signed GitHub webhook. `PP_APPROVAL_TOKEN` (32+ characters) supplies the token instead of generating one. The wrapped server is started without any `PP_*` environment variables, so a tool that echoes its environment cannot leak the token.

When `--approval-port` is **not** set, `require_approval` calls return `-32002` immediately.

This flow is local-only: the approver's name is whatever `--operator` says, not an authenticated identity, and the receipt is signed by a key on this machine. For a signature by a named, signed-in person, see Signed approvals below.

## Signed approvals (Permission Protocol account)

**Fastest way in:**

```bash
npx @permission-protocol/mcp-guard init
```

`init` opens a page where you connect this machine to your workspace (you need the owner or admin role; no secret is copied by hand), stores the install token in the OS keychain, finds the MCP servers Claude Code and Cursor are configured with, wraps the one you pick, writes a policy that holds one tool for a signature, and then holds a do-nothing test call so you sign your first receipt. It ends by printing the receipt, the command that verifies it again, and how long it all took. Your client's config file is copied aside before it is changed, and the copy's path is printed. `mcp-guard init --help` lists the options.

The rest of this section is what `init` sets up, for doing it by hand.

Without an account, MCP Guard runs **local-only**: holds are decided on the machine that runs the guard, and nothing records which person approved. Startup and every held call say so: `local-only, unsigned by Permission Protocol`.

With a `cloud:` section, a held call is released only by a receipt that a **named human signed** in Permission Protocol, and that anyone can verify with Permission Protocol's public key.

```yaml
# pp.config.yaml
server_label: filesystem          # the server name the signer sees
cloud:
  environment: production         # development | staging | production. A label for the signer; it clears nothing
  approval_timeout_seconds: 600   # how long a held call waits for a signature (30 to 3600, default 600)
```

```bash
export PP_INSTALL_TOKEN=pp_live_...   # a workspace API key with the single scope mcp:guard
mcp-guard --config pp.config.yaml --agent-id claude-code -- node my-mcp-server.js
```

Create the token in Permission Protocol under Settings > Developer access, with the scope `mcp:guard` and nothing else. It can open, read and redeem this install's own requests. It cannot approve anything. The guard reads it from `PP_INSTALL_TOKEN`, then the OS keychain (where `init` puts it), then `~/.config/mcp-guard/install-token` (owner-readable only). The wrapped server never sees it.

**Checking a receipt later.** `mcp-guard receipt verify <receipt id> --receipts-path <file>` re-verifies a logged receipt offline against the pinned keys and prints who signed what.

**What happens to a held call**

1. The guard hashes the arguments locally and computes the call's fingerprint: SHA-256 over the canonical JSON of `{argsHash, server, tool}`. Raw arguments are not sent. A preview of them is, so the signer can read the call; Permission Protocol masks secrets in it and keeps at most 2 KB.
2. It opens an approval request and prints the signing link to stderr. The signer opens it, signs in, and chooses Sign or Reject.
3. It polls with backoff (1 s rising to 5 s) until a decision or the timeout.
4. Before releasing, it verifies the receipt **offline**: the signature against the Permission Protocol key pinned in this release, the fingerprint against the one it computed from the held call, the request id, that the signer is a person, that the decision is an approval, and that the receipt has not expired (receipts expire 10 minutes after the signature).
5. It redeems the receipt, which works once, then forwards the call.
6. It appends a `{"cloud": ...}` line to the receipts file with the decision, the receipt id and URL, who signed, and the signed receipt itself. Never the arguments.

**Fail closed.** The call is forwarded only after step 5 succeeds. A rejection, a frozen workspace, a timeout, an API error, a receipt that fails any check, or a redeem that does not succeed all leave it blocked (`-32003`, `-32004`, `-32005` or `-32007`). If the arguments differ from the ones that were signed, the fingerprint differs and the receipt is refused. No environment variable turns any of this off. In enforce mode the guard does not start without a token.

**Pinned keys.** The production keys are compiled into the release (`src/cloud/pinned-keys.ts`); the guard never fetches a key when deciding. When Permission Protocol rotates its signing key, held calls are blocked until you upgrade to a release that pins the new key. To point at a non-production Permission Protocol, set `cloud.api_url` and list its keys in `cloud.trust_keys`; that list is refused for the production API.

**Notes**

- In cloud mode every `require_approval` call needs the signature. Countdowns (`countdown_seconds`) and the local approval UI do not release held calls.
- `mode: observe` still forwards everything and asks no one.
- Tool, server and agent names must be 1 to 128 characters of letters, digits and `_ . : / @ -`. A held call whose name has other characters is blocked.
- While a signature is pending, a failed status check (network, 429, 5xx) is retried until the timeout. It can only end in a verified receipt or a block.

## Why not just use X?

| Approach | Why MCP Guard is different |
|----------|---------------------------|
| API gateway | MCP operates at the tool-call layer, not HTTP. MCP Guard understands tool names and MCP's JSON-RPC protocol. |
| RBAC / IAM | Those gate *users*. MCP Guard gates *agent actions* — the agent is already authenticated, the question is what it's allowed to *do*. |
| "Just code it" | You could. MCP Guard gives you a declarative config, audit receipts, observe mode, and an approval UI — without changing your server code. |

## What This Is NOT

- **Not a dashboard.** It's a proxy. It sits in the data path and enforces rules.
- **Not a scanner.** It doesn't analyze your code or model outputs. It gates tool calls.
- **Not compliance theater.** Every decision has an Ed25519-signed receipt in the open receipt standard that names who or what decided.
- **Not a replacement for good architecture.** It's one layer in a defense-in-depth strategy.

Agents shouldn't be able to execute arbitrary actions without an explicit decision point.

## Part of Permission Protocol

MCP Guard is a building block of the [Permission Protocol](https://github.com/permission-protocol) — explicit authority for autonomous AI systems.

## License

MIT
