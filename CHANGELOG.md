# Changelog

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
