# Changelog

## Unreleased

### Added

- `mcp-guard verify` checks receipts in the org receipt standard (`jcs_v2` artifacts, as issued by Permission Protocol and verified by `@permission-protocol/verify`): `--keys <keys.json>` and `--trust KEY_ID=sha256:<fingerprint>`. The checks follow the receipt-spec order (key, payload hash, Ed25519 over the digest, canonical bytes, identity), then the gate checks read only from the signed payload: approved status, signed expiry, exact scope (`scope.capability`, `scope.ref`, `scope.commitSha`) and an attributed human decider for scoped actions. mcp-guard 0.2 receipts still verify with `--pubkey` and are labelled legacy. Signing in the new format follows in 0.3.0.
- CI job `Audit regression`: replays the October 2026 audit attacks against the pre-fix commit (all must succeed) and the current code (all must be stopped) on every run.

### Changed

- Workflows and the receipt-gate template use `actions/checkout@v5` and `actions/setup-node@v5`; the template pins `@permission-protocol/mcp-guard@0.2.1`.

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
