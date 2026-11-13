# AGENTS.md: MCP Guard

Shared instructions for coding agents in this repository. `CLAUDE.md` imports this file.

## What this is

MCP Guard (`@permission-protocol/mcp-guard`, MIT) checks an agent's tool calls before they run: Claude Code's `Bash`, `PowerShell`, `Write`, `Edit` and `NotebookEdit` through a `PreToolUse` hook (`src/hook/`), and MCP `tools/call` and other methods through a stdio proxy (`src/proxy.ts`). Both use the same policy (`pp.config.yaml`, `src/config.ts`), engine (`src/engine.ts`) and detectors (`src/detect/`).

**Held call → signer decision in Permission Protocol → verified, redeemed receipt → the call runs.**

`src/cloud/hold.ts` is that path: hash the call locally, open an approval request, poll, verify the signed receipt offline (`src/cloud/verify.ts`), redeem it once, release. Every other outcome is `denied`, `expired` or `blocked`.

## Priorities

1. Install command to first signed receipt within 2 minutes.
2. A held call is impossible to miss.
3. Fail closed.
4. Every claim in `README.md` and `docs/` is true of the code.
5. Small, reviewable diffs.

## Non-negotiable rules

- Fail closed everywhere. The seams:
  - Policy load: the hook denies every call while the policy does not load (`src/hook/decide.ts`); the proxy exits (`src/cli.ts`).
  - Hook wrapper exit codes: the installed command maps every exit other than 0 and 2 to 2, with its own message for 127 (`failClosed` in `src/hook/install.ts`), and the hook entry sets `onFailure: "block"`.
  - Cloud errors: anything the guard cannot trust is `blocked` (`src/cloud/hold.ts`).
  - Receipt verification: all nine checks in `src/cloud/verify.ts` pass, or the call is refused with a typed code.
  - Redeem: a call runs only after a successful redeem of the verified receipt.
- Never weaken a detector or a default silently. When a default narrows, say so in `CHANGELOG.md` under "Changed".
- Nothing may create a new path to a released call. The only path is a verified receipt plus a successful redeem.
- Receipts are verified offline against keys pinned in the package (`src/cloud/pinned-keys.ts`). Never fetch keys at decision time.
- Never print, read or commit a real install token or key.
- Text that leaves the machine is listed in README "What is sent to Permission Protocol for a held call" and "Usage heartbeat". A change to what is sent changes those sections, and `docs/hooks.md` or `docs/heartbeat.md`, in the same PR.

## Wire contract

- The contract lives in the app repository: `permission-protocol/app`, `docs/mcp-approval-contract.md` (holds) and `docs/mcp-heartbeat-contract.md` (heartbeat).
- The app validates request bodies strictly and refuses unknown fields. A new field ships in the app first and is live before a guard release sends it.
- Pin the exact request body keys in tests (see `src/tests/hold-visible.test.ts` and `src/tests/heartbeat.test.ts`).

## Credential-shaped text

This repository's pull request gate denies any diff containing text that looks like a credential or private key, including test fixtures and docs. Build such fixtures at run time from pieces, as `fake()` and `fakePem()` do in `src/tests/preview.test.ts`.

## Platforms

- Windows needs Git for Windows: Claude Code runs the hook through Git Bash.
- CI runs on Ubuntu only. Windows and macOS behaviour is tested by injecting the platform (`platform: 'win32' | 'darwin' | 'linux'`; see `src/tests/windows-paths.test.ts`, `src/tests/init.test.ts`, `src/tests/hold-visible.test.ts`).
- Say in each PR what was and was not run on a real machine, per platform.

## Commands before a PR

```bash
npm ci
npm run build                                   # tsc
npm test                                        # node --test dist/src/tests/*.test.js
node scripts/demo-slice1.mjs                    # CI end-to-end demo drivers (after build)
node scripts/demo-slice2.mjs
node scripts/demo-slice25.mjs
npm run e2e:first-receipt                       # init to first signed receipt against a local stand-in
npm run demo                                    # proxy demo with a throwaway demo key
```

CI (`.github/workflows/ci.yml`) also runs `node scripts/audit-poc.mjs <root> --expect vulnerable|fixed`: every audit attack must succeed against baseline commit `1480615` and be stopped by the current code. To run it locally, build a checkout of that commit and pass its path.

## Release

- Releases use the manual Release workflow (`.github/workflows/release.yml`), run from `main`. Its publish job runs in the `npm-release` environment, which the founder approves, and publishes with npm trusted publishing (no npm token in the repository). It refuses any ref but `main` and any version already on npm.
- Agents never publish, tag, run the Release workflow or approve the environment.
- The version is recorded in `package.json`, `package-lock.json` (two places), the `CHANGELOG.md` heading, `templates/github-actions/receipt-gate.yml` and the example body in `docs/heartbeat.md`. Some tests use it as a fixture (`src/tests/presets.test.ts`, `src/tests/windows-paths.test.ts`, `src/tests/init.test.ts`). `mcp-guard --version` reads `package.json`.

## Docs map

| Document | Covers |
|----------|--------|
| `README.md` | Install, held calls, what is guarded and not caught, troubleshooting, what leaves the machine, proxy, policy reference, CLI |
| `SECURITY.md` | Reporting, threat model, signed approvals |
| `CHANGELOG.md` | Every release; narrowed defaults under "Changed" |
| `docs/hooks.md` | Hook setup with init, Claude Code hook contract, answers, wait and timeout, fail closed, limits |
| `docs/presets.md` | The `coding-agent` preset, production targets, self-protection |
| `docs/detectors.md` | Rule schema, detectors, fail-safe behaviour, known limits |
| `docs/heartbeat.md` | Heartbeat body, schedule, opt-out, how counts are made |
| `docs/index.html` | Receipt viewer page |
| `templates/github-actions/receipt-gate.yml` | CI receipt gate template |

## Communication

- Lead with the result.
- Report what ran, with real counts (for example tests passed and failed).
- Name what was not verified, including platforms not run on a real machine.
- Never claim a check passed unless it ran.
