# Security Policy

This repository contains MCP Guard, the Permission Protocol stdio policy proxy for MCP tool calls.

## Reporting a vulnerability

**Do not open public issues for security vulnerabilities.**

Email: security@permissionprotocol.com

Include a description, steps to reproduce, and your assessment of impact. We acknowledge reports within 48 hours and keep you informed through resolution.

Machine-readable contact: https://www.permissionprotocol.com/.well-known/security.txt

## Threat model

MCP Guard assumes the agent behind the MCP client is untrusted: it controls every tool argument, can send any bytes on stdin, and may be able to reach local ports. MCP Guard defends against that agent:

- **Input:** only single, well-formed JSON-RPC 2.0 objects are evaluated, and only the evaluated object is forwarded (re-serialized). Batches and unparseable lines are refused.
- **Policy:** every method except protocol plumbing is decided by the rules. Agent metadata (`_pp`) can add human attention but never removes it; spend caps read only the argument the rule names.
- **Approval channel:** loopback only, Host-checked, no CORS, and a per-process bearer token delivered in the URL fragment. Decisions go through one state machine; final states never change.
- **Receipts:** the Permission Protocol receipt standard (`jcs_v2`): Ed25519 over the SHA-256 of canonical bytes that bind the decision, decider, expiry, scope, policy version and an `inputHash` of the call, never raw arguments. Every final decision is signed, denials included. Gates trust only the key set they are given, pinned by fingerprint, and refuse scoped receipts no person approved, demo-key receipts, and 0.2 receipts unless explicitly accepted.
- **Keys:** created only by `mcp-guard keys init` / `keys rotate`, kept in the operator's config directory with owner-only permissions. The guard never generates a key; a missing, exposed, mismatched or revoked key is a typed error that stops signing, never a fallback. Revoking a key in `keys.json` invalidates every receipt it signed.
- **Decider honesty:** console decisions are signed as `local:<operator>` with `heuristic` confidence, because the operator name is configured rather than authenticated; a console approval with no operator is refused in production.

- **Signed approvals (`cloud:`):** a held call is forwarded only after a Permission Protocol receipt passes offline verification against keys pinned in the release (signature, fingerprint of the exact call, request id, human decider, approval, expiry, single use in this process) and a server-side single-use redeem succeeds. Every other outcome blocks. The API is not trusted for any of those facts, only for delivering the signed bytes; a compromised or impersonated API can block calls but cannot release one without Permission Protocol's signing key. For a held call the guard sends the tool name, the server label, the agent id, the environment label, the SHA-256 hash of the arguments (`argsHash`), and a preview of the arguments that the guard masks and caps at 2,048 bytes before sending (`argsPreview`; omitted with `cloud.args_preview: false`); Permission Protocol masks and caps the preview again before storing it. A held call opens the signing page in the local browser only for an `https:` link on the configured API origin, with no shell. See docs/hooks.md, "What is sent for a held call". The install token can open, read and redeem its own requests and cannot approve.

Out of scope for the local signer: an agent running as the **same OS user** with arbitrary shell access can read that user's files and process memory, including the signing key and the approval token. For that threat, run the agent as a different user or use the managed Permission Protocol signer, where approval and signing happen outside the agent's machine.

## Safe harbor

We will not pursue or support legal action against good-faith security research that:

- respects user privacy and does not access, modify, or destroy data that is not yours;
- avoids service disruption (no denial of service, no spam);
- gives us reasonable time to remediate before public disclosure.

If you are unsure whether something is in scope, ask first at the address above.

## Notes

- There is no formal bug bounty program today. With your permission, we credit reporters in release notes.
- Our security and compliance posture is published at https://www.permissionprotocol.com/trust.
