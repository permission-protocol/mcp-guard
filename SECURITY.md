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
- **Receipts:** Ed25519 over a domain-separated canonical envelope, with expiry, nonce and approver. Verifiers trust only pinned keys and refuse scoped receipts no human approved.
- **Keys:** kept in the operator's config directory with owner-only permissions; MCP Guard refuses to start if the private key is exposed.

Out of scope for the local dev signer: an agent running as the **same OS user** with arbitrary shell access can read that user's files and process memory, including the signing key and the approval token. For that threat, run the agent as a different user or use the managed Permission Protocol signer, where approval and signing happen outside the agent's machine.

## Safe harbor

We will not pursue or support legal action against good-faith security research that:

- respects user privacy and does not access, modify, or destroy data that is not yours;
- avoids service disruption (no denial of service, no spam);
- gives us reasonable time to remediate before public disclosure.

If you are unsure whether something is in scope, ask first at the address above.

## Notes

- There is no formal bug bounty program today. With your permission, we credit reporters in release notes.
- Our security and compliance posture is published at https://www.permissionprotocol.com/trust.
