Copies of the `permission-protocol/receipt-spec` `jcs_v2` test vectors, taken from the
app repository's mirror (`permission-protocol/app`, `tests/fixtures/receipt-spec/`, at
commit `7720bc5`; the app copied them from receipt-spec `main` at `3e5a99b1`, SPEC.md
section 9). `UPSTREAM-README.md` is the app's note about them.

mcp-guard's verifier replays them (`src/tests/receipt-spec-vectors.test.ts`) so its
`jcs_v2` canonicalization and signature checks stay byte-for-byte compatible with the
org standard. Never edit them here; regenerate in receipt-spec and copy them back. The
key is the spec repository's test key and signs nothing outside it.
