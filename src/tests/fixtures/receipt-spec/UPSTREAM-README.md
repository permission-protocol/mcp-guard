Copies of `permission-protocol/receipt-spec` test vectors (`main`, commit
`3e5a99b1`, SPEC.md section 9). Replayed by
`tests/attestation-spec-vectors.test.ts` so a change to this app's `attest_v1`
canonicalization, `outputHash` or the jcs_v2 bytes of an execute-lane
authorization fails here, not only in the spec repository. Regenerate them in
the spec repository (`node tools/generate-vectors.mjs`) and copy them back;
never edit them here. The key is the spec repository's test key and signs
nothing outside it.
