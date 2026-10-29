A receipt issued by mcp-guard 0.2 (`{ envelope, signature, display }`), with the public key
that signed it. It is valid for a century so it never expires in tests. Used to prove that
0.3 still verifies 0.2 receipts on the labelled legacy path, and only with `--accept-legacy`.
Its key is a throwaway test key and signs nothing else.
