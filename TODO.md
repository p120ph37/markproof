# TODO

## Resolved by data-URL rewrite

The following issues from the initial security audit have been addressed:

- **Clean context problem**: The core finding — no guaranteed non-configurable property chain to a clean iframe. Resolved by pivoting to data-URL bookmarklets, which provide a browser-guaranteed clean browsing context.
- **C-1 (public key from manifest)**: Ed25519 public key is now embedded in bootstrap.js at build time.
- **C-2 (canonicalization mismatch)**: Build-time and runtime canonicalization now produce identical output.
- **S-2 (visual token in compromised context)**: Visual token system removed entirely.
- **M-1 (locked mode inoperative)**: Manifest hash passed through bookmarklet config.
- **M-2 (arguments in SHA-256)**: pure-sha256.js deleted; browser-native SRI replaces it.
- **M-5 (Ed25519 import fallback)**: Imports directly as SPKI, no error swallowing.

## Remaining work

- **Test suite**: No automated tests exist. Need SHA-256 test vectors for resource verification, Ed25519 signature round-trip tests, canonicalization consistency tests.
- **iOS compatibility**: Verify data-URL bookmarklet behavior across iOS Safari versions.
- **Fresh security audit**: The new data-URL architecture should be audited independently.
- **Regex minifier review**: The bookmarklet minifier uses regex-based comment/whitespace stripping. Less critical now (no crypto code in bookmarklet), but still worth reviewing.
