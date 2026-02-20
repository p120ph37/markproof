# TODO

## C-1: Ed25519 signature verification chain is non-functional

The Ed25519 manifest signature verification is currently non-functional due to three related issues that break the intended chain of trust.

**Intended chain of trust:**
1. Bookmarklet has an embedded hash → validates bootstrap
2. Bootstrap has an embedded public key (or manifest hash in locked mode) → verifies manifest
3. Manifest has hashes → verifies all other resources

**Actual behavior:** The public key is read from the manifest itself (or missing entirely), and a canonicalization mismatch prevents valid signatures from ever verifying.

### Issue 1: Public key read from manifest instead of embedded in bootstrap

In `src/plugin/runtime/bootstrap.js` lines 640-648, `fetchAndInstall()` reads the public key from the manifest it is trying to verify:

```javascript
if (manifest.publicKey) {
  return importEd25519PublicKey(manifest.publicKey).then(function(pubKey) {
    return verifyManifest(manifest, pubKey);
  });
}
// If no public key in manifest, check if we have one hardcoded
// (This is where a production deployment would embed the key)
return manifest;
```

The same pattern repeats in `checkForUpdates()` at line 743. This is circular — the manifest authenticates itself with its own key. An attacker who controls the server can generate their own keypair, embed their public key in a malicious manifest, sign it, and the bootstrap would accept it.

### Issue 2: No verification when public key is absent

The fallback at line 648 (`return manifest;`) passes the manifest through unsigned and unverified.

### Issue 3: Canonicalization mismatch between build-time and runtime

Build-time canonicalization in `src/plugin/manifest.ts` lines 34-36 **includes** `publicKey`:
```typescript
if (manifest.publicKey) {
  canonical.publicKey = manifest.publicKey;
}
```

Runtime canonicalization in `src/plugin/runtime/bootstrap.js` lines 285-303 **excludes** `publicKey`:
```javascript
var canonical = {
  version: manifest.version,
  timestamp: manifest.timestamp,
  resources: {}
};
```

The data signed at build time differs from the data verified at runtime, so even legitimate signatures always fail verification.

### Net effect

- **Build with signing key:** Signature verification always fails (canonicalization mismatch) → app refuses to load
- **Build without signing key:** Manifest accepted without any verification → signature chain bypassed entirely

### Proposed fix

1. Embed the public key as a constant in `bootstrap.js` at build time (similar to how `BOOTSTRAP_HASH` is embedded in the bookmarklet)
2. In locked mode, use a manifest hash instead of a public key
3. Align the canonicalization functions in `manifest.ts` and `bootstrap.js` so they produce identical output
4. Remove `publicKey` from the manifest (it should not be self-authenticating)
5. Require signature verification when a public key is embedded (no silent fallback)

---

## Tests: Validate the intended trust chain

Write tests covering the full chain of trust with both positive and negative cases at each step.

### Step 1: Bookmarklet → Bootstrap (hash verification)

**Positive:**
- Bookmarklet accepts bootstrap content whose SHA-256 matches the embedded `BOOTSTRAP_HASH`

**Negative:**
- Bookmarklet rejects bootstrap content with any modification (single byte change, truncation, appended data)
- Bookmarklet rejects empty/missing bootstrap content

### Step 2: Bootstrap → Manifest (signature verification)

**Positive:**
- Bootstrap accepts a manifest signed by the private key corresponding to the embedded public key
- Locked mode: bootstrap accepts a manifest whose hash matches the embedded manifest hash

**Negative:**
- Bootstrap rejects a manifest signed by a different keypair
- Bootstrap rejects a manifest with a valid signature but tampered content (changed version, added/removed resource, altered hash)
- Bootstrap rejects an unsigned manifest when a public key is embedded
- Bootstrap rejects a manifest that embeds its own public key (self-authenticating manifest must not be accepted)
- Locked mode: bootstrap rejects a manifest whose hash does not match the embedded hash

### Step 3: Manifest → Resources (hash verification)

**Positive:**
- Bootstrap accepts resources whose SHA-256 hashes match the manifest entries

**Negative:**
- Bootstrap rejects a resource with modified content
- Bootstrap rejects a resource swapped for a different valid resource (correct hash for wrong path)
- Bootstrap rejects when a resource listed in the manifest is missing
- Bootstrap rejects when an extra unlisted resource is injected

### Cross-cutting: Canonicalization consistency

- Build-time `canonicalizeManifest()` and runtime `canonicalizeManifest()` produce identical output for the same manifest input
- Signature produced at build time verifies successfully at runtime (round-trip test)
