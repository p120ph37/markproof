# Implementation Plan: Full SRI Rewrite

## Context

The SECURITY-AUDIT.md identified two critical bugs that render the entire Ed25519 signature verification chain non-functional, plus several significant issues. Rather than patching the existing broken architecture, we are rewriting the bookmarklet verification layer to use browser-native Subresource Integrity (SRI), and fixing all critical/significant issues in the process.

## Background: Why a Rewrite

The current architecture has the bookmarklet embedding a ~230-line pure-JS SHA-256 implementation (built from engine-guaranteed primitives) to hash-verify the bootstrap script. This is clever but produces a ~8KB bookmarklet and introduces fragility (regex-based minification of security-critical code, `arguments` object usage, etc.).

Browser-native SRI (`<script integrity="sha256-...">`) achieves the same goal — verifying fetched content before execution — with zero custom crypto code. The browser's own implementation is faster, tested, and trustworthy within the clean iframe context.

Additionally, the visual token system (S-2) is displayed in the compromised parent window, undermining its purpose. Rather than fix it (which would require rendering UI within the tiny clean iframe), we remove it — it was explicitly documented as having "no cryptographic role."

## Critical Bugs Being Fixed

### C-1: Public Key from Untrusted Manifest (Signature Bypass)
- `bootstrap.js:640-648`: Public key read FROM the manifest it's verifying (circular)
- Fallback at line 648 skips verification entirely when no key present
- **Fix:** Embed public key as a build-time constant in bootstrap.js

### C-2: Canonicalization Divergence (Signatures Always Fail)
- Build-time (`manifest.ts:28-54`) includes `publicKey` and `urls` in canonical form
- Runtime (`bootstrap.js:285-303`) excludes both
- Signature computed at build time never matches at runtime
- **Fix:** Unify canonical forms — exclude `urls` (delivery hints), exclude `publicKey` (no longer in manifest)

### M-1: Locked Mode Inoperative
- `bootstrap.js:654`: `expectedManifestHash` read from the manifest itself (circular)
- **Fix:** Pass manifest hash through bookmarklet config

---

## Architecture: Before and After

### Before (Current)
```
Bookmarklet (~8KB):
  - Origin check (char-by-char comparison)
  - Pure-JS SHA-256 (~230 lines inlined)
  - Property chain validation + clean iframe creation
  - Fetch bootstrap via (poisoned) fetch
  - Hash-verify bootstrap with pure-JS SHA-256
  - Pass config to clean iframe
  - Execute bootstrap via cleanWin.eval()

Bootstrap:
  - Read public key from manifest (C-1 bug)
  - Mismatched canonicalization (C-2 bug)
  - Display visual token in parent window (S-2 bug)
  - Locked mode reads hash from manifest (M-1 bug)
```

### After (New)
```
Bookmarklet (~2KB):
  - Origin check (char-by-char comparison)
  - Property chain validation + clean iframe creation
  - Create <script> tag in clean iframe with:
      src = bootstrap URL
      integrity = "sha256-BASE64HASH"
      crossOrigin = "anonymous"
  - Browser-native SRI verifies bootstrap before execution
  - Config passed via cleanWin.__bookmarkletConfig

Bootstrap:
  - EMBEDDED_PUBLIC_KEY constant (injected at build time)
  - Unified canonicalization (matches manifest.ts exactly)
  - No visual token display
  - Locked mode uses manifestHash from bookmarklet config
```

### Why SRI Works Here

In the clean iframe context, `document.createElement`, `appendChild`, and the browser's resource loading pipeline are all genuine (unmodified by page JS). When we create `<script src="..." integrity="sha256-...">` in the clean iframe:

1. The clean iframe's genuine fetch mechanism retrieves the bootstrap
2. The browser's native SRI implementation verifies the hash
3. If hash matches: script executes in the clean iframe
4. If hash mismatches: script does not execute, `error` event fires

This is equivalent to the current pure-JS SHA-256 verification but delegated to the browser engine. The SRI hash is embedded in the bookmarklet (trusted), just like the current hex hash is.

**Note on SRI hash format:** SRI uses base64-encoded hashes with algorithm prefix, e.g., `sha256-BASE64`. The build pipeline needs to produce base64 hashes instead of hex.

**Note on CORS:** SRI requires the `crossorigin` attribute on the script tag. The bootstrap URL must be served with CORS headers. GitHub Pages (the primary deployment target) does this by default.

---

## Step-by-Step File Changes

### Step 1: Rewrite `src/plugin/runtime/bookmarklet.js`

Remove:
- The `// __PURE_SHA256_SOURCE__` placeholder and all references to `pureSha256()`
- The `VISUAL_TOKEN` variable and config passing
- The `fetchBootstrap()` function and manual hash checking
- The `cleanWin.eval(bootstrapSource)` approach

Keep:
- The origin check (char-by-char string comparison using engine-guaranteed primitives)
- The `validateAndCreateCleanContext()` function (property chain validation, clean iframe)
- The abort handler

Add:
- SRI-based bootstrap loading: create `<script>` in clean iframe document
- Set `script.integrity = 'sha256-' + BOOTSTRAP_HASH_BASE64`
- Set `script.crossOrigin = 'anonymous'`
- Set `script.src = BOOTSTRAP_URL`
- `script.onerror` → abort with integrity failure message
- Before appending script, set `cleanWin.__bookmarkletConfig` with: `originUrl`, `bootstrapUrl`, `hmacKey`, `updateMode`, `parentWindow`, and optionally `manifestHash` (for locked mode)

New placeholder list:
- `__ORIGIN_URL__` (keep)
- `__BOOTSTRAP_HASH_BASE64__` (new — base64 instead of hex)
- `__BOOTSTRAP_URL__` (keep)
- `__HMAC_KEY__` (keep)
- `__UPDATE_MODE__` (keep)
- `__MANIFEST_HASH__` (new — for locked mode, empty string if auto)

Removed placeholders:
- `__VISUAL_TOKEN__` (removed)
- `__BOOTSTRAP_HASH__` (replaced by `__BOOTSTRAP_HASH_BASE64__`)

### Step 2: Delete `src/plugin/runtime/pure-sha256.js`

No longer needed. The browser's native SRI does the hash verification.

### Step 3: Rewrite `src/plugin/runtime/bootstrap.js`

**Changes to configuration section (top of file):**
- Remove `VISUAL_TOKEN` from config reading
- Add: `var MANIFEST_HASH = config.manifestHash || '';`
- Add build-time constant: `var EMBEDDED_PUBLIC_KEY = '__PUBLIC_KEY__';`

**Changes to `canonicalizeManifest()` (line 285-303):**
The canonical form must match `manifest.ts` exactly. After the manifest.ts changes (Step 5), the canonical form will be:
```javascript
function canonicalizeManifest(manifest) {
  var canonical = {
    version: manifest.version,
    timestamp: manifest.timestamp,
    resources: {}
  };
  var keys = Object.keys(manifest.resources).sort();
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    canonical.resources[key] = {
      hash: manifest.resources[key].hash,
      size: manifest.resources[key].size
    };
  }
  return JSON.stringify(canonical);
}
```
(This is the same as the current runtime version — the change is in manifest.ts to remove `publicKey` and `urls` from the build-time version.)

**Changes to `showVisualIdentity()` (line 347-377):**
Delete this entire function and all calls to it.

**Changes to `fetchAndInstall()` (line 622-725):**
Replace lines 636-648 (the public key logic) with:
```javascript
// Use the embedded public key (injected at build time)
if (EMBEDDED_PUBLIC_KEY && EMBEDDED_PUBLIC_KEY !== '__PUBLIC_KEY__') {
  return importEd25519PublicKey(EMBEDDED_PUBLIC_KEY).then(function(pubKey) {
    return verifyManifest(manifest, pubKey);
  });
} else {
  // No public key embedded — unsigned development build
  console.warn('markproof: No signing key embedded. Manifest is NOT signature-verified.');
  if (!manifest.resources || !manifest.version) {
    throw new Error('Invalid manifest structure');
  }
  return manifest;
}
```

Replace lines 652-665 (locked mode) with:
```javascript
// In locked mode, verify manifest hash matches bookmarklet-embedded hash
if (UPDATE_MODE === 'locked' && MANIFEST_HASH) {
  return computeManifestHash(manifest).then(function(hash) {
    if (hash !== MANIFEST_HASH) {
      throw new Error('Locked mode: manifest hash mismatch. Expected: ' + MANIFEST_HASH + ', got: ' + hash);
    }
    return manifest;
  });
}
```

**Changes to `checkForUpdates()` (line 730-758):**
Replace lines 742-749 (same public key bug) with the same EMBEDDED_PUBLIC_KEY approach:
```javascript
if (EMBEDDED_PUBLIC_KEY && EMBEDDED_PUBLIC_KEY !== '__PUBLIC_KEY__') {
  verifyPromise = importEd25519PublicKey(EMBEDDED_PUBLIC_KEY).then(function(pubKey) {
    return verifyManifest(networkManifest, pubKey);
  });
} else {
  verifyPromise = Promise.resolve(networkManifest);
}
```

**Changes to `injectApp()` (line 436-507):**
Remove the call to `showVisualIdentity(body)` at line 502.

**Changes to `main()` (line 512-572):**
Remove `showVisualIdentity()` call at line 513.

**Changes to `importEd25519PublicKey()` (line 136-152):**
Fix M-5: import directly as SPKI (the key format we generate), don't swallow errors:
```javascript
function importEd25519PublicKey(base64Key) {
  var raw = atob(base64Key);
  var bytes = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return crypto.subtle.importKey(
    'spki', bytes, { name: 'Ed25519' },
    false, ['verify']
  );
}
```

### Step 4: Update `src/plugin/bookmarklet.ts`

**Interface changes:**
- Remove `visualToken` from `BookmarkletOptions`
- Change `bootstrapHash` to `bootstrapHashBase64` (base64 instead of hex)
- Add optional `manifestHash?: string` for locked mode

**`generateBookmarklet()` changes:**
- Remove `pureSha256Source` reading and inlining (`// __PURE_SHA256_SOURCE__` replacement)
- Remove `__VISUAL_TOKEN__` placeholder replacement
- Replace `__BOOTSTRAP_HASH__` with `__BOOTSTRAP_HASH_BASE64__`
- Add `__MANIFEST_HASH__` placeholder replacement
- Update minification call (still needed for whitespace/comment stripping)

**`getTemplateSources()` changes:**
- Remove `pureSha256Source` from the return value (file no longer exists)
- Return only `bookmarkletTemplate`

**`minifyBookmarklet()` function:**
- Keep as-is (still useful for stripping comments and whitespace from the bookmarklet template)

### Step 5: Update `src/plugin/manifest.ts`

**`canonicalizeManifest()` changes (lines 28-54):**
- Remove the `if (manifest.publicKey)` block (lines 34-36)
- Remove `urls` from resource entries (remove lines 46-48 where `entry.urls = r.urls`)
- Final canonical form: `{ version, timestamp, resources: { [path]: { hash, size } } }`

**`Manifest` interface:**
- Remove `publicKey?: string` field
- Keep `signature?: string`

**`generateManifest()` changes:**
- Remove `publicKeyBase64` parameter
- Remove the `if (publicKeyBase64)` block that sets `manifest.publicKey`

### Step 6: Update `src/plugin/builder.ts`

**Step 3 (copy bootstrap.js) — add public key injection:**
After reading `bootstrapSource`, before writing it:
```typescript
let bootstrapOutput = bootstrapSource;
if (publicKeyBase64) {
  bootstrapOutput = bootstrapOutput.replace("'__PUBLIC_KEY__'", JSON.stringify(publicKeyBase64));
}
```
Then write `bootstrapOutput` instead of `bootstrapSource`, and hash `bootstrapOutput` (the hash must be of the file as deployed, with the key embedded).

**Bootstrap hash format:**
Change from hex to base64:
```typescript
const bootstrapHashBase64 = createHash('sha256').update(bootstrapOutput).digest('base64');
```
Keep hex hash too if needed for other purposes, but the bookmarklet needs base64.

**Step 5 (derive public key):**
Keep as-is, but note that `generateManifest` no longer takes `publicKeyBase64`.

**Step 6 (generate manifest):**
Change call from `generateManifest(appFiles, version, publicKeyBase64)` to `generateManifest(appFiles, version)`.

**Step 8 (build installer) — update define constants:**
- Remove `__PURE_SHA256_SOURCE__` define
- Change `__BOOTSTRAP_HASH__` to `__BOOTSTRAP_HASH_BASE64__` with base64 value
- Remove any visual-token-related defines
- Add `__MANIFEST_HASH__` define (compute from the signed manifest's canonical form)

**`BuildResult` interface:**
- Change `bootstrapHash: string` to `bootstrapHashBase64: string` (or add both)

### Step 7: Simplify `src/installer/index.html`

Remove:
- The warning banner (`<div class="warning-banner">`)
- The entire mimic zone (`<div class="mimic-zone">` and all children)
- All mimic/glitch/melt CSS animations
- The visual token form field
- The visual token hint text
- References to visual token in instructions

Keep:
- Basic page structure and dark theme styling
- The installer card with: update mode select, generate button
- The result section with: bookmarklet drag link, HMAC key backup display
- The instructions (simplified — remove step about verifying visual token)
- Footer

### Step 8: Update `src/installer/generator.ts`

Remove:
- `__BOOKMARKLET_TEMPLATE__` and `__PURE_SHA256_SOURCE__` build-time constant declarations (template is still needed, but sha256 source is not)
- Wait — actually the generator still needs `__BOOKMARKLET_TEMPLATE__` to assemble the bookmarklet client-side
- Remove `__PURE_SHA256_SOURCE__` declaration and usage
- Remove `initMimic()` function entirely
- Remove `visualToken` from `assembleBookmarklet()` and `initGenerator()`
- Remove `visualTokenInput` references

Update:
- `assembleBookmarklet()`: Remove `__PURE_SHA256_SOURCE__` inlining, remove `__VISUAL_TOKEN__` replacement
- Replace `__BOOTSTRAP_HASH__` with `__BOOTSTRAP_HASH_BASE64__` in placeholder replacement
- Add `__MANIFEST_HASH__` placeholder replacement (empty string for auto mode, computed hash for locked mode)
- `initGenerator()`: Remove visual token input handling, simplify to just update mode

### Step 9: Update `src/plugin/index.ts`

- Remove `ManifestResource.urls` from the type (already handled by manifest.ts change)
- Ensure all renamed exports are correct
- Keep the same public API surface minus visual-token-related options

### Step 10: Delete `SECURITY-AUDIT.md`

The findings are being addressed by this rewrite. The audit itself was the impetus; the fixed codebase should get a fresh audit.

### Step 11: Rewrite `DESIGN.md`

Key sections to update:
- **Section 2.1 (Three Components):** Remove visual token from bookmarklet diagram; add "Bootstrap Hash (SHA-256, base64)" replacing the generic SHA-256 box; remove "Pure-JS SHA-256" box from the bookmarklet
- **Section 2.2 (Chain of Trust):** Link 1 now says "The bookmarklet loads the bootstrap in the clean iframe using a `<script>` tag with browser-native SRI (Subresource Integrity). The expected hash is embedded in the bookmarklet."
- **Section 3 (Engine-Guaranteed Primitives):** Remove the entire pure-JS SHA-256 discussion (Sections 3.2, 3.3). Keep Section 3.1 (what cannot be intercepted) since the chain validation still uses these.
- **Section 4 (Clean Context):** Keep, but update to note that SRI verification happens within the clean context's native loading pipeline.
- **Section 5 (Update Modes):** Remove `publicKey` from manifest structure example. Add note about `manifestHash` in locked mode being passed through bookmarklet config.
- **Section 6 (Per-Installation Secrets):** Remove Section 6.1 (Visual Identity Token) entirely. Keep Section 6.2 (HMAC Key). Remove Section 6.3 (why two secrets) — there's now only one secret.
- **Section 7 (Cache Integrity):** Keep as-is.
- **Section 8 (Untrusted Origin Page):** Remove Section 8.2 (Anti-Training / Mimic Page).
- **Section 10 (Build System):** Update bookmarklet generation description — no more pure-SHA-256 inlining, SRI hash instead. Note that bootstrap.js has public key injected at build time.
- **Section 12 (Security Analysis):** Update "Bootstrap integrity" row to say "Browser-native SRI in clean context" instead of "Pure-JS SHA-256."
- **Section 14 (Future Work):** Remove "Automated security testing" if addressed. Add "Visual verification mechanism" as future work (explore rendering verification UI within the clean iframe).

### Step 12: Rewrite `README.md`

- Update "How It Works" section: step 3 should say "SRI (Subresource Integrity) verification" instead of "pure-JS SHA-256"
- Remove references to visual identity token throughout
- Update "Key Properties" if any mention the pure-JS SHA-256
- Update "Project Structure" tree: remove `pure-sha256.js`
- Update "Programmatic Bookmarklet Generation" example: remove `visualToken` parameter, use `bootstrapHashBase64` instead of `bootstrapHash`
- Update "Browser Compatibility" section: add note about SRI support requirement

### Step 13: Replace `TODO.md`

Replace contents with a brief note:
- Previous issues (C-1, C-2, M-1) have been addressed by the SRI rewrite
- Recommend a fresh security audit of the new architecture
- Note remaining known items: S-1 (clean context circularity — documented limitation), test suite needed, regex minification should be revisited

### Step 14: Commit and push

Commit all changes to `claude/security-audit-review-YI7xI` with a descriptive message summarizing the rewrite.

---

## Files Summary

| File | Action | Description |
|------|--------|-------------|
| `src/plugin/runtime/bookmarklet.js` | Rewrite | SRI-based bootstrap loading, remove pure-SHA-256 |
| `src/plugin/runtime/pure-sha256.js` | Delete | No longer needed |
| `src/plugin/runtime/bootstrap.js` | Edit | Embed public key, fix canonicalization, remove visual token, fix locked mode, fix Ed25519 import |
| `src/plugin/manifest.ts` | Edit | Remove `publicKey` from manifest/canonicalization, remove `urls` from canonicalization |
| `src/plugin/bookmarklet.ts` | Edit | Remove visual token, pure-SHA-256 inlining; add base64 hash, manifestHash |
| `src/plugin/builder.ts` | Edit | Inject public key into bootstrap, base64 hash, remove publicKey from generateManifest call |
| `src/plugin/index.ts` | Edit | Update exports if needed |
| `src/installer/index.html` | Edit | Remove mimic zone, visual token field, simplify |
| `src/installer/generator.ts` | Edit | Remove mimic init, visual token, pure-SHA-256 inlining |
| `SECURITY-AUDIT.md` | Delete | Findings addressed |
| `DESIGN.md` | Rewrite | Update for SRI architecture |
| `README.md` | Edit | Update for SRI architecture |
| `TODO.md` | Replace | Note resolved issues, recommend fresh audit |

## Audit Issues Resolution Status

| ID | Severity | Resolution |
|----|----------|------------|
| C-1 | Critical | **Fixed** — public key embedded in bootstrap at build time |
| C-2 | Critical | **Fixed** — canonical forms unified (both exclude `publicKey` and `urls`) |
| S-1 | Significant | **Documented** — fundamental limitation of bookmarklet paradigm, no code fix |
| S-2 | Significant | **Resolved** — visual token system removed entirely |
| S-3 | Significant | **Deferred** — test suite still needed (note in TODO.md) |
| S-4 | Significant | **Partially resolved** — pure-sha256.js deleted (was main risk); regex minifier still used for bookmarklet but is less critical now since bookmarklet contains no crypto code |
| M-1 | Moderate | **Fixed** — locked mode uses manifestHash from bookmarklet config |
| M-2 | Moderate | **Resolved** — pure-sha256.js deleted |
| M-3 | Moderate | **Resolved** — bookmarklet no longer uses fetch+promise for bootstrap loading |
| M-4 | Moderate | **Documented** — inherent to shared-origin IndexedDB, mitigated by HMAC |
| M-5 | Moderate | **Fixed** — Ed25519 import uses SPKI directly, no error swallowing |
