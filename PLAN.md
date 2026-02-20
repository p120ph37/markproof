# Implementation Plan: Data-URL Bookmarklet Rewrite

## The Core Problem

After exhaustive research, there is currently **no way to guarantee access to a clean JavaScript context** when launching a bookmarklet in a potentially-compromised page. The existing architecture relies on creating a "verified clean iframe" via non-configurable property chains — but no complete chain from `window.document` through `createElement` to `iframe.contentWindow` is guaranteed non-configurable across browsers. An attacker who controls the page can intercept any configurable link and return a fake "clean context" that passes all validation checks.

This breaks the entire trust model. The pure-JS SHA-256, the Ed25519 signature chain, the visual token, the HMAC cache — all of these assume they execute in a clean context. If the context itself is attacker-controlled, none of it matters.

The other audit findings (C-1, C-2, S-2, M-1, etc.) are secondary — they are real bugs, but they exist within an architecture whose foundational assumption (clean iframe context) is broken. Fixing them individually would be pointless.

## The Pivot: Data-URL Bookmarklet

The solution is to use a `data:text/html,...` URL as the bookmarklet target. When the browser navigates to a `data:` URL, it creates a **brand-new browsing context** with a unique opaque origin — completely isolated from the compromised page. No property chain validation needed. No iframe tricks. The browser engine itself guarantees the context is clean.

Within this guaranteed-clean data-URL page, the bootstrap is loaded via a `<script>` tag with a native SRI (Subresource Integrity) `integrity` attribute. The browser's own SRI implementation verifies the hash before executing the script. No custom SHA-256 needed.

### What This Eliminates

| Removed Component | Why |
|---|---|
| `pure-sha256.js` (~230 lines) | Browser-native SRI does hash verification |
| Property chain validation | `data:` URL provides guaranteed clean context |
| Clean iframe creation | `data:` URL provides guaranteed clean context |
| Visual token system | Was displayed in compromised parent window (S-2); no clean context to display it in since we're now on an opaque origin |
| IndexedDB cache + HMAC | `data:` URL has an opaque origin — no access to any origin-scoped storage (IndexedDB, localStorage, cookies). Cache/offline capability is gone. |
| Anti-training mimic page | Was tied to the origin page concept; no longer relevant |

### What Remains

| Component | Role |
|---|---|
| Bookmarklet (data-URL) | Navigates to a clean context, loads bootstrap via SRI |
| Bootstrap script | Fetches manifest, verifies Ed25519 signature, fetches + hash-verifies resources, renders app |
| Signed manifest | Lists resources with hashes, signed by developer's Ed25519 key |
| Build pipeline | Bundles app, generates manifest, signs it, produces bookmarklet |

### New Trust Chain

```
1. Bookmarklet (data: URL)
   - Embedded: bootstrap URL, SRI hash (sha256-BASE64)
   - Browser navigates to data:text/html page (guaranteed clean context)
   - <script src="BOOTSTRAP_URL" integrity="sha256-..." crossorigin="anonymous">
   - Browser-native SRI verifies bootstrap hash before execution

2. Bootstrap (SRI-verified, runs in clean data-URL context)
   - Embedded at build time: Ed25519 public key
   - Fetches manifest.json from network
   - Verifies Ed25519 signature using embedded public key
   - Fetches each resource listed in manifest
   - Verifies SHA-256 hash of each resource against manifest

3. Manifest (Ed25519-signed)
   - Lists all app resources with SHA-256 hashes and sizes
   - Signature covers canonical JSON (version, timestamp, resources)

4. Resources (hash-verified)
   - Individual JS/CSS/HTML files
   - Each verified against manifest hash before use
   - Can be served from any CORS-enabled host
```

### Implications of Opaque Origin

The data-URL page has an opaque origin. This means:
- **No IndexedDB** — every load requires a network fetch
- **No localStorage** — no client-side state persists between sessions
- **No cookies** — no session management
- **CORS everywhere** — all fetches from the data-URL context are cross-origin; the bootstrap URL and all resource URLs must serve CORS headers (`Access-Control-Allow-Origin: *`). GitHub Pages does this by default.
- **Standard HTTP caching still works** — the browser's HTTP cache (via `Cache-Control`, `ETag`, etc.) can avoid redundant network transfers. This is orthogonal to our project.

The selling point is now purely the **guaranteed trust anchor** — the bookmarklet ensures that whatever code runs has been signed by the developer, even if every server in the delivery chain is compromised.

---

## Step-by-Step Implementation

### Step 1: Rewrite `src/plugin/runtime/bookmarklet.js`

This file is completely rewritten. The new bookmarklet is a small JS snippet that navigates to a `data:text/html` document.

**Current file:** 314 lines — origin check, pure-SHA-256 placeholder, property chain validation, clean iframe creation, fetch + hash-verify bootstrap, eval in clean context.

**New file:** ~30 lines — constructs a data-URL HTML page with an SRI-protected script tag, then navigates to it.

```javascript
// Bookmarklet source template.
// Navigates to a data:text/html page that loads the bootstrap via SRI.
// The data-URL page has a fresh browsing context with an opaque origin,
// guaranteeing complete isolation from any compromised page JavaScript.
//
// Placeholders (replaced at install time):
//   __ORIGIN_URL__             - The origin URL (informational, passed to bootstrap)
//   __BOOTSTRAP_URL__          - Absolute URL to fetch bootstrap.js
//   __BOOTSTRAP_HASH_BASE64__  - Base64-encoded SHA-256 hash of bootstrap.js (for SRI)
//   __UPDATE_MODE__            - 'locked' or 'auto'
//   __MANIFEST_HASH__          - SHA-256 hex hash of canonical manifest (locked mode; '' for auto)

void(function() {
  var ORIGIN_URL = '__ORIGIN_URL__';
  var BOOTSTRAP_URL = '__BOOTSTRAP_URL__';
  var BOOTSTRAP_HASH_BASE64 = '__BOOTSTRAP_HASH_BASE64__';
  var UPDATE_MODE = '__UPDATE_MODE__';
  var MANIFEST_HASH = '__MANIFEST_HASH__';

  // Build a minimal HTML page that loads the bootstrap via SRI.
  // The config is passed as a global variable in an inline script.
  var html = '<!DOCTYPE html>'
    + '<html><head><meta charset="utf-8"><title>Loading...</title></head><body>'
    + '<script>'
    + 'window.__markproofConfig='
    + '{"originUrl":"' + ORIGIN_URL + '"'
    + ',"bootstrapUrl":"' + BOOTSTRAP_URL + '"'
    + ',"updateMode":"' + UPDATE_MODE + '"'
    + ',"manifestHash":"' + MANIFEST_HASH + '"'
    + '};'
    + '<\/script>'
    + '<script src="' + BOOTSTRAP_URL + '"'
    + ' integrity="sha256-' + BOOTSTRAP_HASH_BASE64 + '"'
    + ' crossorigin="anonymous"'
    + ' onerror="document.body.innerHTML='
    + "'<h1>Bootstrap integrity check failed.<\\/h1>"
    + "<p>The bootstrap script has been tampered with or the server is unreachable.<\\/p>'"
    + '><\/script>'
    + '</body></html>';

  location.href = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
})();
```

**Notes:**
- The config JSON is constructed via string concatenation (not `JSON.stringify`) because the bookmarklet runs in the compromised page context where `JSON.stringify` could be poisoned. However, since the values are all simple strings injected at build time (no user-controlled content), this is safe. The data-URL context that receives the config is clean.
- `encodeURIComponent` could theoretically be poisoned, but a poisoned `encodeURIComponent` can only produce a malformed data URL (the browser won't navigate to it) or a valid one with different content (which would fail the SRI check on the bootstrap script). Neither outcome allows code execution of attacker-controlled content.

### Step 2: Delete `src/plugin/runtime/pure-sha256.js`

No longer needed. Browser-native SRI handles bootstrap integrity verification.

### Step 3: Rewrite `src/plugin/runtime/bootstrap.js`

Major simplification. Remove all IndexedDB/cache/HMAC code. Remove visual token. Fix C-1 (embed public key), C-2 (canonicalization already correct on runtime side — fix manifest.ts to match), M-1 (locked mode), M-5 (Ed25519 import).

**Remove entirely:**
- `VISUAL_TOKEN` variable and usage
- `HMAC_KEY` variable and all HMAC functions (`importHmacKey`, `hmacSign`, `hmacVerify`)
- All IndexedDB code (`openDB`, `dbGet`, `dbPut`, `dbPutAll`, `dbClear`, and all DB constants)
- `loadFromCache()` function
- `checkForUpdates()` function
- `notifyUpdate()` function
- `showVisualIdentity()` function
- `computeManifestHash()` function (unless needed for locked mode — keep if so)
- `parentWindow` concept — bootstrap now renders into its own document

**Keep (with modifications):**
- Config reading — rename from `__bookmarkletConfig` to `__markproofConfig`
- `hexToBytes()`, `bytesToHex()`, `stringToBuffer()` — utility functions
- `sha256()` — for resource hash verification (using clean context's `crypto.subtle`)
- `importEd25519PublicKey()` — rewrite: SPKI only, no error swallowing (fixes M-5)
- `verifySignature()` — unchanged
- `fetchManifest()` — unchanged
- `fetchResource()` — unchanged
- `canonicalizeManifest()` — unchanged (runtime version is already correct)
- `verifyManifest()` — unchanged
- `verifyResource()` — unchanged
- `showStatus()`, `hideStatus()`, `showError()` — render into current `document` (not parentWindow)
- `injectApp()` — render into current `document` (not parentWindow)

**Add:**
- `var EMBEDDED_PUBLIC_KEY = '__PUBLIC_KEY__';` — build-time constant (fixes C-1)
- Locked mode: if `config.manifestHash` is non-empty, verify canonical manifest hash matches after signature verification (fixes M-1)

**New `main()` flow (no cache):**
```
1. Read config from window.__markproofConfig
2. Show "Loading..." status
3. Derive content base URL from bootstrap URL
4. Fetch manifest.json
5. If EMBEDDED_PUBLIC_KEY set: verify Ed25519 signature (fixes C-1)
6. If locked mode + manifestHash: verify manifest hash (fixes M-1)
7. Fetch all resources listed in manifest
8. Verify SHA-256 hash of each resource against manifest
9. Inject verified app into current document
```

**`importEd25519PublicKey()` rewrite (fixes M-5):**
```javascript
function importEd25519PublicKey(base64Key) {
  var raw = atob(base64Key);
  var bytes = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return crypto.subtle.importKey(
    'spki', bytes, { name: 'Ed25519' }, false, ['verify']
  );
}
```

**`injectApp()` changes:**
Replace all `parentWindow.document` references with just `document`. The bootstrap is running in the data-URL page — it renders the app directly into its own document.

**`showStatus()` / `showError()` changes:**
Same — use `document` instead of `parentWindow.document`.

### Step 4: Update `src/plugin/bookmarklet.ts`

**New interface:**
```typescript
export interface BookmarkletOptions {
  originUrl: string;
  bootstrapUrl: string;
  bootstrapHashBase64: string;  // base64-encoded SHA-256 for SRI
  updateMode?: 'locked' | 'auto';
  manifestHash?: string;  // hex SHA-256 of canonical manifest (locked mode)
}
```
Removed: `visualToken`, `hmacKey`, `bootstrapHash`

**`generateBookmarklet()` — updated:**
- Remove `pureSha256Source` reading (file deleted)
- Remove `// __PURE_SHA256_SOURCE__` replacement
- Remove `__VISUAL_TOKEN__` and `__HMAC_KEY__` replacements
- Replace `__BOOTSTRAP_HASH__` placeholder with `__BOOTSTRAP_HASH_BASE64__`
- Add `__MANIFEST_HASH__` replacement (empty string if not locked mode)
- Return `{ url: string }` — no more `hmacKey` in return

**`getTemplateSources()` — updated:**
- Return `{ bookmarkletTemplate: string }` — no more `pureSha256Source`

### Step 5: Update `src/plugin/manifest.ts`

**`Manifest` interface — remove `publicKey`:**
```typescript
export interface Manifest {
  version: string;
  timestamp: string;
  resources: Record<string, ManifestResource>;
  signature?: string;
}
```

**`canonicalizeManifest()` — remove `publicKey` and `urls`:**
```typescript
export function canonicalizeManifest(manifest: Manifest): string {
  const resources: Record<string, { hash: string; size: number }> = {};
  const keys = Object.keys(manifest.resources).sort();
  for (const key of keys) {
    const r = manifest.resources[key];
    resources[key] = { hash: r.hash, size: r.size };
  }
  return JSON.stringify({
    version: manifest.version,
    timestamp: manifest.timestamp,
    resources,
  });
}
```
This now matches the runtime `canonicalizeManifest()` exactly (fixing C-2).

**`generateManifest()` — remove `publicKeyBase64` parameter:**
```typescript
export function generateManifest(
  files: Map<string, Buffer | string>,
  version: string,
): Manifest { ... }
```

### Step 6: Update `src/plugin/builder.ts`

**Public key injection into bootstrap.js:**
```typescript
let bootstrapOutput = bootstrapSource;
if (publicKeyBase64) {
  bootstrapOutput = bootstrapOutput.replace(
    "'__PUBLIC_KEY__'",
    JSON.stringify(publicKeyBase64)
  );
}
fs.writeFileSync(bootstrapOutPath, bootstrapOutput);
```
Hash the output (with key embedded):
```typescript
const bootstrapHashBase64 = createHash('sha256').update(bootstrapOutput).digest('base64');
```

**Manifest generation — updated call:**
```typescript
let manifest = generateManifest(appFiles, version);
```

**Installer build defines — updated:**
- Remove: `__PURE_SHA256_SOURCE__`
- Rename: `__BOOTSTRAP_HASH__` → `__BOOTSTRAP_HASH_BASE64__` (base64 value)
- Add: `__MANIFEST_HASH__` — `sha256hex(canonicalizeManifest(manifest))`

**BuildResult — updated:**
```typescript
export interface BuildResult {
  manifest: Manifest;
  bootstrapHashBase64: string;
  outputFiles: string[];
}
```

### Step 7: Simplify `src/installer/index.html`

**Remove:**
- Warning banner
- Mimic zone (canvas, overlay, label)
- All glitch/melt CSS
- Visual token form field + hint
- HMAC key backup display

**Keep:**
- Page structure, dark theme
- Installer card with: update mode select, generate button
- Result section with: bookmarklet drag link
- Simplified instructions (drag to bookmark bar, click to launch)
- Footer

### Step 8: Update `src/installer/generator.ts`

**Remove:**
- `__PURE_SHA256_SOURCE__` declaration
- `initMimic()` function
- `generateHmacKey()` function
- `visualToken` from `assembleBookmarklet()`
- All visual token / HMAC key UI handling

**Update:**
- `assembleBookmarklet()`: only takes `{ updateMode }`, removes SHA-256 inlining, uses `__BOOTSTRAP_HASH_BASE64__` and `__MANIFEST_HASH__` placeholders
- `initGenerator()`: just update mode + generate button
- `minifySource()`: keep as-is

### Step 9: Update `src/plugin/index.ts`

Update exports to match changed interfaces. Key changes:
- `BookmarkletOptions` loses `visualToken`, `hmacKey`, `bootstrapHash`; gains `bootstrapHashBase64`, `manifestHash`
- `Manifest` loses `publicKey`
- `generateBookmarklet` returns `{ url: string }`

### Step 10: Check/update `build.ts` (root)

Read and update if it references any changed APIs.

### Step 11: Delete `SECURITY-AUDIT.md`

The findings are addressed by this rewrite. The new architecture deserves a fresh audit.

### Step 12: Rewrite `DESIGN.md`

Major changes:
- **Problem Statement:** Remove "offline capability" from value proposition. Core value: guaranteed trust anchor despite server compromise.
- **Architecture:** Replace iframe-based clean context with data-URL approach. Remove pure-JS SHA-256 from diagram. Remove visual token. Remove cache layer.
- **Engine-Guaranteed Primitives:** Largely remove. Data-URL approach doesn't need them for hashing. Brief note that the bookmarklet uses only basic JS operations.
- **Clean Context:** Completely rewrite. Explain data-URL navigation as the guaranteed clean context mechanism. No property chain validation needed.
- **Update Modes:** Simplify. No cache, every load fetches. Locked mode pins manifest hash.
- **Per-Installation Secrets:** Remove entirely (no visual token, no HMAC key).
- **Cache Integrity:** Remove entirely (no cache).
- **Untrusted Origin Page:** Simplify. No mimic page.
- **CDN-Friendly Delivery:** Keep — still works.
- **Security Analysis:** Update for new architecture.
- **Comparison table:** Remove "Offline?" column advantage.
- **Future Work:** Explore offline recovery options, iOS data-URL compatibility, visual verification within data-URL page.

### Step 13: Rewrite `README.md`

- Remove all "works offline" claims
- Update "How It Works" for data-URL + SRI + Ed25519 chain
- Remove visual token references
- Remove `pure-sha256.js` from project structure
- Update API examples for new `BookmarkletOptions`
- Add CORS requirement note
- Update browser compatibility (SRI support, data-URL support)

### Step 14: Replace `TODO.md`

Brief content noting:
- Core clean-context problem resolved by data-URL pivot
- C-1, C-2, M-1, S-2, M-5 all resolved
- Remaining: test suite needed, iOS data-URL testing, regex minifier review

### Step 15: Commit and push

Single commit to `claude/security-audit-review-YI7xI` with all changes.

---

## Files Summary

| File | Action | Key Changes |
|------|--------|-------------|
| `src/plugin/runtime/bookmarklet.js` | **Rewrite** | data-URL navigation + SRI script tag (~30 lines replaces ~314) |
| `src/plugin/runtime/pure-sha256.js` | **Delete** | Browser-native SRI replaces it |
| `src/plugin/runtime/bootstrap.js` | **Major rewrite** | Remove all cache/IndexedDB/HMAC/visual-token/parentWindow code; embed public key; render into own document |
| `src/plugin/bookmarklet.ts` | **Edit** | Remove visual token, HMAC, pure-SHA-256; base64 hash; manifestHash |
| `src/plugin/manifest.ts` | **Edit** | Remove publicKey from interface + canonicalization; remove urls from canonicalization |
| `src/plugin/builder.ts` | **Edit** | Inject public key into bootstrap; base64 hash; updated manifest generation |
| `src/plugin/index.ts` | **Edit** | Update exports for changed interfaces |
| `src/installer/index.html` | **Simplify** | Remove mimic zone, visual token, HMAC display |
| `src/installer/generator.ts` | **Simplify** | Remove mimic, visual token, HMAC, pure-SHA-256 |
| `build.ts` | **Check/edit** | Update for new API if needed |
| `SECURITY-AUDIT.md` | **Delete** | Addressed by rewrite |
| `DESIGN.md` | **Rewrite** | Data-URL architecture; remove offline/cache/visual-token/engine-primitives sections |
| `README.md` | **Rewrite** | Remove offline claims; update for data-URL architecture |
| `TODO.md` | **Replace** | Note resolved issues, remaining work |

## Key Design Decisions for the Implementing Agent

1. **No `parentWindow` concept.** The bootstrap runs in its own top-level data-URL page. It renders the app directly into its own `document`. There is no iframe, no parent window reference.

2. **CORS everywhere.** The data-URL page has an opaque origin. Every fetch is cross-origin. The bootstrap URL and all resource URLs must serve CORS headers (`Access-Control-Allow-Origin: *`). GitHub Pages does this by default.

3. **No offline.** This is intentional. The opaque origin has no storage access. Standard HTTP caching (browser-managed) is the only optimization, and it's transparent to this project.

4. **SRI hash is base64, not hex.** The SRI `integrity` attribute requires the format `sha256-BASE64HASH`. The build pipeline must produce base64-encoded SHA-256 hashes.

5. **Public key goes in `bootstrap.js`, not the manifest.** The manifest must not self-authenticate. The public key is injected into `bootstrap.js` at build time via placeholder replacement, before the SRI hash is computed.

6. **HMAC key is removed.** Without IndexedDB there is nothing to HMAC. Don't carry dead configuration.

7. **Config variable renamed.** `window.__bookmarkletConfig` → `window.__markproofConfig` to reflect the project name.
