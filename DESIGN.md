# Design Document: anchor.js

## Trust-Anchored Web Application Loader

### Revision History

| Date | Description |
|------|-------------|
| 2026-02-20 | Initial design document |

---

## 1. Problem Statement

Standard web applications place their root of trust in a URL. The browser fetches code from a server, and the user trusts that server to deliver the correct code. This model breaks catastrophically when:

- The domain expires and is re-registered by a new party
- The server is compromised by an attacker
- A government seizes the domain or coerces the hosting provider
- A CDN or DNS provider is compromised
- A certificate authority issues a fraudulent TLS certificate

In all of these cases, the attacker can serve arbitrary JavaScript to every user who visits the URL. Service workers do not help — the browser's SW update lifecycle will eventually install the attacker's replacement, and once all tabs close, the new SW takes full control.

**anchor.js solves this by moving the root of trust from the server to a client-side artifact: a JavaScript bookmarklet.**

### Threat Model

| Actor | Capabilities |
|-------|-------------|
| State-level adversary | Valid TLS certs, DNS hijacking, domain seizure, server compromise, legal compulsion of hosting/CA providers |
| Network attacker | MITM (defeated by TLS, but see above), DNS poisoning |
| Compromised origin | Arbitrary JS execution in the page context before the bookmarklet runs |

**Trusted components:**
- The browser engine (standards-compliant, uncompromised)
- The bookmarklet content (installed from an uncompromised source, immutable after creation)
- Per-installation secrets embedded in the bookmarklet (visual token, HMAC key)

**Explicitly untrusted:**
- The origin URL (the page served at the URL the bookmarklet navigates to)
- All network-fetched content (until cryptographically verified)
- All browser APIs accessible from the page context (until accessed through a verified clean context)

### What anchor.js Is Not

anchor.js does not guarantee perpetual offline availability. Browser storage (IndexedDB) can be evicted by the browser under storage pressure or after extended periods of disuse (particularly on iOS, which may evict after ~2 weeks of inactivity). What anchor.js **does** guarantee is that whenever the application loads — whether from cache or from the network — the code that executes has been verified against the cryptographic keys embedded in the user's bookmarklet. An attacker who gains control of every server involved cannot cause the user to run unverified code.

---

## 2. Architecture Overview

### 2.1 The Three Components

```
┌────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Bookmarklet (javascript: URL)        │   │
│  │  ┌──────────┐ ┌────────────┐ ┌──────────────┐   │   │
│  │  │ Bootstrap │ │ Visual     │ │ HMAC Key     │   │   │
│  │  │ Hash     │ │ Token      │ │ (256-bit)    │   │   │
│  │  │ (SHA-256)│ │ (human     │ │              │   │   │
│  │  │          │ │  verify)   │ │              │   │   │
│  │  └──────────┘ └────────────┘ └──────────────┘   │   │
│  │  ┌──────────────────────────────────────────┐   │   │
│  │  │ Pure-JS SHA-256 (engine-guaranteed only)  │   │   │
│  │  └──────────────────────────────────────────┘   │   │
│  │  ┌──────────────────────────────────────────┐   │   │
│  │  │ Chain validator + clean context creator   │   │   │
│  │  └──────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │        Bootstrap (hash-verified, clean context)   │   │
│  │  Ed25519 verification · IndexedDB cache          │   │
│  │  HMAC integrity · Manifest parsing               │   │
│  │  Resource fetch + hash verification              │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │         Application (signature-verified)          │   │
│  │  HTML · CSS · JS — all hash-checked against      │   │
│  │  the signed manifest before execution             │   │
│  └─────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│                   UNTRUSTED ZONE                        │
│  Origin URL · Network · Servers · CDNs · DNS           │
│  (can deliver content, but cannot bypass verification)  │
└────────────────────────────────────────────────────────┘
```

### 2.2 Chain of Trust

The security of the system rests on a three-link chain:

1. **Bookmarklet → Bootstrap**: The bookmarklet fetches the bootstrap script from the network (using potentially-poisoned `fetch` — this is acceptable), then **hash-verifies** the content using a pure-JS SHA-256 implementation built entirely from engine-guaranteed primitives. The expected hash is embedded in the bookmarklet. An attacker cannot make different content produce the same SHA-256 hash.

2. **Bootstrap → Manifest**: The bootstrap script runs in a verified clean execution context and uses the browser's native `crypto.subtle` to verify the Ed25519 signature on the application manifest. The signing public key is embedded in the bootstrap (which was hash-verified in step 1).

3. **Manifest → Resources**: Each application resource (JS, CSS, HTML) is listed in the manifest with its SHA-256 hash. After fetching each resource (from any URL — including CDN mirrors), the bootstrap verifies the hash matches. Resources can be served from completely untrusted third-party hosts.

### 2.3 Why a Bookmarklet?

| Alternative | Why It Fails |
|------------|-------------|
| Service Worker | Browser controls update lifecycle; server controls SW content |
| localStorage/sessionStorage | Accessible (and writable) by any JS running on the origin |
| Browser extension | Requires extension store trust; store could be compelled to remove |
| Native app wrapper | Requires app store approval; policy restrictions on dynamic code |
| TLS certificate pinning | Defeated by compromised CAs or legal compulsion |
| Subresource Integrity (SRI) | Only works for `<script>` tags in HTML; HTML itself is unverified |

A `javascript:` bookmarklet is:
- **Client-side**: Stored in the browser, not fetched from a server
- **Immutable**: Cannot be modified after creation (no API to read or write bookmark content from page JS)
- **Server-independent**: No server can alter it
- **Portable**: Just a text string — can be backed up in a password manager, printed, etc.

---

## 3. Engine-Guaranteed Primitives

The bookmarklet must operate correctly even when **every JavaScript API** in the page context has been monkey-patched by an attacker. This is achievable because certain JavaScript operations are guaranteed by the engine specification and cannot be intercepted by any JS code:

### 3.1 What Cannot Be Intercepted

| Primitive | Guarantee |
|-----------|----------|
| Literal creation | `{}`, `[]`, `""`, `42`, `true`, `null` always create real values |
| `{__proto__: null}` | Engine-level syntax; creates prototype-free objects |
| Arithmetic/bitwise operators | `+`, `-`, `*`, `>>>`, `&`, `\|`, `^`, `~` on numbers |
| Comparison operators | `===`, `!==`, `<`, `>`, `typeof` |
| String indexing | `str[i]` uses the engine-internal `[[Get]]` on String exotic objects |
| String `.length` | Non-configurable own property of string primitives |
| `function` declarations | Always create real Function objects from syntax |
| Control flow | `if`, `for`, `while`, `try/catch`, `throw`, `return` |
| `delete` operator | Engine-level; returns `false` for non-configurable properties |
| Variable declaration | `let`, `const`, `var` cannot be intercepted |

### 3.2 Pure-JS SHA-256

The `pure-sha256.js` implementation uses exclusively the primitives listed above. Key design decisions:

**No `charCodeAt`**: `String.prototype.charCodeAt` is a method on a mutable prototype — it could be replaced to return wrong byte values, causing the hash to accept tampered content. Instead, we build an ASCII lookup table from a string literal:

```javascript
var _ct = {__proto__: null};
var _cs = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDE...{|}~';
for (var _ci = 0; _ci < _cs.length; _ci = _ci + 1) {
  _ct[_cs[_ci]] = _ci + 32;
}
```

String indexing (`_cs[_ci]`) is engine-guaranteed. The lookup table maps each ASCII character to its byte value without calling any methods.

**No Arrays**: Arrays have a mutable prototype (`Array.prototype`). All collections use `{__proto__: null}` objects with integer keys.

**No `Math`**: `Math.min`, `Math.max`, etc. could be poisoned. All arithmetic uses raw operators.

### 3.3 What This Means

The pure-JS SHA-256 produces the correct hash regardless of what code has run before the bookmarklet. An attacker who has poisoned every API in the page context — `fetch`, `crypto`, `Object`, `Array`, `String.prototype`, `Function.prototype`, `Math`, everything — still cannot cause the bookmarklet to accept content with the wrong hash.

---

## 4. Clean Context Verification

### 4.1 The Problem

After hash-verifying the bootstrap, the bookmarklet needs to **execute** it in a context where browser APIs (crypto.subtle, IndexedDB, fetch, DOM) are trustworthy. A fresh `about:blank` iframe provides such a context — it has its own separate set of built-in objects that page JS cannot reach. But creating and accessing the iframe requires calling browser APIs that may have been poisoned:

```
window.document  →  document.createElement('iframe')  →  iframe.contentWindow
```

If any link in this chain has been replaced by attacker code, the "clean context" might be a fake that the attacker fully controls.

### 4.2 Non-Configurable Property Chains

The solution exploits a guarantee from the JavaScript and Web IDL specifications:

> A non-configurable accessor property's getter function **cannot be replaced** by any JavaScript code, including `Object.defineProperty`.

The `delete` operator is engine-guaranteed and provides two key capabilities:
1. **Shadow removal**: If the attacker used property assignment to create an own property that shadows a prototype getter, `delete` removes the shadow, revealing the original
2. **Configurability test**: `delete obj.prop` returns `false` for non-configurable own properties

If the chain from global scope to `iframe.contentWindow` consists entirely of non-configurable accessor properties, we can provably access a genuine clean context.

### 4.3 Empirical Results

Browser testing (Edge, Safari, Firefox — macOS, February 2026) using `test-property-chains.html` found:

| Property | Non-configurable? | Type |
|----------|------------------|------|
| `Window.prototype.document` / `window.document` | **Yes** | Accessor (getter) |
| `Document.prototype.createElement` | Varies | May be configurable |
| `HTMLIFrameElement.prototype.contentWindow` | Varies | May be configurable |

**Only the `window.document` link (Chain 1b) was confirmed non-configurable across all tested browsers.** The remaining links in the chain may be configurable on some browsers.

### 4.4 Layered Defense

Given that not all chain links are provably non-configurable, anchor.js uses a layered approach:

1. **`delete` shadow removal**: Remove any attacker-created shadows on every property in the chain
2. **Non-configurability verification**: Use the clean context's own `Object.getOwnPropertyDescriptor` (which is trustworthy if the context is genuine) to verify the parent context's properties
3. **Separate-realm check**: Verify `cleanWin.Object !== window.Object` to confirm the iframe has its own execution context
4. **Cryptographic verification**: Even if the context creation is subverted, the pure-JS SHA-256 hash of the bootstrap is verified using engine-guaranteed primitives. Content substitution is always detected.
5. **Runtime abort**: If chain validation fails, the bookmarklet aborts rather than proceeding in an unverified context

The hash verification (layer 4) is the cryptographic guarantee. The chain validation (layers 1-3) determines whether the verified code runs in a genuinely isolated context. Together they provide defense-in-depth: an attacker must both subvert the chain validation AND find a SHA-256 collision.

### 4.5 What Remains Undefendable

If an attacker can replace a configurable link in the chain AND the bookmarklet cannot detect this, then the attacker controls the execution context. In this scenario, the attacker could return a fake "clean context" that appears to pass all checks but actually executes attacker-controlled code instead of the hash-verified bootstrap.

This is a known limitation documented in the threat model. Mitigations:
- The bookmarklet includes runtime validation that **aborts if the chain appears broken** on the current browser
- As browsers adopt stricter Web IDL bindings, more links may become non-configurable
- The test page (`test-property-chains.html`) allows verification on new browsers/versions

---

## 5. Update Modes

anchor.js supports two update behaviors, chosen at install time:

### 5.1 Mode A: Locked (Version-Pinned)

The bookmarklet embeds the hash of a specific bootstrap script, which in turn embeds the hash of a specific manifest. The application is pinned to an exact version.

- **Author-signed updates are rejected** — even valid signatures are refused if the manifest hash differs
- **Update path**: Requires generating a new bookmarklet with the new bootstrap hash. The user must explicitly re-install.
- **Use case**: Maximum security. The application is frozen at a known-good version. Appropriate for high-security contexts where code changes require manual review.

### 5.2 Mode B: Auto-Update (Author-Signed)

The bootstrap accepts any manifest with a valid Ed25519 signature from the embedded public key.

- **Author-signed updates are accepted automatically**
- **Cache tamper detection** uses a per-installation HMAC key (see Section 6)
- **Update discovery**: On each launch, the bootstrap checks the network for a newer signed manifest. If available, it notifies the user and offers to install.
- **Offline operation**: If the network is unavailable, the cached version is used
- **Use case**: Convenience with trust. The user trusts the author's signing key and accepts signed updates, while being protected against cache tampering and server compromise by non-key-holders.

### 5.3 Manifest Structure

```json
{
  "version": "1.2.0",
  "timestamp": "2026-02-20T12:00:00Z",
  "publicKey": "MCowBQYDK2VwAyEA...",
  "resources": {
    "/app.html": {
      "hash": "sha256-39df1931...",
      "size": 394,
      "urls": [
        "https://example.github.io/myapp/app.html",
        "https://unpkg.com/myapp@1.2.0/app.html"
      ]
    },
    "/app.js": {
      "hash": "sha256-fe860513...",
      "size": 12345
    },
    "/style.css": {
      "hash": "sha256-668a7eb2...",
      "size": 400
    }
  },
  "signature": "96a30b73bde5a2da..."
}
```

**Only the manifest is signed.** All other resources are verified by their hashes listed in the manifest. This means resources can be hosted on any CORS-enabled server (GitHub Pages, unpkg, jsDelivr, a corporate CDN) without those servers needing to be trusted. The signature verification applies solely to the manifest, and the manifest's integrity transitively secures every resource.

---

## 6. Per-Installation Secrets

Each bookmarklet installation contains two independent secrets:

### 6.1 Visual Identity Token

- **Purpose**: Human verification that the correct bookmarklet loaded and the verified app is running
- **Nature**: User-chosen or generated (e.g., "blue-dragon-42", a color pattern, an emoji sequence)
- **Display**: Shown briefly in the top-right corner after the verified app loads
- **Security role**: None. This is purely for human confidence. It is displayed in the verified clean context, so an attacker who controls the page cannot observe it (unless the chain validation was defeated).

### 6.2 HMAC Key

- **Purpose**: Cache integrity verification (Mode B only)
- **Nature**: 256-bit random, generated at install time via `crypto.getRandomValues()`
- **Security role**: Detects tampering with IndexedDB cache contents

### 6.3 Why Two Separate Secrets

Early designs considered using the visual token as the HMAC key. This was rejected because:

> If the visual token is used as the HMAC key, an attacker who can read IndexedDB on the compromised origin can observe the HMAC value and brute-force the visual token — especially if it's a short phrase or based on predictable choices (common words, Gravatars, social media photos).

With separate secrets:
- The **HMAC key** has 256 bits of entropy — computationally infeasible to brute-force
- The **visual token** has no cryptographic role — even if an attacker somehow learns it, they cannot use it to forge cache entries or bypass any verification

---

## 7. Cache Integrity (Mode B)

### 7.1 HMAC Scheme

On each successful cache write, the bootstrap computes:
```
HMAC-SHA256(hmacKey, SHA256(canonicalManifest))
```
and stores the result alongside the cached manifest in IndexedDB.

On each launch, before loading from cache:
1. Read the cached manifest and stored HMAC from IndexedDB
2. Recompute `SHA256(canonicalManifest)` from the cached manifest
3. Verify the stored HMAC against the recomputed hash using the per-installation HMAC key

### 7.2 Cache State Table

| Stored HMAC | HMAC Valid? | Hash Matches Cache? | Interpretation | Action |
|-------------|-------------|---------------------|----------------|--------|
| Present | Yes | Yes | Cache consistent | Load from cache |
| Present | Yes | No | Inconsistent cache | Warn user, attempt network re-fetch |
| Present | No | — | Cache tampered | **Security warning**, refuse to load |
| Missing | — | — | Cache purged or first run | Fetch from network |

**Key distinction**: "HMAC valid but hash differs" indicates an inconsistent cache state (interrupted update, concurrent window, browser storage issue) — not necessarily an attack. Update discovery is a separate network check, not inferred from cache state.

"HMAC invalid" indicates that something other than this bookmarklet modified the cache. Since the HMAC key is embedded only in the bookmarklet (256-bit random, never exposed to page JS), this is a strong indicator of tampering.

### 7.3 Cache Poisoning Defense

A compromised origin page could attempt to tamper with IndexedDB before the user clicks the bookmarklet:

| Attack | Defense |
|--------|---------|
| Modify cached resources | HMAC verification fails → security warning |
| Delete cache entirely | Bootstrap re-fetches from network, verifies signatures → graceful recovery |
| Inject fake manifest | Ed25519 signature verification fails (attacker lacks private key) |
| Replace HMAC value | HMAC verification fails (attacker doesn't know the HMAC key) |

---

## 8. The Untrusted Origin Page

### 8.1 Role

The origin URL serves two purposes:
1. **Storage scope**: Provides a consistent origin for IndexedDB persistence across sessions
2. **Navigation target**: The bookmarklet redirects here if activated from a different origin

The page content at this URL is **explicitly, permanently untrusted**. Whether the original developer or an attacker controls the server, the page is treated identically — the bookmarklet never relies on it.

### 8.2 Anti-Training (Mimic Page)

While under the original developer's control, the origin page deliberately conditions users to distrust pre-bookmarklet content:

1. **Wrong visual identity**: The page displays a fake app UI with deliberately incorrect colors, characters, and styling
2. **Interaction penalties**: If the user interacts with the mimic content (clicking, tapping), dramatic animations trigger — glitch effects, melting, screen distortion
3. **Destruction**: After the animation, the mimic content is destroyed, replaced with a message explaining what happened

**Purpose**: Train users to:
- Never trust page content before bookmarklet activation
- Always verify their visual identity token after the bookmarklet loads
- Be suspicious if the page appears to show the app already running

After a server compromise, the attacker's page is no more trusted than the mimic was — the user is already conditioned to distrust whatever appears before the bookmarklet runs.

### 8.3 Installer Function

The origin page also serves as the **installer** for new users:
- Explains the trust model
- Lets the user enter a visual identity token
- Generates a per-installation bookmarklet (client-side, using WebCrypto)
- Provides a draggable link for the bookmark bar
- Displays the HMAC key for backup

This dual role (installer + anti-training) is not a security conflict: the installer page is used once, during initial setup. After that, the user interacts only with the bookmarklet.

---

## 9. iOS-Specific Considerations

### 9.1 Bookmarklet vs. Home Screen

iOS does **not** support `javascript:` URLs as home screen icons. Home screen "Add to Home Screen" bookmarks must be `https:` URLs. Therefore:

- The bookmarklet lives in **Safari's bookmark bar/favorites**, not the home screen
- A home screen icon can link to the origin URL (which opens in Safari with the full browser UI, giving access to bookmarks)
- The user flow is: tap home screen icon → Safari opens → tap bookmarklet in favorites bar

### 9.2 Storage Limits

- iOS WebKit allocates ~50MB per origin for IndexedDB
- Storage may be evicted after ~2 weeks of inactivity
- No background sync API support
- Cache eviction is handled gracefully: the bootstrap re-fetches from the network and re-verifies

---

## 10. Build System (Bun Plugin)

### 10.1 Plugin API

anchor.js provides a Bun build plugin that wraps `Bun.build()` and adds manifest generation, signing, and installer generation:

```typescript
import { buildOfflineApp } from 'anchorjs/plugin';

await buildOfflineApp({
  entrypoints: ['./src/app.ts'],
  staticFiles: ['./src/index.html', './src/style.css'],
  outdir: './dist',
  minify: true,

  appName: 'My App',
  version: '1.0.0',
  originUrl: 'https://myname.github.io/myapp',
  privateKey: process.env.SIGNING_PRIVATE_KEY,

  installer: {
    template: './src/installer.html',
    generatorEntrypoint: './src/installer.ts',
  },
});
```

### 10.2 Build Pipeline

```
Source files ──→ Bun.build() ──→ Bundled JS/CSS
                                      │
Static files ─────────────────────────┤
                                      ▼
                               SHA-256 hashing
                                      │
                                      ▼
                            Manifest generation
                                      │
                               Ed25519 signing
                                      │
                                      ▼
                            bootstrap.js copy
                                      │
                                      ▼
                         Installer page generation
                      (templates + bookmarklet generator
                       embedded via Bun.build define)
                                      │
                                      ▼
                                 dist/ output
```

### 10.3 Bookmarklet Generation

The `generateBookmarklet()` API (and its client-side equivalent in the installer page) assembles a bookmarklet by:

1. Reading the bookmarklet template (`runtime/bookmarklet.js`)
2. Inlining the pure-JS SHA-256 implementation (`runtime/pure-sha256.js`)
3. Replacing placeholders with per-installation values (origin URL, bootstrap hash, visual token, HMAC key, update mode)
4. Minifying (comment stripping + whitespace collapse)
5. Producing the `javascript:` URL (~8KB)

### 10.4 Key Management

```bash
# Generate a new Ed25519 keypair
bun run keygen

# Output:
#   PRIVATE KEY (PEM) — store as GitHub secret SIGNING_PRIVATE_KEY
#   PUBLIC KEY (base64 SPKI) — set as PUBLIC_KEY secret or env var
```

The private key never appears in the repository. The public key is embedded in the bootstrap script at build time. The GitHub Actions workflow reads both from repository secrets.

---

## 11. CDN-Friendly Resource Delivery

Because only the manifest is signed and individual resources are hash-verified, application assets can be served from **any CORS-enabled host**:

```json
{
  "/vendor.js": {
    "hash": "sha256-abc123...",
    "size": 145000,
    "urls": [
      "https://unpkg.com/mylib@2.0.0/dist/mylib.min.js",
      "https://cdn.jsdelivr.net/npm/mylib@2.0.0/dist/mylib.min.js"
    ]
  }
}
```

The bootstrap fetches the resource, computes its SHA-256 hash, and verifies it matches the manifest entry. The server delivering the bytes is completely untrusted. This enables:

- **CDN hosting**: Serve large vendor libraries from unpkg/jsDelivr without trusting them
- **Multi-origin redundancy**: List multiple URLs as fallbacks
- **Cache-friendly deployment**: Long-lived, immutable, content-addressed resources

---

## 12. Security Analysis Summary

### What Is Proven

| Property | Mechanism | Guarantee Level |
|----------|-----------|----------------|
| Bootstrap integrity | Pure-JS SHA-256 using engine-guaranteed primitives | **Cryptographic** (SHA-256 collision resistance) |
| Manifest authenticity | Ed25519 signature verification | **Cryptographic** (Ed25519 unforgeability) |
| Resource integrity | SHA-256 hash verification against signed manifest | **Cryptographic** |
| Cache tamper detection | HMAC-SHA256 with per-installation 256-bit key | **Cryptographic** |
| Bookmarklet immutability | Browser bookmark storage (no JS API to read/write) | **Platform guarantee** |

### What Relies on Non-Configurable Properties

| Property | Mechanism | Current Status |
|----------|-----------|---------------|
| Clean execution context | Non-configurable property chain from `window.document` to `iframe.contentWindow` | **Partially verified** — `window.document` confirmed non-configurable; other links may be configurable on some browsers |

### What Is Best-Effort

| Property | Mechanism |
|----------|-----------|
| User awareness of compromise | Visual identity token displayed in verified context |
| User distrust of origin page | Anti-training mimic page |

### Known Limitations

1. **Configurable chain links**: If `createElement` or `contentWindow` are configurable on a target browser, an attacker could substitute a fake clean context. The bookmarklet's runtime validation aborts if it detects this, but a sufficiently sophisticated attacker on such a browser could potentially bypass the check.

2. **Browser storage eviction**: IndexedDB can be evicted by the browser, requiring a network re-fetch. This is a availability concern, not a security concern (re-fetched content is still verified).

3. **Key rotation**: The public key is baked into the bootstrap hash, which is baked into the bookmarklet. Rotating keys requires distributing new bookmarklets. A key hierarchy (root key signs delegate keys) could mitigate this in a future version.

4. **Bookmarklet loss**: If the user loses their bookmarklet (device loss, browser reset), they must re-install from a trusted source. The bookmarklet is a text string and should be backed up.

---

## 13. Comparison with Related Work

| Approach | Trust Root | Survives Server Compromise? | Offline? |
|----------|-----------|----------------------------|---------|
| Standard HTTPS | Server TLS cert | No | No |
| Service Worker + Cache | SW file on server | No (SW update replaces it) | Yes (until SW updates) |
| Subresource Integrity | `<script integrity>` in HTML | No (HTML itself is unverified) | No |
| Browser extension | Extension store | Partially (store could remove) | Yes |
| **anchor.js** | **Client-side bookmarklet** | **Yes** | **Yes (cache permitting)** |

---

## 14. Future Work

- **Key hierarchy**: Root key in bookmarklet signs delegate/rotation keys, allowing key rotation without new bookmarklets
- **Multi-signature**: Require M-of-N signatures on manifests for high-security deployments
- **Browser extension companion**: Optional extension that provides a provably clean context on browsers where the property chain is insufficient
- **Automated security testing**: CI pipeline that runs simulated API-poisoning attacks against the bookmarklet
- **WebAssembly SHA-256**: If a clean context is available, use WASM for faster hashing of large resources
