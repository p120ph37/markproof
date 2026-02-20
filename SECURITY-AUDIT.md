# Security Audit: markproof

**Trust-Anchored Web Application Loader**

Auditor: Claude (Opus 4.6), acting in the composite style of Bernstein, Schneier, Mitnick, and Knuth
Date: 2026-02-20
Scope: Full codebase review — design, implementation, and threat model

---

## Executive Summary

markproof is an ambitious and intellectually rigorous project that attempts to solve a genuine unsolved problem: providing code integrity guarantees for web applications against server compromise, up to and including state-level adversaries. The core architecture — moving the root of trust from a server URL to a client-side bookmarklet containing cryptographic material — is novel and well-reasoned.

The design document is unusually honest about its own limitations, which is a positive signal. However, the implementation contains two critical deviations from the documented security model that, if deployed, would nullify signature verification entirely. These must be fixed before any security claim is credible.

---

## I. Critical Implementation Defects

### C-1. Public Key Sourced from Untrusted Manifest (Signature Bypass)

**File:** `src/plugin/runtime/bootstrap.js:641`
**Severity:** Critical — defeats the entire signature verification chain

The DESIGN.md states: *"The signing public key is embedded in the bootstrap (which was hash-verified in step 1)."* The implementation does the opposite:

```javascript
// bootstrap.js:641
if (manifest.publicKey) {
  return importEd25519PublicKey(manifest.publicKey).then(function(pubKey) {
    return verifyManifest(manifest, pubKey);
  });
}
// If no public key in manifest... skip verification entirely
return manifest;
```

The public key is read FROM the manifest, then used to verify the manifest's own signature. This is circular. An attacker who compromises the server can generate their own Ed25519 keypair, sign a malicious manifest with their private key, embed their public key in the manifest, and the bootstrap will verify it successfully.

Furthermore, if the manifest has no `publicKey` field, the code falls through to `return manifest` — executing completely unverified content.

**Fix:** The Ed25519 public key must be a constant embedded in `bootstrap.js` at build time, just as the DESIGN.md describes. The build pipeline already computes `bootstrapHash` after writing `bootstrap.js`, so the public key should be injected into the bootstrap source via template replacement before hashing. The manifest's `publicKey` field should be treated as informational only (for display to the user), never as the verification key.

### C-2. Canonicalization Divergence Between Build and Runtime (Signature Always Fails)

**File:** `src/plugin/manifest.ts:28-54` vs `src/plugin/runtime/bootstrap.js:285-303`
**Severity:** Critical — correct signatures will never verify

The build-time `canonicalizeManifest` includes `publicKey` and `urls`:

```typescript
// manifest.ts:34
if (manifest.publicKey) {
  canonical.publicKey = manifest.publicKey;
}
// ...
if (r.urls && r.urls.length > 0) {
  entry.urls = r.urls;
}
```

The runtime `canonicalizeManifest` includes neither:

```javascript
// bootstrap.js:286-303
var canonical = {
  version: manifest.version,
  timestamp: manifest.timestamp,
  resources: {}  // Only hash and size per resource
};
```

The signature is computed over the build-time canonical form (with `publicKey` and `urls`), but verification at runtime computes a different canonical form (without them). The signature will never match. In the current codebase, this bug is masked by C-1 (signatures are effectively skipped), but fixing C-1 without fixing C-2 would make all signed manifests fail verification.

**Fix:** The canonical forms must be identical. Either add `publicKey` and `urls` to the runtime canonicalization, or remove them from the build-time canonicalization. The cleanest approach is to define the canonical form once and be explicit about what it covers. I recommend excluding `urls` (they are delivery hints, not integrity data) and including `publicKey` (it binds the signature to a specific key, preventing key-substitution attacks if the key is ever stored outside the bootstrap).

---

## II. Significant Concerns

### S-1. Clean Context Verification Is Circular

**File:** `src/plugin/runtime/bookmarklet.js:84-209`

The bookmarklet creates a clean iframe context, then uses the clean context's `Object.getOwnPropertyDescriptor` to verify properties of the parent context. But if the attacker controls `createElement` or `contentWindow` (both acknowledged as potentially configurable in the DESIGN.md), they control the iframe returned. The "clean" context is then an attacker-controlled context, and the verification checks (`cleanWin.Object !== window.Object`, property descriptor inspection) can all be fabricated.

The DESIGN.md acknowledges this: *"an attacker must both subvert the chain validation AND find a SHA-256 collision."* But this framing is misleading. The attacker does NOT need a SHA-256 collision. If they control the fake clean context, they control `cleanWin.eval`. The bookmarklet calls `cleanWin.eval(bootstrapSource)` with the genuine hash-verified bootstrap source, but the attacker's fake `eval` can ignore the argument and execute anything.

The pure-JS SHA-256 guarantee is: "the content string passed to the callback has the correct hash." The clean-context guarantee is: "the eval that executes this content is genuine." If the second guarantee fails, the first is irrelevant — the attacker discards the verified content and runs their own code.

**Mitigation assessment:** This is the fundamental tension of the design. On browsers where the full chain is non-configurable, the system is sound. On browsers where it is not, no software-only fix exists within the bookmarklet paradigm. The correct response is:
1. Runtime abort on browsers where chain links are configurable (current behavior — good).
2. Clear documentation that security guarantees are browser-dependent (current docs — good).
3. Continuous testing as browser engines evolve (future work — needed).
4. Consider the browser extension companion mentioned in DESIGN.md Section 14 as a fallback for browsers with configurable chains.

### S-2. Visual Token Displayed in Compromised Context

**File:** `src/plugin/runtime/bootstrap.js:347-377`

The DESIGN.md states: *"It is displayed in the verified clean context, so an attacker who controls the page cannot observe it."* The implementation does the opposite — the visual token is rendered into the parent window's document:

```javascript
var badge = parentWindow.document.createElement('div');
// ...
badge.textContent = VISUAL_TOKEN;
(container || parentWindow.document.body).appendChild(badge);
```

The parent window is the compromised context. A MutationObserver, a poisoned `createElement`, or a poisoned `appendChild` can observe the visual token value. While the visual token has no cryptographic role, its value as a human-verification mechanism is undermined if the attacker can observe and replicate it.

**Fix:** The visual token should be displayed within the clean iframe context (resized/positioned to be visible), not injected into the parent document. Alternatively, accept and document that the visual token is observable by page JS and therefore serves only as a "canary" (if the user sees the wrong token, something is wrong; if they see the right one, it is not proof of integrity).

### S-3. No Automated Test Suite

There are zero tests — no unit tests for the pure-JS SHA-256, no integration tests for signature verification, no property chain tests in CI. For a project whose security rests on the correctness of a hand-written SHA-256 implementation using only bitwise operators, this is a significant gap.

**Recommendation:**
- SHA-256 MUST be tested against known test vectors (NIST FIPS 180-4 examples). A single off-by-one in a rotation constant would produce consistent-but-wrong hashes that pass internal checks but wouldn't match any standard SHA-256 implementation — the bootstrap hash computed at build time (by Node's `crypto`) would never match the bookmarklet's pure-JS computation.
- The canonicalization functions must have tests that verify build-time and runtime produce identical output for the same input.
- The bookmarklet minifier should be tested to ensure it doesn't break the pure-JS SHA-256 or bookmarklet logic.

### S-4. Regex-Based Minification of Security-Critical Code

**File:** `src/plugin/bookmarklet.ts:63-76`, `src/installer/generator.ts:25-33`

The bookmarklet minifier uses regex patterns to strip comments and collapse whitespace:

```typescript
.replace(/(?<![:'"])\/\/(?!.*['"])[^\n]*/g, '')
```

Regex-based JavaScript minification is notoriously fragile. The comment-stripping regex uses a negative lookbehind `(?<![:'"])` and a negative lookahead `(?!.*['"])`, but this cannot correctly parse all JS comment/string interactions. Consider:

```javascript
var x = /regex/; // comment
```

The `/regex/` would match the `//` comment-start heuristic. While the current source doesn't contain regex literals, future edits to `bookmarklet.js` or `pure-sha256.js` could silently break the minified output.

**Recommendation:** Either use a proper JS parser for minification (e.g., Bun's built-in minifier on the assembled bookmarklet) or add a post-minification verification step that runs the minified bookmarklet against SHA-256 test vectors before deployment.

---

## III. Moderate Concerns

### M-1. Locked Mode Is Inoperative

**File:** `src/plugin/runtime/bootstrap.js:654`

```javascript
if (UPDATE_MODE === 'locked' && manifest.expectedManifestHash) {
```

The `expectedManifestHash` is read from the manifest itself. It is never set by the build pipeline (`manifest.ts` has no such field). Even if it were set, trusting the manifest to contain the expected hash of itself is circular. The locked-mode hash should be embedded in the bookmarklet (passed through to the bootstrap via `__bookmarkletConfig`), not in the manifest.

### M-2. `arguments` Object in Pure-JS SHA-256

**File:** `src/plugin/runtime/pure-sha256.js:97-103`

The `_add()` function uses the `arguments` object:

```javascript
function _add() {
  var r = 0;
  for (var i = 0; i < arguments.length; i = i + 1) {
    r = ((r + arguments[i]) & 0xFFFFFFFF) >>> 0;
  }
  return r;
}
```

While `arguments` is an engine-guaranteed object for `function` declarations, its indexed access `arguments[i]` traverses the prototype chain if the index doesn't exist as an own property. If `Object.prototype` has been poisoned with numeric-indexed getters, a hypothetical edge case could arise where `arguments.length` reports the correct count but `arguments[i]` returns attacker values. In practice, `arguments[0]` through `arguments[n]` are own properties of the `arguments` object when `n` actual arguments are passed, so they take precedence. This is safe by specification but violates the stated design principle of using "ONLY engine-guaranteed primitives." The `arguments` object's prototype is `Object.prototype`, not `null`.

**Recommendation:** Replace `_add()` with explicit-arity variants (`_add2` already exists; add `_add3`, `_add4`, `_add5`) to eliminate the `arguments` dependency. Every call site uses a fixed number of arguments.

### M-3. Promise Chain Uses Potentially-Poisoned `.then()`/`.catch()`

**File:** `src/plugin/runtime/bookmarklet.js:256-265`

The bookmarklet uses `fetch(...).then(...)['catch'](...)` to fetch the bootstrap. `Promise.prototype.then` and `Promise.prototype.catch` are potentially poisoned. A poisoned `.then()` could:
- Never invoke the callback (denial of service)
- Invoke the callback with attacker-controlled data (content substitution — detected by hash)
- Invoke the callback AND exfiltrate the argument (the bootstrap source is public, so no secret is leaked)

This is correctly analyzed in the design as acceptable, but the `['catch']` syntax suggests awareness of potential keyword issues — it would be clearer to document why bracket notation is used here.

### M-4. IndexedDB Shared with Compromised Origin

The clean iframe inherits the parent origin's IndexedDB scope. This means the compromised page and the clean context share the same IndexedDB database. While HMAC verification detects tampering, an attacker could:
- Continuously delete or corrupt the cache (persistent denial of service)
- Fill IndexedDB quota with junk data, preventing the verified app from caching
- Race-condition the bootstrap's writes by running concurrent IndexedDB transactions

The HMAC-based tamper detection handles integrity, but availability attacks on the cache remain possible.

### M-5. Ed25519 Import Fallback Logic

**File:** `src/plugin/runtime/bootstrap.js:136-152`

```javascript
return crypto.subtle.importKey('raw', bytes, { name: 'Ed25519' }, false, ['verify'])
  .catch(function() {
    return crypto.subtle.importKey('spki', bytes, { name: 'Ed25519' }, false, ['verify']);
  });
```

The function tries `raw` import first, then falls back to `spki`. The input is a base64-decoded public key that will be in SPKI format (as generated by the keygen). The `raw` import will always fail (SPKI bytes are not a valid raw Ed25519 key), producing an error that is silently caught. This is harmless but wasteful. More importantly, the `catch` swallows ALL errors, including genuine failures like "Ed25519 not supported." If `spki` import also fails, the outer promise chain will reject, but the error message will be from the second attempt, not from the first.

---

## IV. Assumptions That Must Hold

| # | Assumption | Consequence if Violated |
|---|-----------|------------------------|
| A-1 | Browser correctly implements `delete` operator semantics for non-configurable properties | Chain validation provides false assurance; fake clean context accepted |
| A-2 | `{__proto__: null}` syntax creates genuinely prototype-free objects at the engine level | Pure-JS SHA-256 objects could be prototype-polluted, corrupting hash computation |
| A-3 | `string[i]` uses engine-internal `[[Get]]` on String exotic objects, not `String.prototype` | ASCII lookup table construction could be subverted, producing wrong byte values |
| A-4 | `string.length` is a non-configurable own property of string primitives | Message length computation in SHA-256 could be wrong, producing incorrect padding |
| A-5 | Bitwise operators (`>>>`, `&`, `|`, `^`, `~`) operate on numeric values without invoking `valueOf`/`Symbol.toPrimitive` on operands that are already numbers | SHA-256 arithmetic could be subverted |
| A-6 | The initial installation occurs from an uncompromised page | A compromised installer can embed an attacker-controlled HMAC key and public key |
| A-7 | The browser provides no API to read or modify bookmark content from page JS | If such an API is introduced, the bookmarklet's immutability is lost |
| A-8 | The browser's `about:blank` iframe inherits the parent origin | If not, IndexedDB and other storage APIs fail in the clean context |
| A-9 | `javascript:` bookmarklets continue to be supported by major browsers | Chrome has discussed restricting bookmarklets; removal would kill the project |
| A-10 | The Ed25519 signing key is never compromised | Key compromise allows silent malicious updates in auto-update mode |

Assumptions A-1 through A-5 are well-grounded in the ES specification and are unlikely to be violated by conformant engines. A-6 is inherent to any trust-bootstrapping system. A-7 and A-9 are platform risks outside the project's control. A-8 is current browser behavior but not strongly specified. A-10 is standard for any signed-update system.

---

## V. Unique Strengths

### 1. Genuinely Novel Trust Architecture

No other web technology provides the combination of: (a) client-side root of trust, (b) no installation requirement beyond a bookmark, (c) offline capability, (d) resilience against server compromise and domain seizure. The project identifies a real gap in the web platform's security model and proposes a coherent solution.

### 2. Engine-Guaranteed Primitive Discipline

Building SHA-256 from only operators, literals, string indexing, and `{__proto__: null}` objects demonstrates a level of rigor rarely seen in web security projects. The systematic exclusion of all method calls on mutable prototypes is theoretically sound and well-documented.

### 3. Transparent Threat Model

The DESIGN.md is exceptional in its honesty. It clearly distinguishes between what is cryptographically proven, what relies on browser property semantics, and what is best-effort. The "What Remains Undefendable" section (4.5) is the kind of candor that security projects should aspire to.

### 4. Anti-Training Mimic Page

The mimic page that trains users to distrust pre-bookmarklet content is creative and psychologically sound. It addresses the "habit formation" problem — users who become accustomed to seeing a legitimate-looking page before clicking the bookmarklet are vulnerable to phishing if the server is later compromised. The glitch-and-melt animation on interaction is a memorable negative reinforcement.

### 5. CDN-Agnostic Resource Delivery

The separation between signed manifest and hash-verified resources enables hosting on untrusted CDNs without expanding the trust surface. This is architecturally elegant and practically useful.

### 6. Comprehensive Empirical Browser Testing

The `test-property-chains.html` test page is thorough, testing 12 property chains across multiple browsers. The raw descriptor dump enables independent verification. This empirical approach is appropriate given the lack of formal specification for Web IDL property configurability.

### 7. Minimal Dependency Surface

Zero runtime dependencies. The only build dependency is `@types/bun`. This eliminates supply-chain attack vectors that plague most npm projects.

---

## VI. Recommendations Summary

| Priority | Item | Action |
|----------|------|--------|
| **CRITICAL** | C-1: Public key from untrusted manifest | Embed public key in bootstrap.js at build time |
| **CRITICAL** | C-2: Canonicalization divergence | Unify canonical form between build and runtime |
| High | S-2: Visual token in compromised context | Display in clean iframe, or document the limitation |
| High | S-3: No test suite | Add SHA-256 test vectors, canonicalization tests, minifier tests |
| High | M-1: Locked mode inoperative | Embed expected manifest hash in bookmarklet config |
| Medium | S-4: Regex minification | Use proper parser or add post-minification verification |
| Medium | M-2: `arguments` in pure-SHA-256 | Replace with fixed-arity addition functions |
| Low | M-5: Ed25519 import fallback | Import directly as SPKI; don't swallow errors |

---

## VII. Conclusion

markproof's design is intellectually sound and addresses a genuine gap in web security. The engine-guaranteed primitive approach is innovative and the threat model is among the most honest I have reviewed. However, the implementation has two critical bugs (C-1, C-2) that render the signature verification chain completely inoperative — the most important security property the system claims to provide. These must be fixed before any deployment.

The clean-context problem (S-1) is a fundamental limitation that the project handles correctly: acknowledge it, abort when the chain is unreliable, and rely on the hash verification as the cryptographic backstop. The project would benefit greatly from an automated test suite and from fixing the visual token display to match the documented behavior.

The project is at an early but promising stage. The architecture is right; the implementation needs to catch up to the design.
