# Implementation Plan: Security Audit Remediation

## Context

The SECURITY-AUDIT.md identified two critical bugs (C-1, C-2) and several significant/moderate issues. A previous agent session began planning a remediation that evolved into a larger architectural simplification using SRI (Subresource Integrity) data URLs. This plan documents the full scope of work so a fresh agent can execute it.

## Background: The Two Critical Bugs

### C-1: Public Key Sourced from Untrusted Manifest (Signature Bypass)
- **File:** `src/plugin/runtime/bootstrap.js:641`
- The public key used to verify the manifest is read FROM the manifest itself — circular and trivially bypassable.
- If `manifest.publicKey` is absent, verification is skipped entirely (`return manifest;`).
- **Required fix:** Embed the Ed25519 public key as a build-time constant in `bootstrap.js`.

### C-2: Canonicalization Divergence (Signatures Always Fail)
- **Files:** `src/plugin/manifest.ts:28-54` vs `src/plugin/runtime/bootstrap.js:285-303`
- Build-time canonicalization includes `publicKey` and `urls`; runtime excludes them.
- Signatures computed at build time never verify at runtime.
- Currently masked by C-1 (verification is skipped).
- **Required fix:** Unify canonical form. Recommended: exclude `urls` (delivery hints, not integrity data), include `publicKey` (binds signature to key).

## Planned Approach: SRI Data-URL Architecture

The previous agent session concluded that the cleanest fix involves simplifying the architecture to use the browser's native Subresource Integrity (SRI) mechanism via data URLs, rather than the current pure-JS SHA-256 approach for bookmarklet→bootstrap verification. This eliminates the need for `pure-sha256.js` entirely and reduces the bookmarklet size significantly.

**However, this is a major architectural change that goes well beyond fixing C-1 and C-2.** A fresh agent should consider whether to:

1. **Option A (Minimal fix):** Fix only C-1 and C-2 within the existing architecture. This is ~50 lines of code changes across 3 files.
2. **Option B (Full rewrite):** Proceed with the SRI data-URL rewrite as outlined below. This touches every file in the project.

**Recommendation:** Start with Option A. The critical bugs can be fixed without restructuring the entire project. Option B can be a separate follow-up.

---

## Option A: Minimal Fix for C-1 and C-2

### Step 1: Embed public key in bootstrap.js at build time

**File: `src/plugin/builder.ts`**
- After copying `bootstrap.js` to the output directory, replace a placeholder (e.g., `__PUBLIC_KEY__`) with the actual base64-encoded SPKI public key.
- This mirrors how `BOOTSTRAP_HASH` is already embedded in the bookmarklet.

**File: `src/plugin/runtime/bootstrap.js`**
- Add a constant: `var EMBEDDED_PUBLIC_KEY = '__PUBLIC_KEY__';`
- In `fetchAndInstall()` (~line 641) and `checkForUpdates()` (~line 743):
  - Use `EMBEDDED_PUBLIC_KEY` instead of `manifest.publicKey`
  - If `EMBEDDED_PUBLIC_KEY === '__PUBLIC_KEY__'` (not replaced at build time), treat as unsigned dev build with a clear warning
  - Remove the fallback `return manifest;` path — require verification when a key is embedded

### Step 2: Unify canonicalization

**File: `src/plugin/manifest.ts` (build-time)**
- Remove `urls` from the canonical form (lines where `entry.urls = r.urls` is set)
- Keep `publicKey` in the canonical form

**File: `src/plugin/runtime/bootstrap.js` (runtime)**
- Add `publicKey` to the runtime canonical form (around line 285-303):
  ```javascript
  var canonical = {
    version: manifest.version,
    timestamp: manifest.timestamp,
    publicKey: manifest.publicKey,  // ADD THIS
    resources: {}
  };
  ```

### Step 3: Stop using manifest's publicKey for verification

**File: `src/plugin/runtime/bootstrap.js`**
- The manifest may still contain a `publicKey` field for informational purposes, but verification must use only the embedded key.

### Step 4: Fix locked mode (M-1)

**File: `src/plugin/runtime/bootstrap.js:654`**
- `expectedManifestHash` should come from `__bookmarkletConfig`, not from the manifest itself.
- The bookmarklet should pass this through if in locked mode.

**File: `src/plugin/runtime/bookmarklet.js`**
- Add `manifestHash` to the `__bookmarkletConfig` object when in locked mode.

**File: `src/plugin/bookmarklet.ts`**
- Accept an optional `manifestHash` parameter and inject it into the bookmarklet template.

---

## Option B: Full SRI Data-URL Rewrite (Deferred)

This was the larger plan from the previous session. Summary of changes:

1. **Bookmarklet rewrite:** Replace pure-JS SHA-256 hash verification with SRI data-URL approach. The bookmarklet creates a `<script>` tag with `integrity="sha256-..."` and a `data:` URL containing the bootstrap. The browser's native SRI check verifies integrity.
2. **Remove pure-sha256.js:** No longer needed since the browser does the hash check.
3. **Remove visual token system:** S-2 found it's displayed in the compromised context. Rather than fix it, remove it (it has "no cryptographic role" per the design doc).
4. **Remove mimic/anti-training page:** Simplify the installer.
5. **Rewrite DESIGN.md and README.md** for the new architecture.
6. **Delete SECURITY-AUDIT.md** (findings addressed).

---

## Other Issues from the Audit (For Future Work)

| ID | Issue | Priority | Status |
|----|-------|----------|--------|
| S-1 | Clean context verification is circular | Significant | Known limitation, documented — no code fix needed |
| S-2 | Visual token in compromised context | High | Fix: display in clean iframe, OR document limitation |
| S-3 | No automated test suite | High | Write tests per TODO.md test plan |
| S-4 | Regex-based minification | Medium | Use proper parser or add post-minification verification |
| M-2 | `arguments` in pure-SHA-256 | Medium | Replace with fixed-arity functions |
| M-3 | Promise chain uses potentially-poisoned .then()/.catch() | Medium | Document why bracket notation is used |
| M-4 | IndexedDB shared with compromised origin | Medium | Availability attacks possible, integrity handled by HMAC |
| M-5 | Ed25519 import fallback logic | Low | Import directly as SPKI |

---

## Files to Modify (Option A)

1. `src/plugin/runtime/bootstrap.js` — embed public key constant, fix canonicalization, fix locked mode
2. `src/plugin/manifest.ts` — remove `urls` from canonical form
3. `src/plugin/builder.ts` — inject public key into bootstrap.js at build time
4. `src/plugin/runtime/bookmarklet.js` — pass manifestHash in locked mode config
5. `src/plugin/bookmarklet.ts` — accept manifestHash parameter
