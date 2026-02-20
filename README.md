# markproof

**Trust-anchored web application loader.** Protect your static web app against server compromise, domain seizure, and MITM attacks — even by state-level adversaries — after initial installation.

> **[Live Demo & Installer](https://markproof.ameriwether.com)** — try the Dino Runner demo app with bookmarklet-based trust anchoring

---

## What It Does

Standard web apps trust the server every time they load. If the server is compromised, every user gets malicious code. Service workers don't help — the browser's update lifecycle will eventually install the attacker's replacement.

**markproof moves the root of trust from the server to a client-side bookmarklet.** After initial installation, all code is cryptographically verified against keys embedded in the user's bookmark before execution. An attacker who gains control of every server involved — the origin, the CDN, DNS, even a certificate authority — cannot cause the user to run unverified code, though they can cause a denial of service by serving content that fails verification.

> **Important:** This protection assumes the Ed25519 signing key is held offline or otherwise compartmentalized — it must not be compromised alongside the server. This makes markproof suitable for **static, offline-signed content** where the key is managed separately from the deployment infrastructure, but **not for dynamic server-generated content** where the signing key would need to live on the server itself.

### How It Works

1. User visits the origin URL and generates a personalized **bookmarklet** (a `javascript:` bookmark containing the bootstrap URL and its cryptographic hash)
2. The bookmarklet navigates to a **`data:text/html` page** — a guaranteed clean browsing context with an opaque origin, completely isolated from any compromised page JavaScript
3. The data-URL page loads the **bootstrap script** via a `<script>` tag with browser-native **SRI (Subresource Integrity)** — the browser verifies the SHA-256 hash before execution
4. The bootstrap runs in the clean context, verifies the **Ed25519 signature** on the application manifest, then fetches and hash-verifies each resource before execution

### Key Properties

- **Protects against server compromise**: The server is explicitly untrusted. All content is signature-verified against keys in the bootstrap. A compromised server can cause denial of service (by serving content that fails verification) but cannot cause the user to execute unverified code. This assumes the signing key remains uncompromised (held offline/compartmentalized).
- **Protects against domain seizure**: Even if a government seizes the domain, the bookmarklet's keys reject any unsigned replacement code. The application becomes unavailable but cannot be silently replaced.
- **Guaranteed clean context**: The data-URL page provides a browser-guaranteed fresh JavaScript environment — no attacker code can influence it.
- **CDN-friendly**: Only the manifest is signed. Individual resources are hash-verified, so they can be hosted on any CORS-enabled server (unpkg, jsDelivr, etc.) without trusting it.
- **Static content only**: Because the signing key must remain offline/compartmentalized, markproof is designed for static, pre-built content signed at build time — not for dynamic server-generated content where the key would need to be accessible to the server.
- **Minimal dependencies**: Zero runtime dependencies. Only build dependency is `@types/bun`.

See [DESIGN.md](DESIGN.md) for the full threat model, architecture, and security analysis.

---

## Using the Plugin

markproof provides a Bun build plugin that adds manifest generation, Ed25519 signing, and installer page generation to any Bun project.

### 1. Install

```bash
# Add to your project (when published to npm)
bun add markproof

# Or reference directly from a local clone
```

### 2. Create a Build Script

```typescript
// build.ts
import { buildApp } from 'markproof/plugin';
// Or from local path:
// import { buildApp } from './path-to-markproof/src/plugin';

await buildApp({
  // Standard Bun.build options
  entrypoints: ['./src/app.ts'],
  staticFiles: [
    './src/style.css',
    { src: './src/app.html', dest: 'app.html' },
  ],
  outdir: './dist',
  minify: true,

  // markproof options
  appName: 'My App',
  version: '1.0.0',
  originUrl: 'https://yourname.github.io/yourapp',

  // Signing (optional — omit for unsigned development builds)
  privateKey: process.env.SIGNING_PRIVATE_KEY,

  // Installer page
  installer: {
    template: './src/installer/index.html',
    generatorEntrypoint: './src/installer/generator.ts',
  },
});
```

### 3. Generate Signing Keys

```bash
bun run src/plugin/keygen.ts
```

This outputs an Ed25519 keypair:
- **Private key** (PEM): Store as a GitHub repository secret named `SIGNING_PRIVATE_KEY`
- **Public key** (base64 SPKI): Store as `PUBLIC_KEY` secret

### 4. Build

```bash
# Unsigned (development)
bun run build.ts

# Signed (production)
SIGNING_PRIVATE_KEY="$(cat private-key.pem)" bun run build.ts
```

Output in `dist/`:
```
dist/
├── index.html       # Installer / bookmarklet generator page
├── manifest.json    # Signed manifest with resource hashes
├── bootstrap.js     # Bootstrap script (SRI-verified by bookmarklet)
├── app.html         # App resources (hash-verified via manifest)
├── app.js           #   ↑
└── style.css        #   ↑
```

### 5. Deploy

Deploy `dist/` to any static host that serves CORS headers. GitHub Pages works out of the box:

```yaml
# .github/workflows/deploy.yml
env:
  SIGNING_PRIVATE_KEY: ${{ secrets.SIGNING_PRIVATE_KEY }}
  PUBLIC_KEY: ${{ secrets.PUBLIC_KEY }}
```

### 6. Programmatic Bookmarklet Generation

```typescript
import { generateBookmarklet } from 'markproof/plugin';

const { url } = generateBookmarklet({
  originUrl: 'https://yourname.github.io/yourapp',
  bootstrapUrl: 'https://yourname.github.io/yourapp/bootstrap.js',
  bootstrapHashBase64: 'abc123...', // From build output (base64)
  updateMode: 'auto', // or 'locked'
});

console.log(url);     // javascript:void(function(){...})()
```

---

## Project Structure

```
src/
├── plugin/                     # Reusable Bun plugin
│   ├── index.ts                # Public API exports
│   ├── builder.ts              # buildApp() — wraps Bun.build
│   ├── manifest.ts             # Manifest generation + Ed25519 signing
│   ├── bookmarklet.ts          # Bookmarklet assembly + minification
│   ├── keygen.ts               # Ed25519 keypair generation CLI
│   └── runtime/                # Files deployed with every app
│       ├── bookmarklet.js      # Bookmarklet template (data-URL + SRI)
│       └── bootstrap.js        # Bootstrap (runs in clean data-URL context)
├── demo/                       # Demo: Dino Runner game
│   ├── game.ts                 # Canvas-based endless runner
│   ├── index.html              # Game HTML shell
│   └── style.css
└── installer/                  # Demo: installer page
    ├── index.html              # Template for bookmarklet generation
    └── generator.ts            # Client-side bookmarklet generator
```

---

## Update Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Locked** | Pinned to exact version; even signed updates are rejected | Maximum security — code changes require new bookmarklet |
| **Auto-update** | Accepts author-signed updates | Convenience — user trusts the author's signing key |

---

## Trust Anchor & Bookmarklet Installation

Every time a user installs (or re-installs) a bookmarklet, they are **resetting their trust anchor** to whatever entity currently controls the content at that URL. If the server has been compromised at the time of installation, the user will receive a bookmarklet anchored to the attacker's keys.

This is analogous to SSH's "trust on first use" (TOFU) model: the initial connection must be authentic, but all subsequent connections are verified against that anchor.

**Implications:**
- The bookmarklet should clearly communicate that a **signature verification failure may indicate server compromise**, even if the server appears to be functioning normally and still shows the "install bookmarklet" page. The visual appearance of the page is not trustworthy — only the cryptographic verification is.
- Users should treat bookmarklet installation with the same gravity as installing software: verify the source through an out-of-band channel when possible.
- A compromised server that still displays the installer page is indistinguishable from a legitimate one — the user must understand that installing a new bookmarklet from a potentially compromised source resets all prior trust guarantees.

---

## Browser Compatibility

The trust-anchoring mechanism requires:
- `javascript:` bookmarklet support (all major desktop browsers; Safari on iOS via bookmark bar)
- `data:text/html` URL navigation from bookmarklets
- Subresource Integrity (SRI) support for `<script>` tags
- CORS-enabled resource hosting (`Access-Control-Allow-Origin: *`)
- WebCrypto `crypto.subtle` for Ed25519 signature verification

---

## License

MIT
