# markproof

**Trust-anchored web application loader.** Secure your web app against server compromise, domain seizure, and MITM attacks — even by state-level adversaries — after initial installation.

> **[Live Demo & Installer](https://markproof.ameriwether.com)** — try the Dino Runner demo app with bookmarklet-based trust anchoring

---

## What It Does

Standard web apps trust the server every time they load. If the server is compromised, every user gets malicious code. Service workers don't help — the browser's update lifecycle will eventually install the attacker's replacement.

**markproof moves the root of trust from the server to a client-side bookmarklet.** After initial installation, all code is cryptographically verified against keys embedded in the user's bookmark before execution. An attacker who gains control of every server involved — the origin, the CDN, DNS, even a certificate authority — cannot cause the user to run unverified code.

### How It Works

1. User visits the origin URL and generates a personalized **bookmarklet** (a `javascript:` bookmark containing the bootstrap URL and its cryptographic hash)
2. The bookmarklet navigates to a **`data:text/html` page** — a guaranteed clean browsing context with an opaque origin, completely isolated from any compromised page JavaScript
3. The data-URL page loads the **bootstrap script** via a `<script>` tag with browser-native **SRI (Subresource Integrity)** — the browser verifies the SHA-256 hash before execution
4. The bootstrap runs in the clean context, verifies the **Ed25519 signature** on the application manifest, then fetches and hash-verifies each resource before execution

### Key Properties

- **Survives server compromise**: The server is explicitly untrusted. All content is signature-verified against keys in the bootstrap.
- **Survives domain seizure**: Even if a government seizes the domain, the bookmarklet's keys reject any unsigned replacement code.
- **Guaranteed clean context**: The data-URL page provides a browser-guaranteed fresh JavaScript environment — no attacker code can influence it.
- **CDN-friendly**: Only the manifest is signed. Individual resources are hash-verified, so they can be hosted on any CORS-enabled server (unpkg, jsDelivr, etc.) without trusting it.
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
