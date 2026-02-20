# markproof

**Trust-anchored web application loader.** Secure your web app against server compromise, domain seizure, and MITM attacks — even by state-level adversaries — after initial installation.

> **[Live Demo & Installer](https://p120ph37.github.io/html5-webapp)** — try the Dino Runner demo app with bookmarklet-based trust anchoring

---

## What It Does

Standard web apps trust the server every time they load. If the server is compromised, every user gets malicious code. Service workers don't help — the browser's update lifecycle will eventually install the attacker's replacement.

**markproof moves the root of trust from the server to a client-side bookmarklet.** After initial installation, all code is cryptographically verified against keys embedded in the user's bookmark before execution. An attacker who gains control of every server involved — the origin, the CDN, DNS, even a certificate authority — cannot cause the user to run unverified code.

### How It Works

1. User visits the origin URL and generates a personalized **bookmarklet** (a `javascript:` bookmark containing cryptographic keys and a visual identity token)
2. The bookmarklet creates a **verified clean execution context** by exploiting non-configurable browser property chains and the `delete` operator (engine-guaranteed primitives that no JavaScript code can intercept)
3. A **bootstrap script** is fetched and hash-verified using a pure-JS SHA-256 implementation built entirely from engine-guaranteed primitives — immune to API monkey-patching
4. The bootstrap runs in the clean context, verifies the **Ed25519 signature** on the application manifest, then fetches and hash-verifies each resource before execution
5. Verified resources are cached in **IndexedDB** with HMAC-based tamper detection for offline use

### Key Properties

- **Survives server compromise**: The server is explicitly untrusted. All content is signature-verified against keys in the bookmarklet.
- **Survives domain seizure**: Even if a government seizes the domain, the bookmarklet's keys reject any unsigned replacement code.
- **Works offline**: Verified resources are cached locally. (Browser storage eviction may require a network re-fetch, which is re-verified.)
- **CDN-friendly**: Only the manifest is signed. Individual resources are hash-verified, so they can be hosted on any CORS-enabled server (unpkg, jsDelivr, etc.) without trusting it.
- **Open source threat model**: Security does not depend on attacker ignorance. The attacker is assumed to have full knowledge of the bookmarklet logic.

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
import { buildOfflineApp } from 'markproof/plugin';
// Or from local path:
// import { buildOfflineApp } from './path-to-markproof/src/plugin';

await buildOfflineApp({
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
├── bootstrap.js     # Bootstrap script (hash-verified by bookmarklet)
├── app.html         # App resources (hash-verified via manifest)
├── app.js           #   ↑
└── style.css        #   ↑
```

### 5. Deploy

Deploy `dist/` to any static host. The GitHub Actions workflow included in the demo handles this automatically for GitHub Pages:

```yaml
# .github/workflows/deploy.yml
env:
  SIGNING_PRIVATE_KEY: ${{ secrets.SIGNING_PRIVATE_KEY }}
  PUBLIC_KEY: ${{ secrets.PUBLIC_KEY }}
```

### 6. Programmatic Bookmarklet Generation

```typescript
import { generateBookmarklet } from 'markproof/plugin';

const { url, hmacKey } = generateBookmarklet({
  originUrl: 'https://yourname.github.io/yourapp',
  bootstrapUrl: 'https://yourname.github.io/yourapp/bootstrap.js',
  bootstrapHash: 'abc123...', // From build output
  visualToken: 'blue-dragon-42',
  updateMode: 'auto', // or 'locked'
});

console.log(url);     // javascript:void(function(){...})()
console.log(hmacKey); // 64-char hex string — back this up!
```

---

## Project Structure

```
src/
├── plugin/                     # Reusable Bun plugin
│   ├── index.ts                # Public API exports
│   ├── builder.ts              # buildOfflineApp() — wraps Bun.build
│   ├── manifest.ts             # Manifest generation + Ed25519 signing
│   ├── bookmarklet.ts          # Bookmarklet assembly + minification
│   ├── keygen.ts               # Ed25519 keypair generation CLI
│   └── runtime/                # Files deployed with every app
│       ├── pure-sha256.js      # SHA-256 using only engine-guaranteed primitives
│       ├── bookmarklet.js      # Bookmarklet template
│       └── bootstrap.js        # Bootstrap (runs in verified clean context)
├── demo/                       # Demo: Dino Runner game
│   ├── game.ts                 # Canvas-based endless runner
│   ├── index.html              # Game HTML shell
│   └── style.css
└── installer/                  # Demo: installer page
    ├── index.html              # Template with mimic-page anti-training
    └── generator.ts            # Client-side bookmarklet generator
```

---

## Update Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Locked** | Pinned to exact version; even signed updates are rejected | Maximum security — code changes require new bookmarklet |
| **Auto-update** | Accepts author-signed updates; HMAC-based cache tamper detection | Convenience — user trusts the author's signing key |

---

## Browser Compatibility

The trust-anchoring mechanism requires:
- `javascript:` bookmarklet support (all major desktop browsers; Safari on iOS via bookmark bar)
- Non-configurable `window.document` property (confirmed: Chrome/Edge, Safari, Firefox)
- IndexedDB for offline caching
- WebCrypto `crypto.subtle` for Ed25519 signature verification (in the clean context)

The bookmarklet includes runtime validation and **aborts with a clear message** if the required property chain is not secure on the current browser.

---

## License

MIT
