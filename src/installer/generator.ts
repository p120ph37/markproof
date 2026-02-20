/**
 * Client-side bookmarklet generator for the installer page.
 *
 * Build-time constants (injected by Bun.build define):
 *   __BOOKMARKLET_TEMPLATE__ - bookmarklet.js source
 *   __PURE_SHA256_SOURCE__   - pure-sha256.js source
 *   __BOOTSTRAP_HASH__       - SHA-256 hex hash of bootstrap.js
 *   __ORIGIN_URL__           - Origin URL for this deployment
 *   __BOOTSTRAP_URL__        - URL to fetch bootstrap.js from
 *   __APP_NAME__             - Display name of the app
 *   __APP_VERSION__          - Version string
 */

declare const __BOOKMARKLET_TEMPLATE__: string;
declare const __PURE_SHA256_SOURCE__: string;
declare const __BOOTSTRAP_HASH__: string;
declare const __ORIGIN_URL__: string;
declare const __BOOTSTRAP_URL__: string;
declare const __APP_NAME__: string;
declare const __APP_VERSION__: string;

/**
 * Basic minification: strip comments, collapse whitespace.
 */
function minifySource(source: string): string {
  return source
    .replace(/(?<![:'"])\/\/(?!.*['"])[^\n]*/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\s+/g, ' ')
    .replace(/\s*([{}();\[\],=<>!&|+\-*/%^~?:])\s*/g, '$1')
    .replace(/;;+/g, ';')
    .trim();
}

/**
 * Generate a random 256-bit hex string using WebCrypto.
 */
function generateHmacKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Assemble a bookmarklet from template + per-installation values.
 */
function assembleBookmarklet(opts: {
  visualToken: string;
  hmacKey: string;
  updateMode: string;
}): string {
  let bookmarklet = __BOOKMARKLET_TEMPLATE__;

  // Inline pure-sha256
  bookmarklet = bookmarklet.replace(
    '// __PURE_SHA256_SOURCE__',
    __PURE_SHA256_SOURCE__
  );

  // Replace placeholders
  bookmarklet = bookmarklet.split("'__ORIGIN_URL__'").join(JSON.stringify(__ORIGIN_URL__));
  bookmarklet = bookmarklet.split("'__BOOTSTRAP_HASH__'").join(JSON.stringify(__BOOTSTRAP_HASH__));
  bookmarklet = bookmarklet.split("'__BOOTSTRAP_URL__'").join(JSON.stringify(__BOOTSTRAP_URL__));
  bookmarklet = bookmarklet.split("'__VISUAL_TOKEN__'").join(JSON.stringify(opts.visualToken));
  bookmarklet = bookmarklet.split("'__HMAC_KEY__'").join(JSON.stringify(opts.hmacKey));
  bookmarklet = bookmarklet.split("'__UPDATE_MODE__'").join(JSON.stringify(opts.updateMode));

  return 'javascript:' + minifySource(bookmarklet);
}

// === Mimic page anti-training ===
function initMimic() {
  const mimicCanvas = document.getElementById('mimic-canvas') as HTMLCanvasElement;
  const mimicGame = document.getElementById('mimic-game') as HTMLElement;
  if (!mimicCanvas || !mimicGame) return;

  const ctx = mimicCanvas.getContext('2d');
  if (!ctx) return;

  // Draw a deliberately wrong-looking "game" with inverted colors
  ctx.fillStyle = '#ff6060';
  ctx.fillRect(0, 0, 800, 180);
  ctx.fillStyle = '#200000';
  ctx.fillRect(0, 150, 800, 1);

  // Wrong-colored "dino" (a cat-like blob)
  ctx.fillStyle = '#ff00ff';
  ctx.fillRect(80, 110, 30, 40);
  ctx.fillRect(100, 100, 16, 16);
  // Cat ears
  ctx.fillRect(100, 92, 6, 10);
  ctx.fillRect(110, 92, 6, 10);
  // Tail
  ctx.fillRect(72, 115, 12, 4);
  ctx.fillRect(66, 110, 8, 8);

  // Wrong-colored cacti
  ctx.fillStyle = '#ff4444';
  ctx.fillRect(320, 120, 10, 30);
  ctx.fillRect(316, 128, 6, 14);
  ctx.fillRect(500, 110, 10, 40);
  ctx.fillRect(496, 118, 6, 16);
  ctx.fillRect(506, 124, 6, 12);

  // "Score" in wrong position
  ctx.fillStyle = '#440000';
  ctx.font = '14px monospace';
  ctx.fillText('99999', 20, 20);

  // Click handler: trigger glitch + melt
  let glitchTriggered = false;
  mimicGame.addEventListener('click', () => {
    if (glitchTriggered) return;
    glitchTriggered = true;

    mimicGame.classList.add('glitch-active');
    setTimeout(() => {
      mimicGame.classList.remove('glitch-active');
      mimicGame.classList.add('melt-active');
    }, 600);

    setTimeout(() => {
      mimicGame.style.display = 'none';
      const label = mimicGame.nextElementSibling;
      if (label) {
        (label as HTMLElement).textContent =
          'The fake game has been destroyed. This is what should happen — never trust page content.';
        (label as HTMLElement).style.color = '#4a8a4a';
      }
    }, 2800);
  });
}

// === Generator UI ===
function initGenerator() {
  const generateBtn = document.getElementById('generate-btn') as HTMLButtonElement;
  const visualTokenInput = document.getElementById('visual-token') as HTMLInputElement;
  const updateModeSelect = document.getElementById('update-mode') as HTMLSelectElement;
  const resultDiv = document.getElementById('result') as HTMLElement;
  const bookmarkletLink = document.getElementById('bookmarklet-link') as HTMLAnchorElement;
  const hmacValue = document.getElementById('hmac-value') as HTMLElement;

  if (!generateBtn) return;

  generateBtn.addEventListener('click', () => {
    const visualToken = visualTokenInput.value.trim();
    const updateMode = updateModeSelect.value;

    if (!visualToken) {
      visualTokenInput.style.borderColor = '#cc3333';
      visualTokenInput.focus();
      return;
    }

    visualTokenInput.style.borderColor = '';

    const hmacKey = generateHmacKey();
    const bookmarkletUrl = assembleBookmarklet({
      visualToken,
      hmacKey,
      updateMode,
    });

    // Update the bookmarklet link
    bookmarkletLink.href = bookmarkletUrl;
    bookmarkletLink.textContent = `📎 ${__APP_NAME__} Launcher — Drag to bookmark bar`;

    // Show HMAC key for backup
    hmacValue.textContent = hmacKey;

    // Show result section
    resultDiv.classList.add('visible');

    // Log size info
    console.log(`Bookmarklet generated: ${bookmarkletUrl.length} characters`);
    if (bookmarkletUrl.length > 65536) {
      console.warn('Bookmarklet exceeds 65KB — may not work in some browsers');
    }
  });
}

// Boot
document.addEventListener('DOMContentLoaded', () => {
  initMimic();
  initGenerator();
});
