/**
 * Client-side bookmarklet generator for the installer page.
 *
 * Build-time constants (injected by Bun.build define):
 *   __BOOTSTRAP_HASH_BASE64__  - Base64-encoded SHA-256 hash of bootstrap.js
 *   __BOOTSTRAP_URL__          - URL to fetch bootstrap.js from
 *   __MANIFEST_HASH__          - SHA-256 hex hash of canonical manifest
 *   __APP_NAME__               - Display name of the app
 *   __APP_VERSION__            - Version string
 */

declare const __BOOTSTRAP_HASH_BASE64__: string;
declare const __BOOTSTRAP_URL__: string;
declare const __MANIFEST_HASH__: string;
declare const __APP_NAME__: string;
declare const __APP_VERSION__: string;

/**
 * Assemble a bookmarklet data URL from build-time constants + per-installation values.
 *
 * The bookmarklet is a data:text/html URL containing a single <script> tag
 * that loads the bootstrap via SRI, with config passed as data attributes.
 */
function assembleBookmarklet(opts: {
  updateMode: string;
}): string {
  let html = '<script src=' + __BOOTSTRAP_URL__
    + ' integrity=sha256-' + __BOOTSTRAP_HASH_BASE64__
    + ' crossorigin=anonymous';

  if (opts.updateMode === 'locked') {
    html += ' data-mode=locked';
  }
  if (opts.updateMode === 'locked' && __MANIFEST_HASH__) {
    html += ' data-hash=' + __MANIFEST_HASH__;
  }

  html += " onerror=document.body.innerHTML='Secure\\x20app\\x20load\\x20failed.'/>";

  return 'data:text/html;base64,' + btoa(html);
}

// === Generator UI ===
function initGenerator() {
  const generateBtn = document.getElementById('generate-btn') as HTMLButtonElement;
  const updateModeSelect = document.getElementById('update-mode') as HTMLSelectElement;
  const resultDiv = document.getElementById('result') as HTMLElement;
  const bookmarkletLink = document.getElementById('bookmarklet-link') as HTMLAnchorElement;

  if (!generateBtn) return;

  generateBtn.addEventListener('click', () => {
    const updateMode = updateModeSelect.value;

    const bookmarkletUrl = assembleBookmarklet({
      updateMode,
    });

    // Update the bookmarklet link
    bookmarkletLink.href = bookmarkletUrl;
    bookmarkletLink.textContent = `${__APP_NAME__} Launcher — Drag to bookmark bar`;

    // Show result section
    resultDiv.classList.add('visible');

    // Log size info
    console.log(`Bookmarklet generated: ${bookmarkletUrl.length} characters`);
  });
}

// Boot
document.addEventListener('DOMContentLoaded', () => {
  initGenerator();
});
