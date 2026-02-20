/**
 * Client-side bookmarklet generator for the installer page.
 *
 * Build-time constants (injected by Bun.build define):
 *   __BOOKMARKLET_TEMPLATE__   - bookmarklet.js source
 *   __BOOTSTRAP_HASH_BASE64__  - Base64-encoded SHA-256 hash of bootstrap.js
 *   __ORIGIN_URL__             - Origin URL for this deployment
 *   __BOOTSTRAP_URL__          - URL to fetch bootstrap.js from
 *   __MANIFEST_HASH__          - SHA-256 hex hash of canonical manifest
 *   __APP_NAME__               - Display name of the app
 *   __APP_VERSION__            - Version string
 */

declare const __BOOKMARKLET_TEMPLATE__: string;
declare const __BOOTSTRAP_HASH_BASE64__: string;
declare const __ORIGIN_URL__: string;
declare const __BOOTSTRAP_URL__: string;
declare const __MANIFEST_HASH__: string;
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
 * Assemble a bookmarklet from template + per-installation values.
 */
function assembleBookmarklet(opts: {
  updateMode: string;
}): string {
  let bookmarklet = __BOOKMARKLET_TEMPLATE__;

  // Replace placeholders
  bookmarklet = bookmarklet.split("'__ORIGIN_URL__'").join(JSON.stringify(__ORIGIN_URL__));
  bookmarklet = bookmarklet.split("'__BOOTSTRAP_URL__'").join(JSON.stringify(__BOOTSTRAP_URL__));
  bookmarklet = bookmarklet.split("'__BOOTSTRAP_HASH_BASE64__'").join(JSON.stringify(__BOOTSTRAP_HASH_BASE64__));
  bookmarklet = bookmarklet.split("'__UPDATE_MODE__'").join(JSON.stringify(opts.updateMode));
  bookmarklet = bookmarklet.split("'__MANIFEST_HASH__'").join(
    JSON.stringify(opts.updateMode === 'locked' ? __MANIFEST_HASH__ : '')
  );

  return 'javascript:' + minifySource(bookmarklet);
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
    if (bookmarkletUrl.length > 65536) {
      console.warn('Bookmarklet exceeds 65KB — may not work in some browsers');
    }
  });
}

// Boot
document.addEventListener('DOMContentLoaded', () => {
  initGenerator();
});
