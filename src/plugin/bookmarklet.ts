export interface BookmarkletOptions {
  originUrl: string;
  bootstrapUrl: string;
  bootstrapHashBase64: string;  // Base64-encoded SHA-256 hash of bootstrap.js (for SRI)
  updateMode?: 'locked' | 'auto';
  manifestHash?: string;  // Hex SHA-256 of canonical manifest (for locked mode)
}

/**
 * Build the minimal HTML content for a bookmarklet data URL.
 *
 * The HTML is a single <script> tag that loads the bootstrap via SRI,
 * with configuration passed as data attributes.
 */
function buildBookmarkletHtml(options: {
  bootstrapUrl: string;
  bootstrapHashBase64: string;
  updateMode: string;
  manifestHash: string;
}): string {
  let html = '<script src=' + options.bootstrapUrl
    + ' integrity=sha256-' + options.bootstrapHashBase64
    + ' crossorigin=anonymous';

  if (options.updateMode === 'locked') {
    html += ' data-mode=locked';
  }
  if (options.manifestHash) {
    html += ' data-hash=' + options.manifestHash;
  }

  html += " onerror=document.body.innerHTML='Secure\\x20app\\x20load\\x20failed.'></script>";

  return html;
}

/**
 * Generate a bookmarklet data: URL from per-installation values.
 *
 * The bookmarklet is a data:text/html URL containing a single <script> tag
 * that loads the bootstrap via SRI. Configuration is passed as data attributes
 * on the script element.
 *
 * @param options Per-installation configuration
 * @returns Object with the data URL
 */
export function generateBookmarklet(options: BookmarkletOptions): {
  url: string;
} {
  const updateMode = options.updateMode || 'auto';
  const manifestHash = options.manifestHash || '';

  const html = buildBookmarkletHtml({
    bootstrapUrl: options.bootstrapUrl,
    bootstrapHashBase64: options.bootstrapHashBase64,
    updateMode,
    manifestHash,
  });

  const base64 = Buffer.from(html).toString('base64');
  return {
    url: 'data:text/html;base64,' + base64,
  };
}
