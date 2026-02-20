export interface BookmarkletOptions {
  originUrl: string;
  bootstrapUrl: string;
  bootstrapHashBase64: string;  // Base64-encoded SHA-256 hash of bootstrap.js (for SRI)
  updateMode?: 'locked' | 'auto';
  manifestHash?: string;  // Hex SHA-256 of canonical manifest (for locked mode)
}

/**
 * Generate a bookmarklet javascript: URL from the template and per-installation values.
 *
 * @param options Per-installation configuration
 * @returns Object with the javascript URL
 */
export function generateBookmarklet(options: BookmarkletOptions): {
  url: string;
} {
  const runtimeDir = new URL('./runtime/', import.meta.url).pathname;

  const bookmarkletTemplate = require('fs').readFileSync(
    runtimeDir + 'bookmarklet.js', 'utf8'
  );

  const updateMode = options.updateMode || 'auto';
  const manifestHash = options.manifestHash || '';

  // Replace placeholders with per-installation values
  let bookmarklet = bookmarkletTemplate;
  bookmarklet = bookmarklet.split("'__ORIGIN_URL__'").join(JSON.stringify(options.originUrl));
  bookmarklet = bookmarklet.split("'__BOOTSTRAP_URL__'").join(JSON.stringify(options.bootstrapUrl));
  bookmarklet = bookmarklet.split("'__BOOTSTRAP_HASH_BASE64__'").join(JSON.stringify(options.bootstrapHashBase64));
  bookmarklet = bookmarklet.split("'__UPDATE_MODE__'").join(JSON.stringify(updateMode));
  bookmarklet = bookmarklet.split("'__MANIFEST_HASH__'").join(JSON.stringify(manifestHash));

  // Minify for bookmarklet URL
  const minified = minifyBookmarklet(bookmarklet);

  return {
    url: 'javascript:' + minified,
  };
}

/**
 * Basic minification for bookmarklet source.
 * Strips comments and collapses whitespace.
 */
function minifyBookmarklet(source: string): string {
  return source
    // Remove single-line comments (but not URLs containing //)
    .replace(/(?<![:'"])\/\/(?!.*['"])[^\n]*/g, '')
    // Remove multi-line comments
    .replace(/\/\*[\s\S]*?\*\//g, '')
    // Collapse whitespace
    .replace(/\s+/g, ' ')
    // Remove space around operators/punctuation
    .replace(/\s*([{}();\[\],=<>!&|+\-*/%^~?:])\s*/g, '$1')
    // Clean up double semicolons
    .replace(/;;+/g, ';')
    .trim();
}

/**
 * Get the raw template source for client-side bookmarklet generation.
 * Used by the installer page generator to embed the template at build time.
 */
export function getTemplateSources(): {
  bookmarkletTemplate: string;
} {
  const runtimeDir = new URL('./runtime/', import.meta.url).pathname;
  const fs = require('fs');

  return {
    bookmarkletTemplate: fs.readFileSync(runtimeDir + 'bookmarklet.js', 'utf8'),
  };
}
