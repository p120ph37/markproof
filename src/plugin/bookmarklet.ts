import { sha256hex } from './manifest';
import { randomBytes } from 'crypto';

export interface BookmarkletOptions {
  originUrl: string;
  bootstrapUrl: string;
  bootstrapHash: string;
  visualToken?: string;
  hmacKey?: string;      // Hex-encoded 256-bit HMAC key. Generated if not provided.
  updateMode?: 'locked' | 'auto';
}

/**
 * Generate a bookmarklet javascript: URL from the template and per-installation values.
 *
 * @param options Per-installation configuration
 * @returns Object with the javascript URL and the generated HMAC key
 */
export function generateBookmarklet(options: BookmarkletOptions): {
  url: string;
  hmacKey: string;
} {
  const runtimeDir = new URL('./runtime/', import.meta.url).pathname;

  const bookmarkletTemplate = require('fs').readFileSync(
    runtimeDir + 'bookmarklet.js', 'utf8'
  );
  const pureSha256Source = require('fs').readFileSync(
    runtimeDir + 'pure-sha256.js', 'utf8'
  );

  const hmacKey = options.hmacKey || randomBytes(32).toString('hex');
  const updateMode = options.updateMode || 'auto';
  const visualToken = options.visualToken || '';

  // Inline the pure-sha256 source into the bookmarklet template
  let bookmarklet = bookmarkletTemplate.replace(
    '// __PURE_SHA256_SOURCE__',
    pureSha256Source
  );

  // Replace placeholders with per-installation values
  bookmarklet = bookmarklet.split("'__ORIGIN_URL__'").join(JSON.stringify(options.originUrl));
  bookmarklet = bookmarklet.split("'__BOOTSTRAP_HASH__'").join(JSON.stringify(options.bootstrapHash));
  bookmarklet = bookmarklet.split("'__BOOTSTRAP_URL__'").join(JSON.stringify(options.bootstrapUrl));
  bookmarklet = bookmarklet.split("'__VISUAL_TOKEN__'").join(JSON.stringify(visualToken));
  bookmarklet = bookmarklet.split("'__HMAC_KEY__'").join(JSON.stringify(hmacKey));
  bookmarklet = bookmarklet.split("'__UPDATE_MODE__'").join(JSON.stringify(updateMode));

  // Minify for bookmarklet URL
  const minified = minifyBookmarklet(bookmarklet);

  return {
    url: 'javascript:' + minified,
    hmacKey,
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
 * Get the raw template sources for client-side bookmarklet generation.
 * Used by the installer page generator to embed templates at build time.
 */
export function getTemplateSources(): {
  bookmarkletTemplate: string;
  pureSha256Source: string;
} {
  const runtimeDir = new URL('./runtime/', import.meta.url).pathname;
  const fs = require('fs');

  return {
    bookmarkletTemplate: fs.readFileSync(runtimeDir + 'bookmarklet.js', 'utf8'),
    pureSha256Source: fs.readFileSync(runtimeDir + 'pure-sha256.js', 'utf8'),
  };
}
