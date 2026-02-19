#!/usr/bin/env node
// Build tool for generating per-installation bookmarklets.
//
// Usage:
//   node src/build.js \
//     --origin-url "https://example.com/app" \
//     --bootstrap-url "https://cdn.example.com/bootstrap.js" \
//     --visual-token "blue-dragon" \
//     --update-mode "auto"
//
// The tool:
//   1. Reads the bootstrap script and computes its SHA-256 hash
//   2. Reads the bookmarklet template and pure-sha256 source
//   3. Inlines the SHA-256 implementation into the bookmarklet
//   4. Injects per-installation values (origin URL, hash, visual token, HMAC key)
//   5. Outputs the complete javascript: URL

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Parse command-line arguments
const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  const key = process.argv[i].replace(/^--/, '');
  const val = process.argv[i + 1];
  args[key] = val;
}

const originUrl = args['origin-url'];
const bootstrapUrl = args['bootstrap-url'];
const visualToken = args['visual-token'] || '';
const updateMode = args['update-mode'] || 'auto';
const bootstrapPath = args['bootstrap-path'] || path.join(__dirname, 'bootstrap.js');
const outputPath = args['output'] || null;

if (!originUrl || !bootstrapUrl) {
  console.error('Usage: node src/build.js --origin-url URL --bootstrap-url URL [options]');
  console.error('');
  console.error('Required:');
  console.error('  --origin-url URL        The untrusted origin URL for IndexedDB storage');
  console.error('  --bootstrap-url URL     URL to fetch the bootstrap script from');
  console.error('');
  console.error('Optional:');
  console.error('  --visual-token TOKEN    User-specific visual identity token');
  console.error('  --update-mode MODE      "locked" or "auto" (default: auto)');
  console.error('  --bootstrap-path PATH   Path to bootstrap.js (default: src/bootstrap.js)');
  console.error('  --output PATH           Output file path (default: stdout)');
  process.exit(1);
}

// Read source files
const srcDir = __dirname;
const bookmarkletTemplate = fs.readFileSync(
  path.join(srcDir, 'bookmarklet.js'), 'utf8'
);
const pureSha256Source = fs.readFileSync(
  path.join(srcDir, 'pure-sha256.js'), 'utf8'
);
const bootstrapSource = fs.readFileSync(bootstrapPath, 'utf8');

// Compute SHA-256 of the bootstrap script
const bootstrapHash = crypto.createHash('sha256')
  .update(bootstrapSource, 'utf8')
  .digest('hex');

// Generate random 256-bit HMAC key
const hmacKey = crypto.randomBytes(32).toString('hex');

// Build the bookmarklet
let bookmarklet = bookmarkletTemplate;

// Inline the pure-sha256 source
bookmarklet = bookmarklet.replace(
  '// __PURE_SHA256_SOURCE__',
  pureSha256Source
);

// Replace placeholders with per-installation values
// Use exact string replacement to avoid regex issues with special characters
bookmarklet = bookmarklet.split("'__ORIGIN_URL__'").join(
  JSON.stringify(originUrl)
);
bookmarklet = bookmarklet.split("'__BOOTSTRAP_HASH__'").join(
  JSON.stringify(bootstrapHash)
);
bookmarklet = bookmarklet.split("'__BOOTSTRAP_URL__'").join(
  JSON.stringify(bootstrapUrl)
);
bookmarklet = bookmarklet.split("'__VISUAL_TOKEN__'").join(
  JSON.stringify(visualToken)
);
bookmarklet = bookmarklet.split("'__HMAC_KEY__'").join(
  JSON.stringify(hmacKey)
);
bookmarklet = bookmarklet.split("'__UPDATE_MODE__'").join(
  JSON.stringify(updateMode)
);

// Strip comments and collapse whitespace for the bookmarklet URL
// (basic minification -- a production build would use a proper minifier)
let minified = bookmarklet
  // Remove single-line comments (but not URLs containing //)
  .replace(/(?<![:'"])\/\/(?!.*['"])[^\n]*/g, '')
  // Remove multi-line comments
  .replace(/\/\*[\s\S]*?\*\//g, '')
  // Collapse whitespace
  .replace(/\s+/g, ' ')
  // Remove space around operators/punctuation
  .replace(/\s*([{}();\[\],=<>!&|+\-*/%^~?:])\s*/g, '$1')
  // Clean up any double semicolons
  .replace(/;;+/g, ';')
  .trim();

// Create the javascript: URL
const javascriptUrl = 'javascript:' + minified;

// Output
if (outputPath) {
  fs.writeFileSync(outputPath, javascriptUrl, 'utf8');
  console.error('Bookmarklet written to: ' + outputPath);
} else {
  process.stdout.write(javascriptUrl);
}

// Print metadata to stderr
console.error('');
console.error('=== Bookmarklet Build Info ===');
console.error('Origin URL:     ' + originUrl);
console.error('Bootstrap URL:  ' + bootstrapUrl);
console.error('Bootstrap hash: ' + bootstrapHash);
console.error('Visual token:   ' + (visualToken || '(none)'));
console.error('HMAC key:       ' + hmacKey.substring(0, 8) + '...');
console.error('Update mode:    ' + updateMode);
console.error('Bookmarklet size: ' + javascriptUrl.length + ' characters');
console.error('');
if (javascriptUrl.length > 65536) {
  console.error('WARNING: Bookmarklet exceeds 65KB. May not work in Firefox.');
}
if (javascriptUrl.length > 10000) {
  console.error('NOTE: Bookmarklet is ' + javascriptUrl.length +
    ' chars. Test on iOS Safari for size compatibility.');
}
