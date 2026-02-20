// Bookmarklet source template.
// Navigates to a data:text/html page that loads the bootstrap via SRI.
// The data-URL page has a fresh browsing context with an opaque origin,
// guaranteeing complete isolation from any compromised page JavaScript.
//
// Placeholders (replaced at install time):
//   __ORIGIN_URL__             - The origin URL (informational, passed to bootstrap)
//   __BOOTSTRAP_URL__          - Absolute URL to fetch bootstrap.js
//   __BOOTSTRAP_HASH_BASE64__  - Base64-encoded SHA-256 hash of bootstrap.js (for SRI)
//   __UPDATE_MODE__            - 'locked' or 'auto'
//   __MANIFEST_HASH__          - SHA-256 hex hash of canonical manifest (locked mode; '' for auto)

void(function() {
  var ORIGIN_URL = '__ORIGIN_URL__';
  var BOOTSTRAP_URL = '__BOOTSTRAP_URL__';
  var BOOTSTRAP_HASH_BASE64 = '__BOOTSTRAP_HASH_BASE64__';
  var UPDATE_MODE = '__UPDATE_MODE__';
  var MANIFEST_HASH = '__MANIFEST_HASH__';

  // Build a minimal HTML page that loads the bootstrap via SRI.
  // The config is passed as a global variable in an inline script.
  var html = '<!DOCTYPE html>'
    + '<html><head><meta charset="utf-8"><title>Loading...</title></head><body>'
    + '<script>'
    + 'window.__markproofConfig='
    + '{"originUrl":"' + ORIGIN_URL + '"'
    + ',"bootstrapUrl":"' + BOOTSTRAP_URL + '"'
    + ',"updateMode":"' + UPDATE_MODE + '"'
    + ',"manifestHash":"' + MANIFEST_HASH + '"'
    + '};'
    + '<\/script>'
    + '<script src="' + BOOTSTRAP_URL + '"'
    + ' integrity="sha256-' + BOOTSTRAP_HASH_BASE64 + '"'
    + ' crossorigin="anonymous"'
    + ' onerror="document.body.innerHTML='
    + "'<h1>Bootstrap integrity check failed.<\\/h1>"
    + "<p>The bootstrap script has been tampered with or the server is unreachable.<\\/p>'"
    + '><\/script>'
    + '</body></html>';

  location.href = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
})();
