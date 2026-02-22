// Bootstrap script for the markproof trust-anchored web app loader.
//
// This script is loaded via a <script> tag with SRI (Subresource Integrity)
// inside a data:text/html page. The data-URL page provides a guaranteed clean
// browsing context with an opaque origin, completely isolated from any
// compromised page JavaScript.
//
// Because it runs in a clean data-URL context, it can trust:
//   - fetch (native, unmodified Fetch API)
//   - All built-in objects (Object, Array, Promise, etc.)
//
// Note: crypto.subtle may NOT be available in data: URL contexts (they are
// not "secure contexts" in all browsers). The bootstrap includes a pure-JS
// SHA-256 fallback. Ed25519 verification requires crypto.subtle and will
// fail with a clear error if unavailable.
//
// Configuration is read from data attributes on the <script> element:
//   src          - URL to this bootstrap script (used to derive content base URL)
//   data-mode    - 'locked' or 'auto' (default: 'auto')
//   data-hash    - SHA-256 hex hash of canonical manifest (for locked mode)
//
// Responsibilities:
//   1. Read config from script element
//   2. Fetch and verify app manifest (Ed25519 signature)
//   3. Fetch and hash-verify individual resources
//   4. Render verified app in the current document

(function() {
  'use strict';

  // ================================================================
  // Build-time constant: Ed25519 public key (SPKI, base64-encoded)
  // Injected by the build pipeline. If not replaced, signature
  // verification is skipped (unsigned development build).
  // ================================================================
  var EMBEDDED_PUBLIC_KEY = '__PUBLIC_KEY__';

  // ================================================================
  // Configuration (from script element attributes)
  // ================================================================
  var script = document.currentScript;
  var BOOTSTRAP_URL = script.src;
  var UPDATE_MODE = script.getAttribute('data-mode') || 'auto';
  var MANIFEST_HASH = script.getAttribute('data-hash') || '';

  // ================================================================
  // Ensure document.body exists (data: URL pages may only have <head>)
  // ================================================================
  function ensureBody() {
    if (!document.body) {
      document.documentElement.appendChild(document.createElement('body'));
    }
  }

  // ================================================================
  // Utility: hex string to Uint8Array
  // ================================================================
  function hexToBytes(hex) {
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  }

  // ================================================================
  // Utility: Uint8Array to hex string
  // ================================================================
  function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i].toString(16);
      if (b.length === 1) hex += '0';
      hex += b;
    }
    return hex;
  }

  // ================================================================
  // Utility: string to ArrayBuffer (UTF-8)
  // ================================================================
  function stringToBuffer(str) {
    return new TextEncoder().encode(str);
  }

  // ================================================================
  // Pure-JS SHA-256 implementation (fallback for non-secure contexts)
  //
  // data: URL pages have opaque origins and are NOT "secure contexts"
  // in Chrome, so crypto.subtle is unavailable. This pure-JS SHA-256
  // provides identical results and is used as a fallback.
  // ================================================================
  var SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function sha256js(data) {
    var bytes;
    if (typeof data === 'string') {
      bytes = stringToBuffer(data);
    } else if (data instanceof Uint8Array) {
      bytes = data;
    } else {
      bytes = new Uint8Array(data);
    }

    // Pre-processing: pad message
    var bitLen = bytes.length * 8;
    // Message + 1 byte (0x80) + padding + 8 bytes (length)
    var padLen = 64 - ((bytes.length + 9) % 64);
    if (padLen === 64) padLen = 0;
    var padded = new Uint8Array(bytes.length + 1 + padLen + 8);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    // Write bit length as big-endian 64-bit integer (only lower 32 bits for messages < 512MB)
    var view = new DataView(padded.buffer);
    view.setUint32(padded.length - 4, bitLen, false);

    // Initialize hash values
    var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    var h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    var w = new Uint32Array(64);

    // Process each 512-bit (64-byte) block
    for (var offset = 0; offset < padded.length; offset += 64) {
      // Copy block into first 16 words
      for (var i = 0; i < 16; i++) {
        w[i] = view.getUint32(offset + i * 4, false);
      }

      // Extend to 64 words
      for (var i = 16; i < 64; i++) {
        var s0 = (((w[i-15] >>> 7) | (w[i-15] << 25)) ^ ((w[i-15] >>> 18) | (w[i-15] << 14)) ^ (w[i-15] >>> 3)) >>> 0;
        var s1 = (((w[i-2] >>> 17) | (w[i-2] << 15)) ^ ((w[i-2] >>> 19) | (w[i-2] << 13)) ^ (w[i-2] >>> 10)) >>> 0;
        w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
      }

      // Initialize working variables
      var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

      // Compression function
      for (var i = 0; i < 64; i++) {
        var S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
        var ch = ((e & f) ^ (~e & g)) >>> 0;
        var temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
        var S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
        var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        var temp2 = (S0 + maj) >>> 0;

        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }

      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    // Produce the final hash (big-endian)
    var result = new Uint8Array(32);
    var rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false); rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false); rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false); rv.setUint32(20, h5, false);
    rv.setUint32(24, h6, false); rv.setUint32(28, h7, false);

    return bytesToHex(result);
  }

  // ================================================================
  // Crypto: SHA-256 hash (WebCrypto with pure-JS fallback)
  // ================================================================
  function sha256(data) {
    var buffer = (typeof data === 'string') ? stringToBuffer(data) : data;

    // Use crypto.subtle if available (secure contexts)
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      return crypto.subtle.digest('SHA-256', buffer).then(function(hash) {
        return bytesToHex(new Uint8Array(hash));
      });
    }

    // Fallback: pure-JS SHA-256 (for data: URL non-secure contexts)
    return Promise.resolve(sha256js(buffer));
  }

  // ================================================================
  // Crypto: Ed25519 signature verification (requires crypto.subtle)
  // ================================================================
  function importEd25519PublicKey(base64Key) {
    if (!crypto.subtle) {
      return Promise.reject(new Error(
        'Ed25519 verification requires a secure context (crypto.subtle). ' +
        'This data: URL page is not a secure context.'
      ));
    }

    var raw = atob(base64Key);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    return crypto.subtle.importKey(
      'spki', bytes, { name: 'Ed25519' }, false, ['verify']
    );
  }

  function verifySignature(publicKey, signature, data) {
    var sigBytes = hexToBytes(signature);
    var dataBytes = stringToBuffer(data);
    return crypto.subtle.verify(
      { name: 'Ed25519' }, publicKey, sigBytes, dataBytes
    );
  }

  // ================================================================
  // Network: fetch manifest
  // ================================================================
  function fetchManifest(baseUrl) {
    return fetch(baseUrl + '/manifest.json').then(function(resp) {
      if (!resp.ok) throw new Error('Manifest fetch failed: ' + resp.status);
      return resp.json();
    });
  }

  // ================================================================
  // Network: fetch a resource
  // ================================================================
  function fetchResource(baseUrl, resourcePath) {
    var url = baseUrl + resourcePath;
    return fetch(url).then(function(resp) {
      if (!resp.ok) throw new Error('Resource fetch failed: ' + resp.status + ' ' + resourcePath);
      return resp.text();
    });
  }

  // ================================================================
  // Manifest: canonicalize for signature verification
  // ================================================================
  function canonicalizeManifest(manifest) {
    var canonical = {
      version: manifest.version,
      timestamp: manifest.timestamp,
      resources: {}
    };

    var keys = Object.keys(manifest.resources).sort();
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      canonical.resources[key] = {
        hash: manifest.resources[key].hash,
        size: manifest.resources[key].size
      };
    }

    return JSON.stringify(canonical);
  }

  // ================================================================
  // Manifest: verify Ed25519 signature
  // ================================================================
  function verifyManifest(manifest, publicKey) {
    if (!manifest || !manifest.version || !manifest.resources || !manifest.signature) {
      return Promise.reject(new Error('Invalid manifest structure'));
    }

    var canonical = canonicalizeManifest(manifest);

    return verifySignature(publicKey, manifest.signature, canonical).then(function(valid) {
      if (!valid) {
        throw new Error('Manifest signature verification failed');
      }
      return manifest;
    });
  }

  // ================================================================
  // Resources: verify a fetched resource against its manifest hash
  // ================================================================
  function verifyResource(content, expectedHash) {
    return sha256(content).then(function(hash) {
      var expected = expectedHash.replace(/^sha256-/, '');
      if (hash !== expected) {
        throw new Error('Resource hash mismatch: expected ' + expected + ', got: ' + hash);
      }
      return content;
    });
  }

  // ================================================================
  // Status: show loading/status messages
  // ================================================================
  function showStatus(message) {
    try {
      ensureBody();
      var existing = document.getElementById('__bootstrap_status');
      if (!existing) {
        existing = document.createElement('div');
        existing.id = '__bootstrap_status';
        existing.setAttribute('style',
          'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);' +
          'z-index:2147483647;background:#1a1a2e;color:#e0e0ff;' +
          'padding:12px 24px;border-radius:8px;font-family:monospace;' +
          'font-size:13px;box-shadow:0 2px 12px rgba(0,0,0,0.4);' +
          'border:1px solid #4a4a8a;max-width:80%;text-align:center;'
        );
        document.body.appendChild(existing);
      }
      existing.textContent = message;
    } catch(e) {
      // Best-effort status display
    }
  }

  function hideStatus() {
    try {
      var el = document.getElementById('__bootstrap_status');
      if (el) el.remove();
    } catch(e) {}
  }

  // ================================================================
  // Error: show error and abort
  // ================================================================
  function showError(message) {
    console.error('markproof bootstrap: ' + message);
    try {
      ensureBody();
      hideStatus();
      var el = document.createElement('div');
      el.setAttribute('style',
        'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);' +
        'z-index:2147483647;background:#2e1a1a;color:#ffe0e0;' +
        'padding:24px 32px;border-radius:12px;font-family:monospace;' +
        'font-size:14px;box-shadow:0 4px 24px rgba(0,0,0,0.6);' +
        'border:2px solid #8a4a4a;max-width:80%;text-align:center;' +
        'line-height:1.6;'
      );
      el.textContent = message;
      document.body.appendChild(el);
    } catch(e) {
      try { alert('BOOTSTRAP ERROR: ' + message); } catch(e2) {}
    }
  }

  // ================================================================
  // App injection: render verified app content into the current page
  // ================================================================
  function injectApp(resources, manifest) {
    try {
      // Clear the current page content
      document.documentElement.innerHTML = '';

      var head = document.createElement('head');
      var body = document.createElement('body');

      // Inject CSS resources
      var resourceKeys = Object.keys(manifest.resources);
      for (var i = 0; i < resourceKeys.length; i++) {
        var path = resourceKeys[i];
        var content = resources[path];
        if (!content) continue;

        if (path.match(/\.css$/)) {
          var style = document.createElement('style');
          style.textContent = content;
          head.appendChild(style);
        }
      }

      // Inject HTML resources (look for app.html, index.html, or main.html)
      var htmlContent = resources['/app.html'] || resources['/index.html'] || resources['/main.html'] || '';
      if (htmlContent) {
        var parser = new DOMParser();
        var parsed = parser.parseFromString(htmlContent, 'text/html');

        // Copy head elements (except scripts)
        var parsedHead = parsed.head;
        if (parsedHead) {
          var headChildren = parsedHead.children;
          for (var i = 0; i < headChildren.length; i++) {
            var node = headChildren[i];
            if (node.tagName !== 'SCRIPT') {
              head.appendChild(document.importNode(node, true));
            }
          }
        }

        // Copy body content
        body.innerHTML = parsed.body.innerHTML;
      }

      document.documentElement.appendChild(head);
      document.documentElement.appendChild(body);

      // Inject JS resources (after DOM is built)
      for (var i = 0; i < resourceKeys.length; i++) {
        var path = resourceKeys[i];
        var content = resources[path];
        if (!content) continue;

        if (path.match(/\.js$/)) {
          var script = document.createElement('script');
          script.textContent = content;
          body.appendChild(script);
        }
      }

    } catch(e) {
      showError('Failed to inject app: ' + (e.message || 'unknown error'));
    }
  }

  // ================================================================
  // Main: orchestrate the bootstrap process
  // ================================================================
  function main() {
    console.log('markproof bootstrap: starting');
    ensureBody();
    showStatus('Initializing...');

    // Derive the base content URL from the bootstrap URL
    var contentBaseUrl = BOOTSTRAP_URL.replace(/\/[^\/]*$/, '');

    var manifest;

    // Step 1: Fetch manifest
    showStatus('Fetching app manifest...');

    fetchManifest(contentBaseUrl).then(function(_manifest) {
      manifest = _manifest;
      showStatus('Verifying manifest...');

      // Step 2: Verify Ed25519 signature (if public key is embedded)
      if (EMBEDDED_PUBLIC_KEY && EMBEDDED_PUBLIC_KEY !== '__PUBLIC_KEY__') {
        return importEd25519PublicKey(EMBEDDED_PUBLIC_KEY).then(function(pubKey) {
          return verifyManifest(manifest, pubKey);
        });
      } else {
        // No public key embedded — unsigned development build
        console.warn('markproof: No signing key embedded. Manifest is NOT signature-verified.');
        if (!manifest.resources || !manifest.version) {
          throw new Error('Invalid manifest structure');
        }
        return manifest;
      }

    }).then(function(verifiedManifest) {
      manifest = verifiedManifest;

      // Step 3: In locked mode, verify manifest hash matches bookmarklet-embedded value
      if (UPDATE_MODE === 'locked' && MANIFEST_HASH) {
        var canonical = canonicalizeManifest(manifest);
        return sha256(canonical).then(function(hash) {
          if (hash !== MANIFEST_HASH) {
            throw new Error(
              'Locked mode: manifest hash mismatch. Expected: ' +
              MANIFEST_HASH + ', got: ' + hash
            );
          }
          return manifest;
        });
      }

      return manifest;

    }).then(function() {
      // Step 4: Fetch and verify all resources
      var resourcePaths = Object.keys(manifest.resources);
      showStatus('Fetching resources (0/' + resourcePaths.length + ')...');

      var resources = {};
      var chain = Promise.resolve();

      // Fetch resources sequentially to show progress
      for (var i = 0; i < resourcePaths.length; i++) {
        (function(index, path) {
          chain = chain.then(function() {
            showStatus('Fetching resources (' + (index + 1) + '/' + resourcePaths.length + ')...');
            return fetchResource(contentBaseUrl, path).then(function(content) {
              return verifyResource(content, manifest.resources[path].hash).then(function() {
                resources[path] = content;
              });
            });
          });
        })(i, resourcePaths[i]);
      }

      return chain.then(function() {
        return resources;
      });

    }).then(function(resources) {
      // Step 5: Render verified app
      hideStatus();
      injectApp(resources, manifest);

    }).catch(function(err) {
      showError('Bootstrap failed: ' + (err.message || 'unknown error'));
    });
  }

  // ================================================================
  // Start bootstrap
  // ================================================================
  main();

})();
