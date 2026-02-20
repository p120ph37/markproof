// Bootstrap script for the markproof trust-anchored web app loader.
//
// This script is loaded via a <script> tag with SRI (Subresource Integrity)
// inside a data:text/html page. The data-URL page provides a guaranteed clean
// browsing context with an opaque origin, completely isolated from any
// compromised page JavaScript.
//
// Because it runs in a clean data-URL context, it can trust:
//   - crypto.subtle (native, unmodified WebCrypto API)
//   - fetch (native, unmodified Fetch API)
//   - All built-in objects (Object, Array, Promise, etc.)
//
// It receives config from the data-URL page via:
//   window.__markproofConfig = {
//     originUrl, bootstrapUrl, updateMode, manifestHash
//   }
//
// Responsibilities:
//   1. Read config
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
  // Configuration (from data-URL inline script)
  // ================================================================
  var config = window.__markproofConfig;
  if (!config) {
    throw new Error('Bootstrap: missing __markproofConfig');
  }

  var ORIGIN_URL = config.originUrl;
  var BOOTSTRAP_URL = config.bootstrapUrl;
  var UPDATE_MODE = config.updateMode; // 'locked' or 'auto'
  var MANIFEST_HASH = config.manifestHash || '';

  // Clean up config reference
  delete window.__markproofConfig;

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
  // Crypto: SHA-256 hash (using clean context's crypto.subtle)
  // ================================================================
  function sha256(data) {
    var buffer = (typeof data === 'string') ? stringToBuffer(data) : data;
    return crypto.subtle.digest('SHA-256', buffer).then(function(hash) {
      return bytesToHex(new Uint8Array(hash));
    });
  }

  // ================================================================
  // Crypto: Ed25519 signature verification
  // ================================================================
  function importEd25519PublicKey(base64Key) {
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
    try {
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
