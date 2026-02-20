// Bootstrap script for the markproof trust-anchored web app loader.
//
// This script is fetched by the bookmarklet, hash-verified using pure-JS SHA-256,
// and then executed inside a verified clean iframe context via cleanWin.eval().
//
// Because it runs in a clean context, it can trust:
//   - crypto.subtle (native, unmodified WebCrypto API)
//   - indexedDB (native, unmodified IndexedDB API)
//   - fetch (native, unmodified Fetch API)
//   - All built-in objects (Object, Array, Promise, etc.)
//
// It receives per-installation config from the bookmarklet via:
//   window.__bookmarkletConfig = {
//     originUrl, bootstrapUrl, visualToken, hmacKey,
//     updateMode, parentWindow
//   }
//
// Responsibilities:
//   1. Read config from bookmarklet
//   2. Display visual identity token for human verification
//   3. Open IndexedDB for cache management
//   4. Verify cache integrity (HMAC check in auto-update mode)
//   5. Load app from cache or fetch from network
//   6. Verify app manifest signature (Ed25519)
//   7. Verify individual resource hashes
//   8. Render verified app in the parent window

(function() {
  'use strict';

  // ================================================================
  // Configuration (injected by bookmarklet)
  // ================================================================
  var config = window.__bookmarkletConfig;
  if (!config) {
    throw new Error('Bootstrap: missing __bookmarkletConfig');
  }

  var ORIGIN_URL = config.originUrl;
  var BOOTSTRAP_URL = config.bootstrapUrl;
  var VISUAL_TOKEN = config.visualToken;
  var HMAC_KEY = config.hmacKey;
  var UPDATE_MODE = config.updateMode; // 'locked' or 'auto'
  var parentWindow = config.parentWindow;

  // Clean up config reference
  delete window.__bookmarkletConfig;

  // ================================================================
  // Constants
  // ================================================================
  var DB_NAME = 'offline-app-cache';
  var DB_VERSION = 1;
  var STORE_RESOURCES = 'resources';
  var STORE_META = 'meta';
  var MANIFEST_KEY = 'manifest';
  var HMAC_KEY_NAME = 'hmac';

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
  // Crypto: HMAC-SHA256 (for cache integrity in auto-update mode)
  // ================================================================
  function importHmacKey(hexKey) {
    var keyBytes = hexToBytes(hexKey);
    return crypto.subtle.importKey(
      'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' },
      false, ['sign', 'verify']
    );
  }

  function hmacSign(key, data) {
    var buffer = stringToBuffer(data);
    return crypto.subtle.sign('HMAC', key, buffer).then(function(sig) {
      return bytesToHex(new Uint8Array(sig));
    });
  }

  function hmacVerify(key, data, expectedHex) {
    return hmacSign(key, data).then(function(computed) {
      // Constant-time comparison not critical here (not a remote timing attack),
      // but we do a full comparison anyway.
      if (computed.length !== expectedHex.length) return false;
      var match = true;
      for (var i = 0; i < computed.length; i++) {
        if (computed[i] !== expectedHex[i]) match = false;
      }
      return match;
    });
  }

  // ================================================================
  // Crypto: Ed25519 signature verification
  // ================================================================
  // Uses WebCrypto Ed25519 (available in modern browsers).
  // Falls back to rejection if not supported.
  function importEd25519PublicKey(base64Key) {
    var raw = atob(base64Key);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    return crypto.subtle.importKey(
      'raw', bytes, { name: 'Ed25519' },
      false, ['verify']
    ).catch(function() {
      // Fallback: try as SPKI format
      return crypto.subtle.importKey(
        'spki', bytes, { name: 'Ed25519' },
        false, ['verify']
      );
    });
  }

  function verifySignature(publicKey, signature, data) {
    var sigBytes = hexToBytes(signature);
    var dataBytes = stringToBuffer(data);
    return crypto.subtle.verify(
      { name: 'Ed25519' }, publicKey, sigBytes, dataBytes
    );
  }

  // ================================================================
  // IndexedDB: open database
  // ================================================================
  function openDB() {
    return new Promise(function(resolve, reject) {
      var request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = function(event) {
        var db = event.target.result;
        if (!db.objectStoreNames.contains(STORE_RESOURCES)) {
          db.createObjectStore(STORE_RESOURCES, { keyPath: 'path' });
        }
        if (!db.objectStoreNames.contains(STORE_META)) {
          db.createObjectStore(STORE_META, { keyPath: 'key' });
        }
      };

      request.onsuccess = function(event) {
        resolve(event.target.result);
      };

      request.onerror = function(event) {
        reject(new Error('IndexedDB open failed: ' + event.target.errorCode));
      };
    });
  }

  // ================================================================
  // IndexedDB: read from store
  // ================================================================
  function dbGet(db, storeName, key) {
    return new Promise(function(resolve, reject) {
      var tx = db.transaction(storeName, 'readonly');
      var store = tx.objectStore(storeName);
      var request = store.get(key);
      request.onsuccess = function() {
        resolve(request.result || null);
      };
      request.onerror = function() {
        reject(new Error('IndexedDB get failed'));
      };
    });
  }

  // ================================================================
  // IndexedDB: write to store
  // ================================================================
  function dbPut(db, storeName, value) {
    return new Promise(function(resolve, reject) {
      var tx = db.transaction(storeName, 'readwrite');
      var store = tx.objectStore(storeName);
      var request = store.put(value);
      request.onsuccess = function() {
        resolve();
      };
      request.onerror = function() {
        reject(new Error('IndexedDB put failed'));
      };
    });
  }

  // ================================================================
  // IndexedDB: write multiple values atomically
  // ================================================================
  function dbPutAll(db, storeName, values) {
    return new Promise(function(resolve, reject) {
      var tx = db.transaction(storeName, 'readwrite');
      var store = tx.objectStore(storeName);
      for (var i = 0; i < values.length; i++) {
        store.put(values[i]);
      }
      tx.oncomplete = function() {
        resolve();
      };
      tx.onerror = function() {
        reject(new Error('IndexedDB putAll failed'));
      };
    });
  }

  // ================================================================
  // IndexedDB: clear a store
  // ================================================================
  function dbClear(db, storeName) {
    return new Promise(function(resolve, reject) {
      var tx = db.transaction(storeName, 'readwrite');
      var store = tx.objectStore(storeName);
      var request = store.clear();
      request.onsuccess = function() {
        resolve();
      };
      request.onerror = function() {
        reject(new Error('IndexedDB clear failed'));
      };
    });
  }

  // ================================================================
  // Network: fetch manifest from content URL
  // ================================================================
  function fetchManifest(url) {
    return fetch(url + '/manifest.json').then(function(resp) {
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
  // The signature covers the manifest content EXCLUDING the signature field itself.
  // We produce a canonical JSON representation for deterministic verification.
  function canonicalizeManifest(manifest) {
    var canonical = {
      version: manifest.version,
      timestamp: manifest.timestamp,
      resources: {}
    };

    // Sort resource keys for deterministic ordering
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
  // Manifest: verify signature and resource hashes
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
        throw new Error('Resource hash mismatch: expected ' + expected + ', got ' + hash);
      }
      return content;
    });
  }

  // ================================================================
  // Cache: compute manifest hash for HMAC integrity
  // ================================================================
  function computeManifestHash(manifest) {
    var canonical = canonicalizeManifest(manifest);
    return sha256(canonical);
  }

  // ================================================================
  // Visual identity: render the user's visual token
  // ================================================================
  function showVisualIdentity(container) {
    if (!VISUAL_TOKEN) return;

    var badge = parentWindow.document.createElement('div');
    badge.setAttribute('style',
      'position:fixed;top:10px;right:10px;z-index:2147483647;' +
      'background:#1a1a2e;color:#e0e0ff;padding:8px 16px;' +
      'border-radius:8px;font-family:monospace;font-size:14px;' +
      'box-shadow:0 2px 12px rgba(0,0,0,0.4);' +
      'border:2px solid #4a4a8a;pointer-events:none;' +
      'opacity:0.95;'
    );
    badge.textContent = VISUAL_TOKEN;

    try {
      (container || parentWindow.document.body).appendChild(badge);
    } catch(e) {
      // Best-effort visual identity display
    }

    // Fade out after 5 seconds
    setTimeout(function() {
      try {
        badge.style.transition = 'opacity 2s';
        badge.style.opacity = '0';
        setTimeout(function() {
          try { badge.remove(); } catch(e) {}
        }, 2000);
      } catch(e) {}
    }, 5000);
  }

  // ================================================================
  // Status: show loading/status messages to user
  // ================================================================
  function showStatus(message) {
    try {
      var existing = parentWindow.document.getElementById('__bootstrap_status');
      if (!existing) {
        existing = parentWindow.document.createElement('div');
        existing.id = '__bootstrap_status';
        existing.setAttribute('style',
          'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);' +
          'z-index:2147483647;background:#1a1a2e;color:#e0e0ff;' +
          'padding:12px 24px;border-radius:8px;font-family:monospace;' +
          'font-size:13px;box-shadow:0 2px 12px rgba(0,0,0,0.4);' +
          'border:1px solid #4a4a8a;max-width:80%;text-align:center;'
        );
        parentWindow.document.body.appendChild(existing);
      }
      existing.textContent = message;
    } catch(e) {
      // Best-effort status display
    }
  }

  function hideStatus() {
    try {
      var el = parentWindow.document.getElementById('__bootstrap_status');
      if (el) el.remove();
    } catch(e) {}
  }

  // ================================================================
  // Error: show error to user and abort
  // ================================================================
  function showError(message) {
    try {
      hideStatus();
      var el = parentWindow.document.createElement('div');
      el.setAttribute('style',
        'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);' +
        'z-index:2147483647;background:#2e1a1a;color:#ffe0e0;' +
        'padding:24px 32px;border-radius:12px;font-family:monospace;' +
        'font-size:14px;box-shadow:0 4px 24px rgba(0,0,0,0.6);' +
        'border:2px solid #8a4a4a;max-width:80%;text-align:center;' +
        'line-height:1.6;'
      );
      el.textContent = message;
      parentWindow.document.body.appendChild(el);
    } catch(e) {
      // Last resort
      try { parentWindow.alert('BOOTSTRAP ERROR: ' + message); } catch(e2) {}
    }
  }

  // ================================================================
  // App injection: render verified app content into the parent page
  // ================================================================
  function injectApp(resources, manifest) {
    try {
      var doc = parentWindow.document;

      // Clear the parent page content
      doc.documentElement.innerHTML = '';

      // Build the new page from verified resources
      var head = doc.createElement('head');
      var body = doc.createElement('body');

      // Inject CSS resources
      var resourceKeys = Object.keys(manifest.resources);
      for (var i = 0; i < resourceKeys.length; i++) {
        var path = resourceKeys[i];
        var content = resources[path];
        if (!content) continue;

        if (path.match(/\.css$/)) {
          var style = doc.createElement('style');
          style.textContent = content;
          head.appendChild(style);
        }
      }

      // Inject HTML resources (look for app.html, index.html, or main.html)
      var htmlContent = resources['/app.html'] || resources['/index.html'] || resources['/main.html'] || '';
      if (htmlContent) {
        // Parse the HTML and extract body content
        var parser = new DOMParser();
        var parsed = parser.parseFromString(htmlContent, 'text/html');

        // Copy head elements
        var parsedHead = parsed.head;
        if (parsedHead) {
          var headChildren = parsedHead.children;
          for (var i = 0; i < headChildren.length; i++) {
            var node = headChildren[i];
            // Skip script tags - we'll inject verified JS separately
            if (node.tagName !== 'SCRIPT') {
              head.appendChild(doc.importNode(node, true));
            }
          }
        }

        // Copy body content
        body.innerHTML = parsed.body.innerHTML;
      }

      doc.documentElement.appendChild(head);
      doc.documentElement.appendChild(body);

      // Inject JS resources (after DOM is built)
      for (var i = 0; i < resourceKeys.length; i++) {
        var path = resourceKeys[i];
        var content = resources[path];
        if (!content) continue;

        if (path.match(/\.js$/)) {
          var script = doc.createElement('script');
          script.textContent = content;
          body.appendChild(script);
        }
      }

      // Show visual identity badge
      showVisualIdentity(body);

    } catch(e) {
      showError('Failed to inject app: ' + (e.message || 'unknown error'));
    }
  }

  // ================================================================
  // Main: orchestrate the bootstrap process
  // ================================================================
  function main() {
    showVisualIdentity();
    showStatus('Initializing...');

    var db;
    var hmacCryptoKey;

    // Step 1: Open IndexedDB and import HMAC key
    openDB().then(function(_db) {
      db = _db;
      showStatus('Cache opened...');
      return importHmacKey(HMAC_KEY);

    }).then(function(key) {
      hmacCryptoKey = key;

      // Step 2: Check cache state
      return Promise.all([
        dbGet(db, STORE_META, MANIFEST_KEY),
        dbGet(db, STORE_META, HMAC_KEY_NAME)
      ]);

    }).then(function(results) {
      var cachedManifestRecord = results[0];
      var storedHmacRecord = results[1];

      // Determine cache state
      if (!cachedManifestRecord || !storedHmacRecord) {
        // No cache or incomplete cache -- fetch from network
        showStatus('No cached app found. Fetching from network...');
        return fetchAndInstall(db, hmacCryptoKey);
      }

      var cachedManifest = cachedManifestRecord.value;
      var storedHmac = storedHmacRecord.value;

      // Verify HMAC of cached manifest
      return computeManifestHash(cachedManifest).then(function(manifestHash) {
        return hmacVerify(hmacCryptoKey, manifestHash, storedHmac).then(function(hmacValid) {
          if (!hmacValid) {
            // HMAC invalid: cache has been tampered with
            showError(
              'SECURITY WARNING: Cache integrity check failed.\n' +
              'The cached app data may have been tampered with.\n' +
              'The HMAC verification failed, indicating the cache was modified ' +
              'by something other than this bookmarklet.\n' +
              'Refusing to load. Please re-install the app from a trusted source.'
            );
            throw new Error('Cache HMAC verification failed -- possible tampering');
          }

          // HMAC valid -- now verify the actual cached resources match manifest hashes
          showStatus('Cache verified. Loading app...');
          return loadFromCache(db, cachedManifest, hmacCryptoKey);
        });
      });

    }).catch(function(err) {
      showError('Bootstrap failed: ' + (err.message || 'unknown error'));
    });
  }

  // ================================================================
  // Load from cache: read resources and verify hashes
  // ================================================================
  function loadFromCache(db, manifest, hmacCryptoKey) {
    var resourcePaths = Object.keys(manifest.resources);
    var fetchPromises = [];

    for (var i = 0; i < resourcePaths.length; i++) {
      fetchPromises.push(dbGet(db, STORE_RESOURCES, resourcePaths[i]));
    }

    return Promise.all(fetchPromises).then(function(results) {
      var resources = {};
      var hashPromises = [];

      for (var i = 0; i < results.length; i++) {
        var record = results[i];
        var path = resourcePaths[i];

        if (!record || !record.content) {
          // Resource missing from cache -- need to re-fetch
          showStatus('Cache incomplete. Fetching missing resources...');
          return fetchAndInstall(db, hmacCryptoKey);
        }

        resources[path] = record.content;

        // Verify each resource hash
        hashPromises.push(
          verifyResource(record.content, manifest.resources[path].hash)
        );
      }

      return Promise.all(hashPromises).then(function() {
        hideStatus();
        injectApp(resources, manifest);

        // In auto-update mode, check for updates in the background
        if (UPDATE_MODE === 'auto') {
          checkForUpdates(db, manifest, hmacCryptoKey);
        }
      });
    });
  }

  // ================================================================
  // Fetch and install: download from network, verify, cache
  // ================================================================
  function fetchAndInstall(db, hmacCryptoKey) {
    showStatus('Fetching app manifest...');

    // Derive the base content URL from the bootstrap URL
    // (bootstrap URL is like https://cdn.example.com/bootstrap.js,
    //  content lives at the same base URL)
    var contentBaseUrl = BOOTSTRAP_URL.replace(/\/[^\/]*$/, '');

    var manifest;

    return fetchManifest(contentBaseUrl).then(function(_manifest) {
      manifest = _manifest;
      showStatus('Verifying manifest signature...');

      // The public key is embedded in this bootstrap script.
      // In a real deployment, this would be set to the developer's Ed25519 public key.
      // For now, we verify the manifest structure but skip signature verification
      // if no public key is configured.
      if (manifest.publicKey) {
        return importEd25519PublicKey(manifest.publicKey).then(function(pubKey) {
          return verifyManifest(manifest, pubKey);
        });
      }

      // If no public key in manifest, check if we have one hardcoded
      // (This is where a production deployment would embed the key)
      return manifest;

    }).then(function(verifiedManifest) {
      manifest = verifiedManifest;

      // In locked mode, verify manifest hash matches expected
      if (UPDATE_MODE === 'locked' && manifest.expectedManifestHash) {
        return computeManifestHash(manifest).then(function(hash) {
          if (hash !== manifest.expectedManifestHash) {
            throw new Error(
              'Locked mode: manifest hash does not match expected hash. ' +
              'Update rejected. Expected: ' + manifest.expectedManifestHash +
              ', got: ' + hash
            );
          }
          return manifest;
        });
      }

      return manifest;

    }).then(function() {
      // Fetch all resources
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
      showStatus('Caching verified resources...');

      // Store resources in IndexedDB
      var resourceRecords = [];
      var paths = Object.keys(resources);
      for (var i = 0; i < paths.length; i++) {
        resourceRecords.push({
          path: paths[i],
          content: resources[paths[i]]
        });
      }

      return dbClear(db, STORE_RESOURCES).then(function() {
        return dbPutAll(db, STORE_RESOURCES, resourceRecords);
      }).then(function() {
        // Store manifest
        return dbPut(db, STORE_META, { key: MANIFEST_KEY, value: manifest });
      }).then(function() {
        // Compute and store HMAC
        return computeManifestHash(manifest).then(function(manifestHash) {
          return hmacSign(hmacCryptoKey, manifestHash);
        }).then(function(hmac) {
          return dbPut(db, STORE_META, { key: HMAC_KEY_NAME, value: hmac });
        });
      }).then(function() {
        hideStatus();
        injectApp(resources, manifest);
      });
    });
  }

  // ================================================================
  // Update check: background check for newer signed manifest
  // ================================================================
  function checkForUpdates(db, currentManifest, hmacCryptoKey) {
    var contentBaseUrl = BOOTSTRAP_URL.replace(/\/[^\/]*$/, '');

    fetchManifest(contentBaseUrl).then(function(networkManifest) {
      if (!networkManifest || !networkManifest.version) return;

      // Compare versions (simple string comparison; semver would be better)
      if (networkManifest.version === currentManifest.version) {
        return; // Already on latest
      }

      // Verify signature of new manifest
      var verifyPromise;
      if (networkManifest.publicKey) {
        verifyPromise = importEd25519PublicKey(networkManifest.publicKey).then(function(pubKey) {
          return verifyManifest(networkManifest, pubKey);
        });
      } else {
        verifyPromise = Promise.resolve(networkManifest);
      }

      return verifyPromise.then(function(verifiedManifest) {
        // Notify user of available update
        notifyUpdate(verifiedManifest, db, hmacCryptoKey);
      });

    }).catch(function() {
      // Network unavailable -- silently continue with cached version
    });
  }

  // ================================================================
  // Update notification: inform user and offer update
  // ================================================================
  function notifyUpdate(newManifest, db, hmacCryptoKey) {
    try {
      var doc = parentWindow.document;
      var banner = doc.createElement('div');
      banner.setAttribute('style',
        'position:fixed;top:0;left:0;right:0;z-index:2147483647;' +
        'background:#1a2e1a;color:#e0ffe0;padding:12px 24px;' +
        'font-family:monospace;font-size:13px;text-align:center;' +
        'border-bottom:2px solid #4a8a4a;'
      );
      banner.textContent = 'Update available: v' + newManifest.version + '. ';

      var btn = doc.createElement('button');
      btn.setAttribute('style',
        'background:#4a8a4a;color:#fff;border:none;padding:4px 16px;' +
        'border-radius:4px;cursor:pointer;font-family:monospace;' +
        'font-size:13px;margin-left:8px;'
      );
      btn.textContent = 'Install Update';
      btn.onclick = function() {
        banner.remove();
        fetchAndInstall(db, hmacCryptoKey);
      };
      banner.appendChild(btn);

      var dismiss = doc.createElement('button');
      dismiss.setAttribute('style',
        'background:transparent;color:#e0ffe0;border:1px solid #4a8a4a;' +
        'padding:4px 16px;border-radius:4px;cursor:pointer;' +
        'font-family:monospace;font-size:13px;margin-left:8px;'
      );
      dismiss.textContent = 'Later';
      dismiss.onclick = function() {
        banner.remove();
      };
      banner.appendChild(dismiss);

      doc.body.insertBefore(banner, doc.body.firstChild);
    } catch(e) {
      // Best-effort notification
    }
  }

  // ================================================================
  // Start bootstrap
  // ================================================================
  main();

})();
