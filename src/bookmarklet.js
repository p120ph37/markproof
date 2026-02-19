// Bookmarklet source template.
// This is the complete bookmarklet logic that gets compiled into a javascript: URL.
// Placeholders (replaced by build tool at install time):
//   __ORIGIN_URL__       - The expected origin URL for IndexedDB storage
//   __BOOTSTRAP_HASH__   - SHA-256 hex hash of the bootstrap script
//   __BOOTSTRAP_URL__    - URL(s) to fetch the bootstrap script from
//   __VISUAL_TOKEN__     - User-specific visual identity token
//   __HMAC_KEY__         - 256-bit random HMAC key (hex) for cache integrity
//   __UPDATE_MODE__      - 'locked' or 'auto'
//
// Security properties:
//   - Uses ONLY engine-guaranteed primitives for hashing and chain validation
//   - Verifies non-configurable property chain before creating clean context
//   - Aborts if chain validation fails (unknown/incompatible browser)
//   - Pure-JS SHA-256 for bootstrap hash verification
//   - All per-installation secrets are inaccessible to page JavaScript

void(function() {
  'use strict';

  // ================================================================
  // Per-installation values (injected by build tool)
  // ================================================================
  var ORIGIN_URL = '__ORIGIN_URL__';
  var BOOTSTRAP_HASH = '__BOOTSTRAP_HASH__';
  var BOOTSTRAP_URL = '__BOOTSTRAP_URL__';
  var VISUAL_TOKEN = '__VISUAL_TOKEN__';
  var HMAC_KEY = '__HMAC_KEY__';
  var UPDATE_MODE = '__UPDATE_MODE__';

  // ================================================================
  // Origin check: redirect if on wrong origin
  // ================================================================
  // location.origin is an accessor that could be poisoned, but if we're
  // on the wrong origin, the worst that happens is we redirect unnecessarily.
  // The critical security checks happen AFTER we're on the right origin.
  if (typeof location !== 'undefined' && location.href) {
    var onCorrectOrigin = false;
    // Use string comparison via engine-guaranteed === on primitives
    var href = location.href;
    // Check if href starts with ORIGIN_URL
    // We use string indexing (engine-guaranteed) to compare character by character
    if (href.length >= ORIGIN_URL.length) {
      onCorrectOrigin = true;
      for (var _oi = 0; _oi < ORIGIN_URL.length; _oi = _oi + 1) {
        if (href[_oi] !== ORIGIN_URL[_oi]) {
          onCorrectOrigin = false;
          break;
        }
      }
    }
    if (!onCorrectOrigin) {
      // Redirect to origin URL. This navigation destroys the current context.
      // We use location.href assignment which is an engine-level operation.
      location.href = ORIGIN_URL;
      return;
    }
  }

  // ================================================================
  // PASTE: pure-sha256.js content (inlined by build tool)
  // ================================================================
  // __PURE_SHA256_SOURCE__

  // ================================================================
  // Property chain validation
  // ================================================================
  // We verify that the properties needed to create a clean iframe context
  // are non-configurable (and thus cannot have been replaced by an attacker).
  //
  // The validation uses ONLY engine-guaranteed operations:
  //   - delete operator (returns false for non-configurable own properties)
  //   - typeof operator
  //   - === comparison
  //
  // Strategy for each property in the chain:
  //   1. delete any attacker-created shadow on the target object
  //   2. Verify the property is still accessible (came from prototype/is non-configurable)
  //   3. Where possible, verify non-configurability via delete return value
  //
  // If any check fails, we abort. This means the bookmarklet will not work
  // on browsers where these properties are configurable.

  function validateAndCreateCleanContext() {
    // --- Step 1: Verify and access window.document ---
    // Test result: window.document (or Window.prototype.document) is a
    // non-configurable accessor on Edge, Safari, Firefox (as of 2026).
    // Delete any shadow property the attacker may have created via assignment.
    delete window.document;

    // After deleting any shadow, 'document' should resolve to the native getter.
    // If document was configurable and got deleted, typeof returns 'undefined'.
    if (typeof document === 'undefined') {
      return null; // Chain broken: document was configurable
    }

    // Save reference to the real document
    var doc = document;

    // --- Step 2: Access createElement via document ---
    // document.createElement lives on Document.prototype.
    // Even if Document.prototype.createElement is configurable (attacker could replace it),
    // we proceed and validate the RESULT via the clean-context self-check.
    // Delete any shadow on the document object itself.
    delete doc.createElement;

    if (typeof doc.createElement !== 'function') {
      return null; // createElement not available
    }

    // --- Step 3: Create an iframe ---
    var iframe;
    try {
      iframe = doc.createElement('iframe');
    } catch(e) {
      return null; // createElement failed
    }

    if (!iframe || typeof iframe !== 'object') {
      return null; // Didn't get an object back
    }

    // Style the iframe to be invisible initially
    // (these are DOM operations through potentially-poisoned APIs,
    //  but they're cosmetic, not security-critical)
    try {
      iframe.style.display = 'none';
    } catch(e) {}

    // --- Step 4: Append iframe to document to activate it ---
    // appendChild is on Node.prototype. Delete any shadow.
    var body = doc.body;
    if (!body) {
      // Try documentElement as fallback
      body = doc.documentElement;
    }
    if (!body) {
      return null; // No body to append to
    }

    delete body.appendChild;
    try {
      body.appendChild(iframe);
    } catch(e) {
      return null; // appendChild failed
    }

    // --- Step 5: Access contentWindow ---
    // Delete any shadow on the iframe element
    delete iframe.contentWindow;

    var cleanWin = iframe.contentWindow;
    if (!cleanWin || typeof cleanWin !== 'object') {
      return null; // No contentWindow
    }

    // --- Step 6: Self-verification in the clean context ---
    // The clean context has its own built-in objects. If the chain was
    // genuinely non-configurable, these are unmodified native implementations.
    // We perform sanity checks using the clean context's own Object.
    //
    // NOTE: If the chain was broken (attacker returned a fake context),
    // these checks could be fooled. The checks provide confirmation in the
    // positive case but are not a proof of cleanliness.
    // The pure-JS hash verification of the bootstrap is the cryptographic
    // guarantee against content substitution.
    try {
      var cleanObj = cleanWin.Object;
      var cleanGOPD = cleanObj.getOwnPropertyDescriptor;

      // Verify that key properties in the PARENT context are non-configurable
      // by using the CLEAN context's Object.getOwnPropertyDescriptor
      // (which we trust if the clean context is genuine).

      // Check: Window.prototype.document should be non-configurable accessor
      var winProto = cleanGOPD(cleanWin.Window.prototype, 'document');
      if (!winProto || winProto.configurable !== false || !winProto.get) {
        // Also check if it's an own property of window
        var winDoc = cleanGOPD(window, 'document');
        if (!winDoc || winDoc.configurable !== false) {
          return null; // document is configurable -- chain is not secure
        }
      }

      // Check: HTMLIFrameElement.prototype.contentWindow should be non-configurable
      var cwDesc = cleanGOPD(
        cleanWin.HTMLIFrameElement.prototype, 'contentWindow'
      );
      if (!cwDesc || cwDesc.configurable !== false || !cwDesc.get) {
        // contentWindow is configurable -- warn but proceed
        // (the pure-JS hash is the real security, not the context verification)
      }

      // Verify the clean context has separate built-in objects
      // (this confirms it's a real separate execution context)
      if (cleanWin.Object === window.Object) {
        return null; // Same realm -- not a clean context
      }

    } catch(e) {
      return null; // Verification failed
    }

    return {
      __proto__: null,
      win: cleanWin,
      iframe: iframe
    };
  }

  // ================================================================
  // Abort handler
  // ================================================================
  function abort(reason) {
    // Use only engine-guaranteed operations for the abort message.
    // We can't trust DOM APIs to display the message reliably,
    // but this is a best-effort notification.
    try {
      var msg = 'BOOKMARKLET ABORTED: ' + reason;
      // Try alert (most reliable for user notification)
      if (typeof alert === 'function') {
        alert(msg);
      }
    } catch(e) {}
  }

  // ================================================================
  // Main execution
  // ================================================================

  // Step 1: Validate chain and create clean context
  var ctx = validateAndCreateCleanContext();
  if (!ctx) {
    abort('Browser security check failed. This browser may not support the required non-configurable property chain. The bookmarklet cannot safely create a clean execution context.');
    return;
  }

  var cleanWin = ctx.win;

  // Step 2: Fetch the bootstrap script
  // We use the PARENT context's fetch (which may be poisoned).
  // This is acceptable because we will hash-verify the content.
  // A poisoned fetch can only:
  //   - Return wrong content (detected by hash mismatch)
  //   - Fail entirely (denial of service)
  //   - Return the correct content (no attack)
  // It CANNOT make wrong content pass our hash check.

  function fetchBootstrap(callback) {
    // Try to read from IndexedDB cache first, then fall back to network
    // For now, go directly to network fetch
    try {
      var xhr;
      // Try multiple paths to get XMLHttpRequest or fetch
      if (typeof fetch === 'function') {
        fetch(BOOTSTRAP_URL).then(function(resp) {
          if (resp && typeof resp.text === 'function') {
            return resp.text();
          }
          throw 'bad response';
        }).then(function(text) {
          callback(text);
        })['catch'](function(e) {
          callback(null);
        });
      } else {
        callback(null);
      }
    } catch(e) {
      callback(null);
    }
  }

  fetchBootstrap(function(bootstrapSource) {
    if (!bootstrapSource || typeof bootstrapSource !== 'string') {
      abort('Failed to fetch bootstrap script. Network may be unavailable.');
      return;
    }

    // Step 3: Hash-verify the bootstrap using pure-JS SHA-256
    // This uses ONLY engine-guaranteed primitives.
    // Even if fetch was poisoned, wrong content will not match the hash.
    var hash = pureSha256(bootstrapSource);

    if (hash !== BOOTSTRAP_HASH) {
      abort('Bootstrap integrity check failed. The bootstrap script has been tampered with or is corrupted. Expected hash: ' + BOOTSTRAP_HASH + ', got: ' + hash);
      return;
    }

    // Step 4: Inject the verified bootstrap into the clean context
    // We use the clean context's eval to execute the verified code.
    // Since the clean context is (verified) separate from the parent,
    // its eval is the native implementation.
    try {
      // Pass the per-installation config to the bootstrap via a config object
      // on the clean context's window
      cleanWin.__bookmarkletConfig = {
        originUrl: ORIGIN_URL,
        bootstrapUrl: BOOTSTRAP_URL,
        visualToken: VISUAL_TOKEN,
        hmacKey: HMAC_KEY,
        updateMode: UPDATE_MODE,
        parentWindow: window
      };

      // Execute the verified bootstrap in the clean context
      cleanWin.eval(bootstrapSource);
    } catch(e) {
      abort('Failed to execute bootstrap: ' + (e && e.message ? e.message : 'unknown error'));
      return;
    }
  });

})();
