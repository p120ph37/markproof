// Pure-JS SHA-256 implementation using ONLY engine-guaranteed primitives.
//
// This code is designed to run correctly even in a fully API-poisoned JS
// environment where String.prototype, Array.prototype, Math, etc. have been
// overridden by an attacker. It relies ONLY on:
//   - Arithmetic/bitwise operators (+, -, *, >>>, &, |, ^, ~)
//   - Comparison operators (===, !==, <, >)
//   - typeof operator
//   - {__proto__: null} objects (engine-level, no prototype pollution)
//   - String indexing str[i] (engine-internal [[Get]] on String exotic objects)
//   - String .length (non-configurable own property of string primitives)
//   - function declarations (always create real functions from syntax)
//   - for/while/if control flow
//   - Variable declaration and assignment
//
// It does NOT use:
//   - String.prototype.charCodeAt (could be poisoned)
//   - Array.prototype.* (could be poisoned)
//   - Math.* (could be poisoned)
//   - Object.* (could be poisoned)
//   - Any method calls on potentially-poisoned prototypes

// === ASCII lookup table ===
// Built using only string literals, string indexing, and {__proto__: null}
// This avoids dependence on String.prototype.charCodeAt.
var _ct = {__proto__: null};
// Printable ASCII 32-126
var _cs = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~';
for (var _ci = 0; _ci < _cs.length; _ci = _ci + 1) {
  _ct[_cs[_ci]] = _ci + 32;
}
// Control characters needed for source code
_ct['\t'] = 9;
_ct['\n'] = 10;
_ct['\r'] = 13;

// === SHA-256 constants ===
// First 32 bits of fractional parts of cube roots of first 64 primes
// Stored as a {__proto__: null} integer-indexed object (not an Array)
var _K = {__proto__: null};
_K[0]=0x428a2f98; _K[1]=0x71374491; _K[2]=0xb5c0fbcf; _K[3]=0xe9b5dba5;
_K[4]=0x3956c25b; _K[5]=0x59f111f1; _K[6]=0x923f82a4; _K[7]=0xab1c5ed5;
_K[8]=0xd807aa98; _K[9]=0x12835b01; _K[10]=0x243185be; _K[11]=0x550c7dc3;
_K[12]=0x72be5d74; _K[13]=0x80deb1fe; _K[14]=0x9bdc06a7; _K[15]=0xc19bf174;
_K[16]=0xe49b69c1; _K[17]=0xefbe4786; _K[18]=0x0fc19dc6; _K[19]=0x240ca1cc;
_K[20]=0x2de92c6f; _K[21]=0x4a7484aa; _K[22]=0x5cb0a9dc; _K[23]=0x76f988da;
_K[24]=0x983e5152; _K[25]=0xa831c66d; _K[26]=0xb00327c8; _K[27]=0xbf597fc7;
_K[28]=0xc6e00bf3; _K[29]=0xd5a79147; _K[30]=0x06ca6351; _K[31]=0x14292967;
_K[32]=0x27b70a85; _K[33]=0x2e1b2138; _K[34]=0x4d2c6dfc; _K[35]=0x53380d13;
_K[36]=0x650a7354; _K[37]=0x766a0abb; _K[38]=0x81c2c92e; _K[39]=0x92722c85;
_K[40]=0xa2bfe8a1; _K[41]=0xa81a664b; _K[42]=0xc24b8b70; _K[43]=0xc76c51a3;
_K[44]=0xd192e819; _K[45]=0xd6990624; _K[46]=0xf40e3585; _K[47]=0x106aa070;
_K[48]=0x19a4c116; _K[49]=0x1e376c08; _K[50]=0x2748774c; _K[51]=0x34b0bcb5;
_K[52]=0x391c0cb3; _K[53]=0x4ed8aa4a; _K[54]=0x5b9cca4f; _K[55]=0x682e6ff3;
_K[56]=0x748f82ee; _K[57]=0x78a5636f; _K[58]=0x84c87814; _K[59]=0x8cc70208;
_K[60]=0x90befffa; _K[61]=0xa4506ceb; _K[62]=0xbef9a3f7; _K[63]=0xc67178f2;

// === Hex lookup ===
var _hex = '0123456789abcdef';

// === SHA-256 helper functions (all use bitwise ops only) ===

function _rotr(n, x) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function _sigma0(x) {
  return (_rotr(2, x) ^ _rotr(13, x) ^ _rotr(22, x)) >>> 0;
}

function _sigma1(x) {
  return (_rotr(6, x) ^ _rotr(11, x) ^ _rotr(25, x)) >>> 0;
}

function _gamma0(x) {
  return (_rotr(7, x) ^ _rotr(18, x) ^ (x >>> 3)) >>> 0;
}

function _gamma1(x) {
  return (_rotr(17, x) ^ _rotr(19, x) ^ (x >>> 10)) >>> 0;
}

function _ch(x, y, z) {
  return ((x & y) ^ (~x & z)) >>> 0;
}

function _maj(x, y, z) {
  return ((x & y) ^ (x & z) ^ (y & z)) >>> 0;
}

// Safe 32-bit addition (two operands)
function _add2(a, b) {
  return ((a + b) & 0xFFFFFFFF) >>> 0;
}

// Safe 32-bit addition (multiple operands via sequential addition)
function _add() {
  var r = 0;
  for (var i = 0; i < arguments.length; i = i + 1) {
    r = ((r + arguments[i]) & 0xFFFFFFFF) >>> 0;
  }
  return r;
}

// === Main SHA-256 function ===
// Input: ASCII string (only characters present in _ct lookup)
// Output: 64-character lowercase hex string
function pureSha256(str) {
  // Convert string to byte values using lookup table
  var msgLen = str.length;
  var bytes = {__proto__: null};
  for (var i = 0; i < msgLen; i = i + 1) {
    var ch = str[i];
    var code = _ct[ch];
    if (code === undefined) {
      // Non-ASCII or unmapped character: abort
      return '';
    }
    bytes[i] = code;
  }

  // Pre-processing: append bit '1', then zeros, then 64-bit big-endian length
  var bitLen = msgLen * 8;

  // Calculate padded length (must be multiple of 64 bytes)
  // Need: msgLen + 1 (0x80 byte) + padding + 8 (length) ≡ 0 (mod 64)
  var padded = msgLen + 1;
  while ((padded % 64) !== 56) {
    padded = padded + 1;
  }
  padded = padded + 8; // total padded length

  // Build padded message
  var msg = {__proto__: null};
  for (var i = 0; i < msgLen; i = i + 1) {
    msg[i] = bytes[i];
  }
  msg[msgLen] = 0x80;
  for (var i = msgLen + 1; i < padded - 8; i = i + 1) {
    msg[i] = 0;
  }

  // Append length as 64-bit big-endian
  // For strings up to ~500MB, the high 32 bits are sufficient
  // JavaScript bitwise ops work on 32 bits, so we handle both words
  var lenHigh = 0; // For messages < 2^32 bits (536MB), this is 0
  var lenLow = bitLen;
  // If the message is very long, we'd need proper 64-bit math
  // For our use case (bootstrap scripts), this is fine
  msg[padded - 8] = (lenHigh >>> 24) & 0xFF;
  msg[padded - 7] = (lenHigh >>> 16) & 0xFF;
  msg[padded - 6] = (lenHigh >>> 8) & 0xFF;
  msg[padded - 5] = lenHigh & 0xFF;
  msg[padded - 4] = (lenLow >>> 24) & 0xFF;
  msg[padded - 3] = (lenLow >>> 16) & 0xFF;
  msg[padded - 2] = (lenLow >>> 8) & 0xFF;
  msg[padded - 1] = lenLow & 0xFF;

  // Initialize hash values (first 32 bits of fractional parts of square roots of first 8 primes)
  var H0 = 0x6a09e667;
  var H1 = 0xbb67ae85;
  var H2 = 0x3c6ef372;
  var H3 = 0xa54ff53a;
  var H4 = 0x510e527f;
  var H5 = 0x9b05688c;
  var H6 = 0x1f83d9ab;
  var H7 = 0x5be0cd19;

  // Process each 64-byte (512-bit) block
  var numBlocks = padded / 64;
  for (var block = 0; block < numBlocks; block = block + 1) {
    var offset = block * 64;

    // Prepare message schedule (W)
    var W = {__proto__: null};

    // First 16 words: directly from message bytes (big-endian)
    for (var t = 0; t < 16; t = t + 1) {
      var j = offset + t * 4;
      W[t] = ((msg[j] << 24) | (msg[j+1] << 16) | (msg[j+2] << 8) | msg[j+3]) >>> 0;
    }

    // Extend to 64 words
    for (var t = 16; t < 64; t = t + 1) {
      W[t] = _add(_gamma1(W[t-2]), W[t-7], _gamma0(W[t-15]), W[t-16]);
    }

    // Initialize working variables
    var a = H0, b = H1, c = H2, d = H3;
    var e = H4, f = H5, g = H6, h = H7;

    // Compression function
    for (var t = 0; t < 64; t = t + 1) {
      var T1 = _add(h, _sigma1(e), _ch(e, f, g), _K[t], W[t]);
      var T2 = _add(_sigma0(a), _maj(a, b, c));
      h = g;
      g = f;
      f = e;
      e = _add(d, T1);
      d = c;
      c = b;
      b = a;
      a = _add(T1, T2);
    }

    // Update hash values
    H0 = _add(H0, a);
    H1 = _add(H1, b);
    H2 = _add(H2, c);
    H3 = _add(H3, d);
    H4 = _add(H4, e);
    H5 = _add(H5, f);
    H6 = _add(H6, g);
    H7 = _add(H7, h);
  }

  // Produce hex output using only string indexing on _hex literal
  var result = '';
  var hashWords = {__proto__: null};
  hashWords[0] = H0; hashWords[1] = H1; hashWords[2] = H2; hashWords[3] = H3;
  hashWords[4] = H4; hashWords[5] = H5; hashWords[6] = H6; hashWords[7] = H7;

  for (var w = 0; w < 8; w = w + 1) {
    var val = hashWords[w];
    for (var b = 28; b >= 0; b = b - 4) {
      result = result + _hex[(val >>> b) & 0xF];
    }
  }

  return result;
}
