#!/usr/bin/env bun
/**
 * Ed25519 keypair generation utility.
 *
 * Usage:
 *   bun run src/plugin/keygen.ts
 *   bun run keygen
 *
 * Outputs:
 *   - Private key (PEM format) — store as a GitHub secret (SIGNING_PRIVATE_KEY)
 *   - Public key (base64 SPKI) — passed to the build as PUBLIC_KEY
 */

import { generateKeyPairSync, createPublicKey } from 'crypto';

const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Also export the public key as base64 for easy embedding
const pubKeyObj = createPublicKey(privateKey);
const spkiDer = pubKeyObj.export({ type: 'spki', format: 'der' });
const publicKeyBase64 = (spkiDer as Buffer).toString('base64');

console.log('=== Ed25519 Keypair Generated ===\n');

console.log('--- PRIVATE KEY (store as GitHub secret: SIGNING_PRIVATE_KEY) ---');
console.log(privateKey);

console.log('--- PUBLIC KEY (PEM) ---');
console.log(publicKey);

console.log('--- PUBLIC KEY (base64 SPKI, for build config) ---');
console.log(publicKeyBase64);
console.log();

console.log('Instructions:');
console.log('1. Copy the PRIVATE KEY and store it as a GitHub repository secret');
console.log('   named SIGNING_PRIVATE_KEY');
console.log('2. Set the PUBLIC KEY base64 in your build configuration or as');
console.log('   an environment variable PUBLIC_KEY');
console.log('3. NEVER commit the private key to the repository');
