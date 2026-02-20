#!/usr/bin/env bun
/**
 * Build script for the Dino Runner demo app.
 *
 * Usage:
 *   bun run build.ts
 *
 * Environment variables:
 *   SIGNING_PRIVATE_KEY  - PEM-encoded Ed25519 private key (optional, for signing)
 *   PUBLIC_KEY           - Base64 SPKI public key (derived from private key if not set)
 *   ORIGIN_URL           - Override origin URL (default: GitHub Pages URL)
 *   APP_VERSION          - Override version string (default: from package.json)
 */

import { buildApp } from './src/plugin';
import { readFileSync } from 'fs';
import { join } from 'path';

// Load package.json for version
const pkg = JSON.parse(readFileSync(join(import.meta.dir, 'package.json'), 'utf8'));

// Configuration
const originUrl = process.env.ORIGIN_URL || 'https://markproof.ameriwether.com';
const privateKey = process.env.SIGNING_PRIVATE_KEY || undefined;
const publicKey = process.env.PUBLIC_KEY || undefined;
const version = process.env.APP_VERSION || pkg.version;

console.log('');
console.log('╔══════════════════════════════════════╗');
console.log('║   Dino Runner — markproof Build      ║');
console.log('╚══════════════════════════════════════╝');
console.log('');

const result = await buildApp({
  entrypoints: [join(import.meta.dir, 'src/demo/game.ts')],
  staticFiles: [
    join(import.meta.dir, 'src/demo/style.css'),
    { src: join(import.meta.dir, 'src/demo/index.html'), dest: 'app.html' },
  ],
  outdir: join(import.meta.dir, 'dist'),
  minify: true,
  appName: 'Dino Runner',
  version,
  originUrl,
  privateKey,
  publicKey,
  installer: {
    template: join(import.meta.dir, 'src/installer/index.html'),
    generatorEntrypoint: join(import.meta.dir, 'src/installer/generator.ts'),
  },
});

console.log('');
console.log('Manifest resources:');
for (const [path, resource] of Object.entries(result.manifest.resources)) {
  console.log(`  ${path}: ${resource.hash} (${resource.size} bytes)`);
}
console.log('');
console.log(`Bootstrap hash: ${result.bootstrapHash}`);
console.log(`Manifest signed: ${!!result.manifest.signature}`);
console.log('');
