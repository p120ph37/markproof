import { createHash, sign, generateKeyPairSync } from 'crypto';

export interface ManifestResource {
  hash: string;
  size: number;
  urls?: string[];  // Optional alternative fetch URLs (CDN mirrors)
}

export interface Manifest {
  version: string;
  timestamp: string;
  publicKey?: string;
  resources: Record<string, ManifestResource>;
  signature?: string;
}

/**
 * Compute SHA-256 hash of a string or buffer.
 */
export function sha256hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Produce a canonical JSON representation of a manifest for signing.
 * Excludes the signature field and sorts resource keys deterministically.
 */
export function canonicalizeManifest(manifest: Manifest): string {
  const canonical: Record<string, unknown> = {
    version: manifest.version,
    timestamp: manifest.timestamp,
  };

  if (manifest.publicKey) {
    canonical.publicKey = manifest.publicKey;
  }

  const resources: Record<string, { hash: string; size: number; urls?: string[] }> = {};
  const keys = Object.keys(manifest.resources).sort();
  for (const key of keys) {
    const r = manifest.resources[key];
    const entry: { hash: string; size: number; urls?: string[] } = {
      hash: r.hash,
      size: r.size,
    };
    if (r.urls && r.urls.length > 0) {
      entry.urls = r.urls;
    }
    resources[key] = entry;
  }
  canonical.resources = resources;

  return JSON.stringify(canonical);
}

/**
 * Generate a manifest from a set of built files.
 *
 * @param files Map of resource path (e.g., "/game.js") to file content
 * @param version Version string
 * @param publicKeyBase64 Optional base64-encoded Ed25519 public key
 */
export function generateManifest(
  files: Map<string, Buffer | string>,
  version: string,
  publicKeyBase64?: string,
): Manifest {
  const resources: Record<string, ManifestResource> = {};

  for (const [path, content] of files) {
    const buf = typeof content === 'string' ? Buffer.from(content) : content;
    resources[path] = {
      hash: 'sha256-' + sha256hex(buf),
      size: buf.length,
    };
  }

  const manifest: Manifest = {
    version,
    timestamp: new Date().toISOString(),
    resources,
  };

  if (publicKeyBase64) {
    manifest.publicKey = publicKeyBase64;
  }

  return manifest;
}

/**
 * Sign a manifest using an Ed25519 private key.
 * The signature covers the canonical representation (excluding the signature field).
 *
 * @param manifest The manifest to sign
 * @param privateKeyPem PEM-encoded Ed25519 private key
 * @returns The manifest with signature field populated
 */
export function signManifest(manifest: Manifest, privateKeyPem: string): Manifest {
  const canonical = canonicalizeManifest(manifest);
  const signature = sign(null, Buffer.from(canonical), privateKeyPem);

  return {
    ...manifest,
    signature: signature.toString('hex'),
  };
}

/**
 * Generate an Ed25519 keypair for manifest signing.
 * Returns PEM-encoded private key and base64-encoded raw public key.
 */
export function generateKeypair(): { privateKey: string; publicKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Also export raw public key as base64 for embedding
  const { publicKey: rawPub } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Actually, re-derive from the PEM we already have
  const pubKeyObj = require('crypto').createPublicKey(privateKey);
  const rawDer = pubKeyObj.export({ type: 'spki', format: 'der' });
  const rawBase64 = rawDer.toString('base64');

  return {
    privateKey,
    publicKey: rawBase64,
  };
}
