import { describe, test, expect, beforeAll } from 'bun:test';
import { buildForTest, TEST_DIST, getKeypair } from '../helpers';
import { startServer } from '../server';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { createHash, createPublicKey, verify } from 'crypto';
import { sha256hex, canonicalizeManifest, type Manifest } from '../../src/plugin/manifest';

let buildResult: Awaited<ReturnType<typeof buildForTest>>;

beforeAll(async () => {
  buildResult = await buildForTest('http://localhost:9999');
}, 30_000);

describe('build output', () => {
  test('creates dist-test directory with expected files', () => {
    expect(existsSync(join(TEST_DIST, 'bootstrap.js'))).toBe(true);
    expect(existsSync(join(TEST_DIST, 'manifest.json'))).toBe(true);
    expect(existsSync(join(TEST_DIST, 'index.html'))).toBe(true);
    expect(existsSync(join(TEST_DIST, 'generator.js'))).toBe(true);
    expect(existsSync(join(TEST_DIST, 'game.js'))).toBe(true);
    expect(existsSync(join(TEST_DIST, 'style.css'))).toBe(true);
    expect(existsSync(join(TEST_DIST, 'app.html'))).toBe(true);
  });

  test('manifest has correct structure', () => {
    const manifest: Manifest = JSON.parse(
      readFileSync(join(TEST_DIST, 'manifest.json'), 'utf-8')
    );
    expect(manifest.version).toBe('0.0.1-test');
    expect(manifest.timestamp).toBeDefined();
    expect(manifest.resources).toBeDefined();
    expect(manifest.signature).toBeDefined();
  });

  test('manifest resource hashes match actual file contents', () => {
    const manifest: Manifest = JSON.parse(
      readFileSync(join(TEST_DIST, 'manifest.json'), 'utf-8')
    );

    for (const [path, resource] of Object.entries(manifest.resources)) {
      const filename = path.replace(/^\//, '');
      const content = readFileSync(join(TEST_DIST, filename));
      const expectedHash = 'sha256-' + sha256hex(content);
      expect(resource.hash).toBe(expectedHash);
      expect(resource.size).toBe(content.length);
    }
  });

  test('bootstrap.js has public key embedded', () => {
    const bootstrap = readFileSync(join(TEST_DIST, 'bootstrap.js'), 'utf-8');
    const keypair = getKeypair();
    expect(bootstrap).toContain(keypair.publicKey);
    // The variable assignment should use the real key, not the placeholder
    expect(bootstrap).not.toContain("EMBEDDED_PUBLIC_KEY = '__PUBLIC_KEY__'");
  });

  test('bootstrapHashBase64 matches actual bootstrap.js hash', () => {
    const bootstrap = readFileSync(join(TEST_DIST, 'bootstrap.js'));
    const hash = createHash('sha256').update(bootstrap).digest('base64');
    expect(buildResult.bootstrapHashBase64).toBe(hash);
  });

  test('manifest signature is valid', () => {
    const manifest: Manifest = JSON.parse(
      readFileSync(join(TEST_DIST, 'manifest.json'), 'utf-8')
    );
    const keypair = getKeypair();

    const canonical = canonicalizeManifest(manifest);
    const pubKeyObj = createPublicKey({
      key: Buffer.from(keypair.publicKey, 'base64'),
      format: 'der',
      type: 'spki',
    });

    const valid = verify(
      null,
      Buffer.from(canonical),
      pubKeyObj,
      Buffer.from(manifest.signature!, 'hex')
    );
    expect(valid).toBe(true);
  });

  test('generator.js embeds the correct bootstrap URL', () => {
    const generator = readFileSync(join(TEST_DIST, 'generator.js'), 'utf-8');
    expect(generator).toContain('http://localhost:9999/bootstrap.js');
  });

  test('generator.js embeds the correct bootstrap hash', () => {
    const generator = readFileSync(join(TEST_DIST, 'generator.js'), 'utf-8');
    expect(generator).toContain(buildResult.bootstrapHashBase64);
  });

  test('installer HTML has app name replaced', () => {
    const html = readFileSync(join(TEST_DIST, 'index.html'), 'utf-8');
    expect(html).toContain('Test App');
    expect(html).not.toContain('__APP_NAME__');
  });
});

describe('build-time vs runtime hash consistency', () => {
  test('Node.js sha256hex matches Web Crypto sha256 for all resources', async () => {
    // This verifies that our build-time hashing (Node.js crypto) produces
    // the same hex hashes as the runtime hashing (Web Crypto in bootstrap.js).
    // We do this by computing hashes with both approaches.

    const manifest: Manifest = JSON.parse(
      readFileSync(join(TEST_DIST, 'manifest.json'), 'utf-8')
    );

    for (const [path, resource] of Object.entries(manifest.resources)) {
      const filename = path.replace(/^\//, '');
      const content = readFileSync(join(TEST_DIST, filename), 'utf-8');

      // Build-time hash (Node.js)
      const nodeHash = sha256hex(content);

      // Runtime-equivalent hash (Web Crypto simulation via Node.js)
      const encoder = new TextEncoder();
      const data = encoder.encode(content);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = new Uint8Array(hashBuffer);
      let webCryptoHash = '';
      for (const b of hashArray) {
        webCryptoHash += b.toString(16).padStart(2, '0');
      }

      expect(nodeHash).toBe(webCryptoHash);
    }
  });
});

describe('test server', () => {
  test('serves files with CORS headers', async () => {
    const srv = startServer(TEST_DIST);
    try {
      const resp = await fetch(srv.url + '/manifest.json');
      expect(resp.status).toBe(200);
      expect(resp.headers.get('access-control-allow-origin')).toBe('*');
      expect(resp.headers.get('content-type')).toContain('application/json');

      const body = await resp.json();
      expect(body.version).toBeDefined();
    } finally {
      srv.stop();
    }
  });

  test('returns 404 for missing files', async () => {
    const srv = startServer(TEST_DIST);
    try {
      const resp = await fetch(srv.url + '/nonexistent.txt');
      expect(resp.status).toBe(404);
      expect(resp.headers.get('access-control-allow-origin')).toBe('*');
    } finally {
      srv.stop();
    }
  });

  test('handles CORS preflight', async () => {
    const srv = startServer(TEST_DIST);
    try {
      const resp = await fetch(srv.url + '/manifest.json', {
        method: 'OPTIONS',
      });
      expect(resp.status).toBe(204);
      expect(resp.headers.get('access-control-allow-origin')).toBe('*');
      expect(resp.headers.get('access-control-allow-methods')).toContain('GET');
    } finally {
      srv.stop();
    }
  });
});
