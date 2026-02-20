import { describe, test, expect } from 'bun:test';
import {
  sha256hex,
  canonicalizeManifest,
  generateManifest,
  signManifest,
  generateKeypair,
  type Manifest,
} from '../../src/plugin/manifest';
import { createPublicKey, verify } from 'crypto';

describe('sha256hex', () => {
  test('hashes empty string correctly', () => {
    const hash = sha256hex('');
    expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  test('hashes "hello" correctly', () => {
    const hash = sha256hex('hello');
    expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });

  test('hashes Buffer correctly', () => {
    const hash = sha256hex(Buffer.from('hello'));
    expect(hash).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });
});

describe('canonicalizeManifest', () => {
  test('excludes signature field', () => {
    const manifest: Manifest = {
      version: '1.0.0',
      timestamp: '2025-01-01T00:00:00.000Z',
      resources: {
        '/app.js': { hash: 'sha256-abc123', size: 100 },
      },
      signature: 'should-not-appear',
    };
    const canonical = canonicalizeManifest(manifest);
    const parsed = JSON.parse(canonical);
    expect(parsed.signature).toBeUndefined();
  });

  test('excludes urls from resources', () => {
    const manifest: Manifest = {
      version: '1.0.0',
      timestamp: '2025-01-01T00:00:00.000Z',
      resources: {
        '/app.js': { hash: 'sha256-abc123', size: 100, urls: ['https://cdn.example.com/app.js'] },
      },
    };
    const canonical = canonicalizeManifest(manifest);
    const parsed = JSON.parse(canonical);
    expect(parsed.resources['/app.js'].urls).toBeUndefined();
  });

  test('sorts resource keys alphabetically', () => {
    const manifest: Manifest = {
      version: '1.0.0',
      timestamp: '2025-01-01T00:00:00.000Z',
      resources: {
        '/z.js': { hash: 'sha256-zzz', size: 50 },
        '/a.js': { hash: 'sha256-aaa', size: 100 },
        '/m.css': { hash: 'sha256-mmm', size: 200 },
      },
    };
    const canonical = canonicalizeManifest(manifest);
    const keys = Object.keys(JSON.parse(canonical).resources);
    expect(keys).toEqual(['/a.js', '/m.css', '/z.js']);
  });

  test('is deterministic across calls', () => {
    const manifest: Manifest = {
      version: '1.0.0',
      timestamp: '2025-01-01T00:00:00.000Z',
      resources: {
        '/b.js': { hash: 'sha256-bbb', size: 200 },
        '/a.js': { hash: 'sha256-aaa', size: 100 },
      },
    };
    expect(canonicalizeManifest(manifest)).toBe(canonicalizeManifest(manifest));
  });
});

describe('generateManifest', () => {
  test('creates manifest with correct hashes and sizes', () => {
    const files = new Map<string, Buffer | string>();
    files.set('/hello.txt', 'hello');

    const manifest = generateManifest(files, '1.0.0');

    expect(manifest.version).toBe('1.0.0');
    expect(manifest.timestamp).toBeDefined();
    expect(manifest.resources['/hello.txt']).toBeDefined();
    expect(manifest.resources['/hello.txt'].hash).toBe(
      'sha256-2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    );
    expect(manifest.resources['/hello.txt'].size).toBe(5);
  });

  test('handles Buffer content', () => {
    const files = new Map<string, Buffer>();
    files.set('/data.bin', Buffer.from([0x00, 0x01, 0x02]));

    const manifest = generateManifest(files, '2.0.0');
    expect(manifest.resources['/data.bin'].size).toBe(3);
    expect(manifest.resources['/data.bin'].hash).toStartWith('sha256-');
  });

  test('has no signature by default', () => {
    const files = new Map<string, string>();
    files.set('/x.js', 'code');
    const manifest = generateManifest(files, '1.0.0');
    expect(manifest.signature).toBeUndefined();
  });
});

describe('signManifest', () => {
  test('adds valid Ed25519 signature', () => {
    const { privateKey, publicKey } = generateKeypair();

    const files = new Map<string, string>();
    files.set('/app.js', 'console.log("hello")');
    files.set('/style.css', 'body { color: red }');

    const manifest = generateManifest(files, '1.0.0');
    const signed = signManifest(manifest, privateKey);

    expect(signed.signature).toBeDefined();
    expect(signed.signature!.length).toBeGreaterThan(0);

    // Verify the signature using Node.js crypto
    const canonical = canonicalizeManifest(signed);
    const pubKeyObj = createPublicKey({
      key: Buffer.from(publicKey, 'base64'),
      format: 'der',
      type: 'spki',
    });
    const valid = verify(
      null,
      Buffer.from(canonical),
      pubKeyObj,
      Buffer.from(signed.signature!, 'hex')
    );
    expect(valid).toBe(true);
  });

  test('signature changes when content changes', () => {
    const { privateKey } = generateKeypair();

    const files1 = new Map<string, string>();
    files1.set('/app.js', 'version1');
    const m1 = signManifest(generateManifest(files1, '1.0.0'), privateKey);

    const files2 = new Map<string, string>();
    files2.set('/app.js', 'version2');
    const m2 = signManifest(generateManifest(files2, '1.0.0'), privateKey);

    expect(m1.signature).not.toBe(m2.signature);
  });
});

describe('generateKeypair', () => {
  test('returns valid PEM private key and base64 public key', () => {
    const { privateKey, publicKey } = generateKeypair();

    expect(privateKey).toContain('-----BEGIN PRIVATE KEY-----');
    expect(privateKey).toContain('-----END PRIVATE KEY-----');

    // Public key should be valid base64
    expect(() => Buffer.from(publicKey, 'base64')).not.toThrow();

    // Public key should be importable
    const pubKeyObj = createPublicKey({
      key: Buffer.from(publicKey, 'base64'),
      format: 'der',
      type: 'spki',
    });
    expect(pubKeyObj.type).toBe('public');
  });
});
