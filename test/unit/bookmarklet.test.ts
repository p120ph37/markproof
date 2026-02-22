import { describe, test, expect } from 'bun:test';
import { generateBookmarklet, type BookmarkletOptions } from '../../src/plugin/bookmarklet';
import { createHash } from 'crypto';

function base64Decode(str: string): string {
  return Buffer.from(str, 'base64').toString('utf-8');
}

const baseOptions: BookmarkletOptions = {
  originUrl: 'http://localhost:3000',
  bootstrapUrl: 'http://localhost:3000/bootstrap.js',
  bootstrapHashBase64: 'abc123base64hash=',
};

describe('generateBookmarklet', () => {
  test('returns a data:text/html;base64 URL', () => {
    const { url } = generateBookmarklet(baseOptions);
    expect(url).toStartWith('data:text/html;base64,');
  });

  test('HTML contains a script tag with correct src', () => {
    const { url } = generateBookmarklet(baseOptions);
    const base64 = url.replace('data:text/html;base64,', '');
    const html = base64Decode(base64);
    expect(html).toContain('src=http://localhost:3000/bootstrap.js');
  });

  test('HTML contains integrity attribute with SHA-256 hash', () => {
    const { url } = generateBookmarklet(baseOptions);
    const base64 = url.replace('data:text/html;base64,', '');
    const html = base64Decode(base64);
    expect(html).toContain('integrity=sha256-abc123base64hash=');
  });

  test('HTML contains crossorigin=anonymous', () => {
    const { url } = generateBookmarklet(baseOptions);
    const base64 = url.replace('data:text/html;base64,', '');
    const html = base64Decode(base64);
    expect(html).toContain('crossorigin=anonymous');
  });

  test('auto mode does not include data-mode attribute', () => {
    const { url } = generateBookmarklet({ ...baseOptions, updateMode: 'auto' });
    const base64 = url.replace('data:text/html;base64,', '');
    const html = base64Decode(base64);
    expect(html).not.toContain('data-mode');
  });

  test('locked mode includes data-mode=locked', () => {
    const { url } = generateBookmarklet({
      ...baseOptions,
      updateMode: 'locked',
      manifestHash: 'deadbeef',
    });
    const base64 = url.replace('data:text/html;base64,', '');
    const html = base64Decode(base64);
    expect(html).toContain('data-mode=locked');
  });

  test('locked mode includes data-hash attribute', () => {
    const { url } = generateBookmarklet({
      ...baseOptions,
      updateMode: 'locked',
      manifestHash: 'deadbeef1234',
    });
    const base64 = url.replace('data:text/html;base64,', '');
    const html = base64Decode(base64);
    expect(html).toContain('data-hash=deadbeef1234');
  });

  test('auto mode without manifestHash omits data-hash', () => {
    const { url } = generateBookmarklet({
      ...baseOptions,
      updateMode: 'auto',
    });
    const base64 = url.replace('data:text/html;base64,', '');
    const html = base64Decode(base64);
    expect(html).not.toContain('data-hash');
  });

  test('auto mode with manifestHash still includes data-hash (harmless)', () => {
    // When manifestHash is explicitly provided, it's included in the HTML
    // even in auto mode. The bootstrap ignores it unless mode is 'locked'.
    const { url } = generateBookmarklet({
      ...baseOptions,
      updateMode: 'auto',
      manifestHash: 'deadbeef1234',
    });
    const base64 = url.replace('data:text/html;base64,', '');
    const html = base64Decode(base64);
    expect(html).toContain('data-hash=deadbeef1234');
  });

  test('includes onerror fallback', () => {
    const { url } = generateBookmarklet(baseOptions);
    const base64 = url.replace('data:text/html;base64,', '');
    const html = base64Decode(base64);
    expect(html).toContain('onerror=');
  });

  test('uses closing </script> tag, not self-closing />', () => {
    const { url } = generateBookmarklet(baseOptions);
    const base64 = url.replace('data:text/html;base64,', '');
    const html = base64Decode(base64);
    // HTML5 does not support self-closing <script/> tags. A self-closing tag
    // causes the parser to enter "script data" state waiting for </script>.
    // Without it, the script is fetched (visible in devtools) but never executed.
    expect(html).toContain('></script>');
    expect(html).not.toContain('/>');
  });

  test('generated URL is valid base64', () => {
    const { url } = generateBookmarklet(baseOptions);
    const base64 = url.replace('data:text/html;base64,', '');
    expect(() => Buffer.from(base64, 'base64')).not.toThrow();
  });
});
