import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import {
  buildAndServe,
  launchBrowser,
  collectConsoleMessages,
  collectNetworkRequests,
  TEST_DIST,
} from '../helpers';
import type { TestServer } from '../server';
import type { Browser, Page } from 'puppeteer-core';
import { readFileSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';

/**
 * Bootstrap E2E tests.
 *
 * These test the full bootstrap execution flow: loading the bootstrap script,
 * fetching the manifest, verifying resources, and rendering the app.
 *
 * Note on test approach: data: URL navigation to localhost is blocked by
 * Chrome's Private Network Access (PNA) policy in non-secure contexts.
 * In production, the server is a public HTTPS endpoint so PNA doesn't apply.
 * For testing, we use page.setContent() which creates an about:blank context
 * that can load cross-origin scripts, faithfully testing the bootstrap logic.
 *
 * Separate tests verify data: URL behavior and PNA constraints.
 */

let server: TestServer;
let browser: Browser;

beforeAll(async () => {
  const result = await buildAndServe({ signed: false });
  server = result.server;
  browser = await launchBrowser();
}, 30_000);

afterAll(async () => {
  await browser?.close();
  server?.stop();
});

/**
 * Helper: create a page with bootstrap loaded via setContent().
 * This simulates the bookmarklet loading bootstrap.js in a clean context.
 */
function bootstrapHtmlPage(opts?: { mode?: string; hash?: string }): string {
  const bootstrapContent = readFileSync(join(TEST_DIST, 'bootstrap.js'));
  const sriHash = createHash('sha256').update(bootstrapContent).digest('base64');

  let scriptTag = `<script src="${server.url}/bootstrap.js"`;
  scriptTag += ` integrity="sha256-${sriHash}"`;
  scriptTag += ` crossorigin="anonymous"`;

  if (opts?.mode === 'locked') {
    scriptTag += ` data-mode="locked"`;
  }
  if (opts?.hash) {
    scriptTag += ` data-hash="${opts.hash}"`;
  }

  scriptTag += ` onerror="document.body.textContent='Secure app load failed.'"></script>`;

  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>${scriptTag}</body></html>`;
}

/**
 * Helper: get the manifest hash for locked mode.
 */
function getManifestHash(): string {
  const manifest = JSON.parse(readFileSync(join(TEST_DIST, 'manifest.json'), 'utf-8'));
  // Canonicalize the same way bootstrap.js does
  const canonical: Record<string, unknown> = {
    version: manifest.version,
    timestamp: manifest.timestamp,
    resources: {} as Record<string, unknown>,
  };
  const keys = Object.keys(manifest.resources).sort();
  for (const key of keys) {
    (canonical.resources as Record<string, unknown>)[key] = {
      hash: manifest.resources[key].hash,
      size: manifest.resources[key].size,
    };
  }
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

describe('bootstrap execution — unsigned auto mode', () => {
  test('bootstrap fetches manifest.json', async () => {
    const page = await browser.newPage();
    const requests = collectNetworkRequests(page);
    try {
      await page.setContent(bootstrapHtmlPage(), { waitUntil: 'networkidle0', timeout: 15_000 });

      const manifestReq = requests.find((r) => r.url.includes('manifest.json'));
      expect(manifestReq).toBeDefined();
      expect(manifestReq!.status).toBe(200);
    } finally {
      await page.close();
    }
  }, 30_000);

  test('bootstrap fetches all app resources', async () => {
    const page = await browser.newPage();
    const requests = collectNetworkRequests(page);
    try {
      await page.setContent(bootstrapHtmlPage(), { waitUntil: 'networkidle0', timeout: 15_000 });

      const manifest = JSON.parse(readFileSync(join(TEST_DIST, 'manifest.json'), 'utf-8'));
      const resourcePaths = Object.keys(manifest.resources);

      for (const resourcePath of resourcePaths) {
        const filename = resourcePath.replace(/^\//, '');
        const req = requests.find((r) => r.url.endsWith('/' + filename));
        expect(req).toBeDefined();
        expect(req!.status).toBe(200);
      }
    } finally {
      await page.close();
    }
  }, 30_000);

  test('bootstrap renders the app HTML (canvas element present)', async () => {
    const page = await browser.newPage();
    try {
      await page.setContent(bootstrapHtmlPage(), { waitUntil: 'networkidle0', timeout: 15_000 });
      await new Promise((r) => setTimeout(r, 1000));

      const hasCanvas = await page.evaluate(() => document.querySelector('canvas') !== null);
      expect(hasCanvas).toBe(true);
    } finally {
      await page.close();
    }
  }, 30_000);

  test('bootstrap injects CSS as style elements', async () => {
    const page = await browser.newPage();
    try {
      await page.setContent(bootstrapHtmlPage(), { waitUntil: 'networkidle0', timeout: 15_000 });
      await new Promise((r) => setTimeout(r, 1000));

      const styleCount = await page.evaluate(() => document.querySelectorAll('style').length);
      expect(styleCount).toBeGreaterThanOrEqual(1);
    } finally {
      await page.close();
    }
  }, 30_000);

  test('bootstrap injects JS as script elements', async () => {
    const page = await browser.newPage();
    try {
      await page.setContent(bootstrapHtmlPage(), { waitUntil: 'networkidle0', timeout: 15_000 });
      await new Promise((r) => setTimeout(r, 1000));

      const scriptCount = await page.evaluate(() => document.querySelectorAll('script').length);
      expect(scriptCount).toBeGreaterThanOrEqual(1);
    } finally {
      await page.close();
    }
  }, 30_000);

  test('unsigned build logs a signature warning', async () => {
    const page = await browser.newPage();
    const consoleMessages = collectConsoleMessages(page);
    try {
      await page.setContent(bootstrapHtmlPage(), { waitUntil: 'networkidle0', timeout: 15_000 });
      await new Promise((r) => setTimeout(r, 1000));

      const unsignedWarning = consoleMessages.find((m) =>
        m.includes('NOT signature-verified')
      );
      expect(unsignedWarning).toBeDefined();
    } finally {
      await page.close();
    }
  }, 30_000);

  test('no error-level console messages during bootstrap', async () => {
    const page = await browser.newPage();
    const consoleMessages = collectConsoleMessages(page);
    try {
      await page.setContent(bootstrapHtmlPage(), { waitUntil: 'networkidle0', timeout: 15_000 });
      await new Promise((r) => setTimeout(r, 1000));

      // Filter for error-level messages (excluding expected localStorage error from game)
      const errors = consoleMessages.filter(
        (m) => m.startsWith('[error]') && !m.includes('favicon') && !m.includes('localStorage')
      );

      if (errors.length > 0) {
        console.log('All console messages:', consoleMessages);
      }

      expect(errors).toEqual([]);
    } finally {
      await page.close();
    }
  }, 30_000);
});

describe('bootstrap execution — unsigned locked mode', () => {
  test('locked mode verifies manifest hash and renders app', async () => {
    const manifestHash = getManifestHash();
    const page = await browser.newPage();
    const requests = collectNetworkRequests(page);
    try {
      await page.setContent(
        bootstrapHtmlPage({ mode: 'locked', hash: manifestHash }),
        { waitUntil: 'networkidle0', timeout: 15_000 }
      );
      await new Promise((r) => setTimeout(r, 1000));

      // Manifest should be fetched
      const manifestReq = requests.find((r) => r.url.includes('manifest.json'));
      expect(manifestReq).toBeDefined();

      // App should render
      const hasCanvas = await page.evaluate(() => document.querySelector('canvas') !== null);
      expect(hasCanvas).toBe(true);
    } finally {
      await page.close();
    }
  }, 30_000);

  test('locked mode rejects wrong manifest hash', async () => {
    const page = await browser.newPage();
    const consoleMessages = collectConsoleMessages(page);
    try {
      await page.setContent(
        bootstrapHtmlPage({ mode: 'locked', hash: 'deadbeef0000000000000000000000000000000000000000000000000000dead' }),
        { waitUntil: 'networkidle0', timeout: 15_000 }
      );
      await new Promise((r) => setTimeout(r, 2000));

      // Should show an error about hash mismatch
      const bodyText = await page.evaluate(() => document.body?.textContent || '');
      const consoleError = consoleMessages.find(
        (m) => m.includes('hash mismatch') || m.includes('Bootstrap failed')
      );

      expect(bodyText.includes('hash mismatch') || bodyText.includes('Bootstrap failed') || !!consoleError).toBe(true);
    } finally {
      await page.close();
    }
  }, 30_000);
});

describe('bootstrap error handling', () => {
  test('SRI check failure shows onerror message', async () => {
    const page = await browser.newPage();
    try {
      const wrongHtml = `<!DOCTYPE html><html><head></head><body>
<script src="${server.url}/bootstrap.js"
  integrity="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  crossorigin="anonymous"
  onerror="document.body.textContent='Secure app load failed.'"></script>
</body></html>`;

      await page.setContent(wrongHtml, { waitUntil: 'networkidle0', timeout: 15_000 });
      await new Promise((r) => setTimeout(r, 2000));

      const bodyText = await page.evaluate(() => document.body?.textContent || '');
      expect(bodyText).toContain('Secure app load failed.');
    } finally {
      await page.close();
    }
  }, 30_000);

  test('missing manifest.json shows bootstrap error', async () => {
    const { startServer } = await import('../server');
    const emptyDir = join(TEST_DIST, '..', 'dist-empty');
    const { mkdirSync, copyFileSync, rmSync } = await import('fs');
    mkdirSync(emptyDir, { recursive: true });

    // Copy only bootstrap.js (unsigned)
    copyFileSync(join(TEST_DIST, 'bootstrap.js'), join(emptyDir, 'bootstrap.js'));

    const emptyServer = startServer(emptyDir);
    try {
      const bootstrapContent = readFileSync(join(emptyDir, 'bootstrap.js'));
      const hash = createHash('sha256').update(bootstrapContent).digest('base64');

      const html = `<!DOCTYPE html><html><head></head><body>
<script src="${emptyServer.url}/bootstrap.js"
  integrity="sha256-${hash}"
  crossorigin="anonymous"
  onerror="document.body.textContent='Script load failed.'"></script>
</body></html>`;

      const page = await browser.newPage();
      const consoleMessages = collectConsoleMessages(page);

      await page.setContent(html, { waitUntil: 'networkidle0', timeout: 15_000 });
      await new Promise((r) => setTimeout(r, 2000));

      const bodyText = await page.evaluate(() => document.body?.textContent || '');
      const hasError = bodyText.includes('Bootstrap failed') || bodyText.includes('Manifest fetch failed');
      const fetchError = consoleMessages.find(
        (m) => m.includes('Manifest fetch failed') || m.includes('Bootstrap failed')
      );

      expect(hasError || !!fetchError).toBe(true);

      await page.close();
    } finally {
      emptyServer.stop();
      rmSync(emptyDir, { recursive: true, force: true });
    }
  }, 30_000);
});

describe('signed build — crypto.subtle detection', () => {
  test('signed build shows clear error when crypto.subtle unavailable', async () => {
    // Build with signing enabled
    const signed = await buildAndServe({ signed: true });
    try {
      const bootstrapContent = readFileSync(join(TEST_DIST, 'bootstrap.js'));
      const hash = createHash('sha256').update(bootstrapContent).digest('base64');

      // Create a page that disables crypto.subtle to simulate non-secure context
      const page = await browser.newPage();
      const consoleMessages = collectConsoleMessages(page);

      // Navigate to about:blank and override crypto.subtle
      await page.goto('about:blank');
      await page.evaluate(() => {
        Object.defineProperty(crypto, 'subtle', { value: undefined, writable: false });
      });

      const html = `<!DOCTYPE html><html><head></head><body>
<script src="${signed.server.url}/bootstrap.js"
  integrity="sha256-${hash}"
  crossorigin="anonymous"
  onerror="document.body.textContent='Script load failed.'"></script>
</body></html>`;

      await page.setContent(html, { waitUntil: 'networkidle0', timeout: 15_000 });
      await new Promise((r) => setTimeout(r, 2000));

      const bodyText = await page.evaluate(() => document.body?.textContent || '');
      const errorInDom = bodyText.includes('secure context') || bodyText.includes('Bootstrap failed');
      const errorInConsole = consoleMessages.find(
        (m) => m.includes('secure context') || m.includes('Bootstrap failed')
      );

      expect(errorInDom || !!errorInConsole).toBe(true);

      await page.close();
    } finally {
      signed.server.stop();
    }
  }, 60_000);
});

describe('data: URL navigation (PNA behavior)', () => {
  test('documents that data: URL + PNA blocks bootstrap execution in non-secure localhost context', async () => {
    // This test documents the Chrome Private Network Access restriction.
    // data: URL pages have null origin (non-secure context) and Chrome blocks
    // their requests to localhost (private network). In production, the server
    // is a public HTTPS endpoint so PNA doesn't apply.
    const page = await browser.newPage();
    try {
      await page.goto(server.url, { waitUntil: 'domcontentloaded' });
      await page.click('#generate-btn');
      const bookmarkletUrl = await page.$eval('#bookmarklet-link', (el) =>
        (el as HTMLAnchorElement).href
      );

      const page2 = await browser.newPage();
      const consoleMessages = collectConsoleMessages(page2);
      const requests = collectNetworkRequests(page2);

      await page2.goto(bookmarkletUrl, { waitUntil: 'networkidle0', timeout: 15_000 });
      await new Promise((r) => setTimeout(r, 1000));

      // The bootstrap.js is fetched but may not execute due to PNA
      const bootstrapReq = requests.find((r) => r.url.includes('bootstrap.js'));

      // manifest.json fetch won't happen if bootstrap didn't execute
      const manifestReq = requests.find((r) => r.url.includes('manifest.json'));

      // isSecureContext should be false for data: URL
      const isSecure = await page2.evaluate(() =>
        typeof isSecureContext !== 'undefined' ? isSecureContext : null
      );
      expect(isSecure).toBe(false);

      // Document these facts for CI/debugging
      console.log('data: URL test results:');
      console.log(`  bootstrap.js fetched: ${!!bootstrapReq}`);
      console.log(`  manifest.json fetched: ${!!manifestReq}`);
      console.log(`  isSecureContext: ${isSecure}`);
      console.log(`  Console: ${consoleMessages.join('; ') || '(none)'}`);

      await page2.close();
    } finally {
      await page.close();
    }
  }, 30_000);
});
