import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import {
  buildAndServe,
  launchBrowser,
  collectConsoleMessages,
  collectNetworkRequests,
  TEST_DIST,
} from '../helpers';
import type { TestServer } from '../server';
import type { Browser, Page } from 'playwright-core';

let server: TestServer;
let browser: Browser;

beforeAll(async () => {
  const result = await buildAndServe();
  server = result.server;
  browser = await launchBrowser();
}, 30_000);

afterAll(async () => {
  await browser?.close();
  server?.stop();
});

describe('installer page', () => {
  test('loads and renders the installer UI', async () => {
    const page = await browser.newPage();
    try {
      await page.goto(server.url, { waitUntil: 'domcontentloaded' });

      // Check title
      const title = await page.title();
      expect(title).toContain('Test App');

      // Check heading
      const heading = await page.$eval('h1', (el) => el.textContent);
      expect(heading).toContain('Test App');

      // Check generate button exists
      const btn = await page.$('#generate-btn');
      expect(btn).not.toBeNull();

      // Check update mode dropdown exists
      const select = await page.$('#update-mode');
      expect(select).not.toBeNull();

      // Result section should be hidden initially
      const resultVisible = await page.$eval('#result', (el) =>
        el.classList.contains('visible')
      );
      expect(resultVisible).toBe(false);
    } finally {
      await page.close();
    }
  });

  test('generate button produces a bookmarklet link (auto mode)', async () => {
    const page = await browser.newPage();
    try {
      await page.goto(server.url, { waitUntil: 'domcontentloaded' });

      // Click generate
      await page.click('#generate-btn');

      // Result should become visible
      const resultVisible = await page.$eval('#result', (el) =>
        el.classList.contains('visible')
      );
      expect(resultVisible).toBe(true);

      // Bookmarklet link should have a data:text/html URL
      const href = await page.$eval('#bookmarklet-link', (el) =>
        (el as HTMLAnchorElement).href
      );
      expect(href).toStartWith('data:text/html;base64,');

      // Decode and verify it contains the bootstrap URL
      const base64 = href.replace('data:text/html;base64,', '');
      const html = atob(base64);
      expect(html).toContain(server.url + '/bootstrap.js');
      expect(html).toContain('integrity=sha256-');
      expect(html).toContain('crossorigin=anonymous');

      // Auto mode: should NOT include data-mode attribute
      expect(html).not.toContain('data-mode');
    } finally {
      await page.close();
    }
  });

  test('generate button produces a locked-mode bookmarklet', async () => {
    const page = await browser.newPage();
    try {
      await page.goto(server.url, { waitUntil: 'domcontentloaded' });

      // Select locked mode
      await page.selectOption('#update-mode', 'locked');

      // Click generate
      await page.click('#generate-btn');

      // Decode the bookmarklet
      const href = await page.$eval('#bookmarklet-link', (el) =>
        (el as HTMLAnchorElement).href
      );
      const base64 = href.replace('data:text/html;base64,', '');
      const html = atob(base64);

      // Locked mode: should include data-mode and data-hash
      expect(html).toContain('data-mode=locked');
      expect(html).toContain('data-hash=');
    } finally {
      await page.close();
    }
  });

  test('bookmarklet link text includes app name', async () => {
    const page = await browser.newPage();
    try {
      await page.goto(server.url, { waitUntil: 'domcontentloaded' });
      await page.click('#generate-btn');

      const linkText = await page.$eval('#bookmarklet-link', (el) => el.textContent);
      expect(linkText).toContain('Test App');
      expect(linkText).toContain('Drag to bookmark bar');
    } finally {
      await page.close();
    }
  });
});
