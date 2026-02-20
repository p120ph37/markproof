/**
 * Shared test helpers: build the project with a test-local origin URL,
 * launch browser via puppeteer-core, etc.
 */

import { join } from 'path';
import { buildApp } from '../src/plugin';
import { generateKeypair } from '../src/plugin/manifest';
import { startServer, type TestServer } from './server';
import puppeteer, { type Browser, type Page } from 'puppeteer-core';

export const PROJECT_ROOT = join(import.meta.dir, '..');
export const TEST_DIST = join(PROJECT_ROOT, 'dist-test');
export const CHROMIUM_PATH = '/root/.cache/ms-playwright/chromium-1194/chrome-linux/chrome';

/** Cached keypair so we only generate once per test run. */
let cachedKeypair: { privateKey: string; publicKey: string } | null = null;

export function getKeypair() {
  if (!cachedKeypair) {
    cachedKeypair = generateKeypair();
  }
  return cachedKeypair;
}

export interface BuildForTestOptions {
  /** Whether to sign the manifest with Ed25519 */
  signed?: boolean;
}

/**
 * Build the project targeting a specific origin URL.
 * @param originUrl The URL where the test server will be
 * @param options.signed Whether to sign the manifest (default: true)
 */
export async function buildForTest(originUrl: string, options?: BuildForTestOptions) {
  const signed = options?.signed ?? true;
  const keypair = signed ? getKeypair() : undefined;

  const result = await buildApp({
    entrypoints: [join(PROJECT_ROOT, 'src/demo/game.ts')],
    staticFiles: [
      join(PROJECT_ROOT, 'src/demo/style.css'),
      { src: join(PROJECT_ROOT, 'src/demo/index.html'), dest: 'app.html' },
    ],
    outdir: TEST_DIST,
    minify: true,
    appName: 'Test App',
    version: '0.0.1-test',
    originUrl,
    privateKey: keypair?.privateKey,
    publicKey: keypair?.publicKey,
    installer: {
      template: join(PROJECT_ROOT, 'src/installer/index.html'),
      generatorEntrypoint: join(PROJECT_ROOT, 'src/installer/generator.ts'),
    },
  });

  return result;
}

/**
 * Start the test server serving dist-test/ on a random port,
 * then build the project targeting that server's URL.
 *
 * This is a two-pass approach: first start the server to learn the port,
 * then build with the correct origin URL so the bookmarklet points to the
 * right place.
 *
 * @param options.signed Whether to sign the manifest (default: true)
 */
export async function buildAndServe(options?: BuildForTestOptions): Promise<{
  server: TestServer;
  buildResult: Awaited<ReturnType<typeof buildForTest>>;
}> {
  // Start server on a random port first so we know the URL
  const tempServer = startServer(TEST_DIST, 0);
  const originUrl = tempServer.url;
  tempServer.stop();

  // Build targeting that port
  const buildResult = await buildForTest(originUrl, options);

  // Start the real server on the same port
  const server = startServer(TEST_DIST, tempServer.port);

  return { server, buildResult };
}

/**
 * Launch a headless Chromium browser via puppeteer-core.
 */
export async function launchBrowser(): Promise<Browser> {
  const { mkdtempSync } = await import('fs');
  const { tmpdir } = await import('os');
  const userDataDir = mkdtempSync(join(tmpdir(), 'markproof-test-'));

  return puppeteer.launch({
    executablePath: CHROMIUM_PATH,
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      // --disable-web-security requires --user-data-dir to take effect
      `--user-data-dir=${userDataDir}`,
      // Disable web security: data: URL pages (null origin) need to fetch from
      // localhost. Chrome's Private Network Access policy blocks this because
      // data: URLs are non-secure contexts accessing loopback addresses.
      // In production, the server is a public HTTPS endpoint so PNA doesn't apply.
      '--disable-web-security',
      '--allow-running-insecure-content',
      // Disable PNA checks
      '--disable-features=PrivateNetworkAccessSendPreflights,PrivateNetworkAccessRespectPreflightResults',
    ],
  });
}

/**
 * Collect all console messages from a page.
 */
export function collectConsoleMessages(page: Page): string[] {
  const messages: string[] = [];
  page.on('console', (msg) => {
    messages.push(`[${msg.type()}] ${msg.text()}`);
  });
  return messages;
}

/**
 * Collect all network requests from a page.
 */
export function collectNetworkRequests(page: Page): { url: string; status: number; method: string }[] {
  const requests: { url: string; status: number; method: string }[] = [];
  page.on('response', (response) => {
    requests.push({
      url: response.url(),
      status: response.status(),
      method: response.request().method(),
    });
  });
  return requests;
}
