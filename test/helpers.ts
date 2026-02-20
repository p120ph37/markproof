/**
 * Shared test helpers: build the project with a test-local origin URL,
 * launch browser via playwright-core, etc.
 */

import { join } from 'path';
import { buildApp } from '../src/plugin';
import { generateKeypair } from '../src/plugin/manifest';
import { startServer, type TestServer } from './server';
import { chromium, type Browser, type Page } from 'playwright-core';

export const PROJECT_ROOT = join(import.meta.dir, '..');
export const TEST_DIST = join(PROJECT_ROOT, 'dist-test');

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
 * Find a usable Chromium executable.
 * Prefers: CHROMIUM_PATH env var > Playwright-managed browser > common system paths.
 */
function findChromium(): string | undefined {
  const { existsSync } = require('fs');

  // 1. Explicit env override
  if (process.env.CHROMIUM_PATH && existsSync(process.env.CHROMIUM_PATH)) {
    return process.env.CHROMIUM_PATH;
  }

  // 2. Let Playwright find its own managed browser (works after `bunx playwright-core install chromium`)
  try {
    const path = chromium.executablePath();
    if (path && existsSync(path)) return path;
  } catch {}

  // 3. Common system / CI paths
  const candidates = [
    '/root/.cache/ms-playwright/chromium-1194/chrome-linux/chrome',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/google-chrome',
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }

  return undefined;
}

/**
 * Launch a headless Chromium browser via playwright-core.
 *
 * Playwright manages its own temporary user-data-dir, so --disable-web-security
 * works without an explicit --user-data-dir flag (unlike raw Puppeteer).
 */
export async function launchBrowser(): Promise<Browser> {
  return chromium.launch({
    executablePath: findChromium(),
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
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
