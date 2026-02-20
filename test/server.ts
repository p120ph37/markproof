/**
 * Test HTTP server that serves the dist/ directory with proper CORS headers.
 *
 * Required for E2E tests: data-URL pages (opaque origin) need CORS on all fetches.
 */

import { readFileSync, existsSync, statSync } from 'fs';
import { join, extname } from 'path';

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

export interface TestServer {
  url: string;
  port: number;
  stop: () => void;
}

/**
 * Start a Bun HTTP server serving the given directory.
 * Adds CORS headers to all responses so data-URL contexts can fetch resources.
 */
export function startServer(distDir: string, port = 0): TestServer {
  const server = Bun.serve({
    port,
    fetch(req) {
      // Handle CORS preflight
      if (req.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: corsHeaders(),
        });
      }

      const url = new URL(req.url);
      let pathname = url.pathname;
      if (pathname === '/') pathname = '/index.html';

      const filePath = join(distDir, pathname);

      if (!existsSync(filePath) || !statSync(filePath).isFile()) {
        return new Response('Not Found', {
          status: 404,
          headers: corsHeaders(),
        });
      }

      const content = readFileSync(filePath);
      const ext = extname(filePath);
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';

      return new Response(content, {
        status: 200,
        headers: {
          'Content-Type': contentType,
          ...corsHeaders(),
        },
      });
    },
  });

  return {
    url: `http://localhost:${server.port}`,
    port: server.port,
    stop: () => server.stop(),
  };
}

function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': '*',
    // Required for Private Network Access (PNA): data: URL pages have a null
    // origin which Chrome considers "non-secure". When they fetch from localhost
    // (a private/loopback address), Chrome sends a PNA preflight and requires
    // this header in the response.
    'Access-Control-Allow-Private-Network': 'true',
  };
}
