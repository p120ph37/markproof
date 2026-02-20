import { generateManifest, signManifest, sha256hex, canonicalizeManifest, type Manifest } from './manifest';
import type { BunPlugin, BuildConfig } from 'bun';

export interface BuildOptions {
  /** Bun.build entrypoints */
  entrypoints: string[];
  /** Additional static files to include (HTML, CSS, images).
   *  Can be paths (basename used) or {src, dest} objects for renaming. */
  staticFiles?: (string | { src: string; dest: string })[];
  /** Output directory */
  outdir: string;
  /** Enable minification */
  minify?: boolean;
  /** App name (for display) */
  appName?: string;
  /** App version string */
  version?: string;
  /** Origin URL where the app will be hosted */
  originUrl: string;
  /** PEM-encoded Ed25519 private key for signing (optional) */
  privateKey?: string;
  /** Base64-encoded Ed25519 public key (derived from private key if not provided) */
  publicKey?: string;
  /** Additional Bun plugins */
  plugins?: BunPlugin[];
  /** Installer page configuration */
  installer?: {
    /** Path to installer HTML template */
    template: string;
    /** Entrypoint for installer JavaScript */
    generatorEntrypoint: string;
  };
}

export interface BuildResult {
  /** The generated manifest */
  manifest: Manifest;
  /** Base64-encoded SHA-256 hash of bootstrap.js (for SRI) */
  bootstrapHashBase64: string;
  /** Map of output file paths */
  outputFiles: string[];
}

/**
 * Build a trust-anchored web app with manifest generation, signing, and installer.
 *
 * This wraps Bun.build() and adds:
 * 1. SHA-256 hashing of all output files
 * 2. Manifest generation with resource hashes
 * 3. Ed25519 signing of the manifest (if private key provided)
 * 4. Bootstrap.js deployment (with public key injection)
 * 5. Installer page generation with embedded bookmarklet generator
 */
export async function buildApp(options: BuildOptions): Promise<BuildResult> {
  const {
    entrypoints,
    staticFiles = [],
    outdir,
    minify = true,
    appName = 'App',
    version = '1.0.0',
    originUrl,
    privateKey,
    plugins = [],
  } = options;

  const fs = await import('fs');
  const path = await import('path');
  const crypto = await import('crypto');

  // Ensure output directory exists
  fs.mkdirSync(outdir, { recursive: true });

  console.log(`Building ${appName} v${version}...`);

  // Step 1: Run Bun.build for JavaScript/TypeScript entrypoints
  const buildResult = await Bun.build({
    entrypoints,
    outdir,
    minify,
    plugins,
    naming: '[name].[ext]',
    target: 'browser',
  });

  if (!buildResult.success) {
    console.error('Build failed:');
    for (const log of buildResult.logs) {
      console.error(log);
    }
    throw new Error('Bun.build failed');
  }

  console.log(`  Bundled ${buildResult.outputs.length} file(s)`);

  // Step 2: Copy static files to output directory
  for (const entry of staticFiles) {
    const src = typeof entry === 'string' ? entry : entry.src;
    const destName = typeof entry === 'string' ? path.basename(entry) : entry.dest;
    const dest = path.join(outdir, destName);
    fs.copyFileSync(src, dest);
    console.log(`  Copied ${destName}`);
  }

  // Step 3: Derive public key from private key if needed
  let publicKeyBase64 = options.publicKey;
  if (privateKey && !publicKeyBase64) {
    const pubKeyObj = crypto.createPublicKey(privateKey);
    const spkiDer = pubKeyObj.export({ type: 'spki', format: 'der' });
    publicKeyBase64 = (spkiDer as Buffer).toString('base64');
  }

  // Step 4: Copy bootstrap.js runtime to output directory, injecting public key
  const runtimeDir = path.join(path.dirname(new URL(import.meta.url).pathname), 'runtime');
  let bootstrapOutput = fs.readFileSync(path.join(runtimeDir, 'bootstrap.js'), 'utf8');

  if (publicKeyBase64) {
    bootstrapOutput = bootstrapOutput.replace(
      "'__PUBLIC_KEY__'",
      JSON.stringify(publicKeyBase64)
    );
    console.log(`  Public key embedded in bootstrap`);
  }

  const bootstrapOutPath = path.join(outdir, 'bootstrap.js');
  fs.writeFileSync(bootstrapOutPath, bootstrapOutput);

  // Hash the deployed bootstrap (with key embedded) — base64 for SRI
  const bootstrapHashBase64 = crypto.createHash('sha256')
    .update(bootstrapOutput)
    .digest('base64');
  console.log(`  Bootstrap hash (base64): ${bootstrapHashBase64}`);

  // Step 5: Collect all output files and compute hashes
  const appFiles = new Map<string, Buffer>();
  const allOutputFiles: string[] = [];

  const outDirContents = fs.readdirSync(outdir);
  for (const filename of outDirContents) {
    const filePath = path.join(outdir, filename);
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) continue;
    // Skip bootstrap.js and manifest.json from the manifest (they're infrastructure, not app)
    if (filename === 'bootstrap.js' || filename === 'manifest.json') continue;
    // Skip installer files
    if (filename === 'index.html' || filename === 'generator.js') continue;

    const content = fs.readFileSync(filePath);
    appFiles.set('/' + filename, content);
    allOutputFiles.push(filePath);
  }

  // Step 6: Generate manifest
  let manifest = generateManifest(appFiles, version);

  // Step 7: Sign manifest if private key is available
  if (privateKey) {
    manifest = signManifest(manifest, privateKey);
    console.log(`  Manifest signed`);
  } else {
    console.log(`  Manifest unsigned (no private key provided)`);
  }

  // Write manifest
  const manifestPath = path.join(outdir, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  allOutputFiles.push(manifestPath);

  // Step 8: Build installer page if configured
  if (options.installer) {
    // Compute manifest hash for locked mode
    const manifestHash = sha256hex(canonicalizeManifest(manifest));

    await buildInstaller(options, outdir, bootstrapHashBase64, manifestHash);
  }

  console.log(`Build complete: ${allOutputFiles.length} files in ${outdir}/`);

  return {
    manifest,
    bootstrapHashBase64,
    outputFiles: allOutputFiles,
  };
}

/**
 * Build the installer/bookmarklet-generator page.
 */
async function buildInstaller(
  options: BuildOptions,
  outdir: string,
  bootstrapHashBase64: string,
  manifestHash: string,
): Promise<void> {
  const fs = await import('fs');
  const path = await import('path');

  if (!options.installer) return;

  const { template, generatorEntrypoint } = options.installer;
  const bootstrapUrl = options.originUrl.replace(/\/$/, '') + '/bootstrap.js';

  // Build the installer JS with embedded constants
  const installerBuild = await Bun.build({
    entrypoints: [generatorEntrypoint],
    outdir,
    minify: options.minify ?? true,
    naming: 'generator.[ext]',
    target: 'browser',
    define: {
      '__BOOTSTRAP_HASH_BASE64__': JSON.stringify(bootstrapHashBase64),
      '__BOOTSTRAP_URL__': JSON.stringify(bootstrapUrl),
      '__MANIFEST_HASH__': JSON.stringify(manifestHash),
      '__APP_NAME__': JSON.stringify(options.appName || 'App'),
      '__APP_VERSION__': JSON.stringify(options.version || '1.0.0'),
    },
  });

  if (!installerBuild.success) {
    console.error('Installer build failed:');
    for (const log of installerBuild.logs) {
      console.error(log);
    }
    throw new Error('Installer build failed');
  }

  // Copy installer HTML template
  let installerHtml = fs.readFileSync(template, 'utf8');
  // Replace any template variables in the HTML
  installerHtml = installerHtml
    .replace(/__APP_NAME__/g, options.appName || 'App')
    .replace(/__APP_VERSION__/g, options.version || '1.0.0');

  fs.writeFileSync(path.join(outdir, 'index.html'), installerHtml);
  console.log(`  Installer page generated`);
}
