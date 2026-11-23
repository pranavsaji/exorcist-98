import { fileURLToPath } from 'node:url';

/** @type {import('next').NextConfig} */
const nextConfig = {
  // The engine ships TypeScript source with ".js" import specifiers.
  transpilePackages: ['@exorcist-98/core', '@exorcist-98/shield'],
  // Self-contained server output (node server.js), so any Node host can run it.
  output: 'standalone',
  experimental: {
    // Trace from the monorepo root and ship the definitions and the Haunted Repo
    // with the server: both are read from disk at run time.
    outputFileTracingRoot: fileURLToPath(new URL('../../', import.meta.url)),
    outputFileTracingIncludes: {
      '/api/scan': ['../../definitions/**/*', '../../fixtures/haunted-repo/**/*'],
      '/api/shield-sim': ['../../definitions/**/*'],
      '/encyclopedia': ['../../definitions/**/*'],
      '/encyclopedia/[id]': ['../../definitions/**/*', '../../fixtures/haunted-repo/**/*'],
    },
    // The Bedrock SDK is only used by the AWS Lambda entry point, not the web app.
    serverComponentsExternalPackages: ['@aws-sdk/client-bedrock-runtime'],
  },
  eslint: { ignoreDuringBuilds: true },
  poweredByHeader: false,
  // Browser hardening for the public site. Next.js 14 inlines its bootstrap
  // scripts, so script-src keeps 'unsafe-inline'; scanned text is only ever
  // rendered as text (no dangerouslySetInnerHTML), and the page cannot be framed.
  async headers() {
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join('; ');
    return [{
      source: '/:path*',
      headers: [
        { key: 'Content-Security-Policy', value: csp },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
      ],
    }];
  },
  webpack(config) {
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js'],
      '.mjs': ['.mts', '.mjs'],
    };
    return config;
  },
};

export default nextConfig;
