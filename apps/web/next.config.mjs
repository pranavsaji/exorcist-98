import { fileURLToPath } from 'node:url';

/** @type {import('next').NextConfig} */
const nextConfig = {
  // The engine ships TypeScript source with ".js" import specifiers.
  transpilePackages: ['@exorcist-98/core'],
  // Self-contained server output (node server.js), so any Node host can run it.
  output: 'standalone',
  experimental: {
    // Trace from the monorepo root and ship the definitions and the Haunted Repo
    // with the server: both are read from disk at run time.
    outputFileTracingRoot: fileURLToPath(new URL('../../', import.meta.url)),
    outputFileTracingIncludes: {
      '/api/scan': ['../../definitions/**/*', '../../fixtures/haunted-repo/**/*'],
      '/encyclopedia': ['../../definitions/**/*'],
      '/encyclopedia/[id]': ['../../definitions/**/*', '../../fixtures/haunted-repo/**/*'],
    },
    // The Bedrock SDK is only used by the AWS Lambda entry point, not the web app.
    serverComponentsExternalPackages: ['@aws-sdk/client-bedrock-runtime'],
  },
  eslint: { ignoreDuringBuilds: true },
  webpack(config) {
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js'],
      '.mjs': ['.mts', '.mjs'],
    };
    return config;
  },
};

export default nextConfig;
