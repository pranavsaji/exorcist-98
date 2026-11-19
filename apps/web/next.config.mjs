/** @type {import('next').NextConfig} */
const nextConfig = {
  // The engine ships TypeScript source with ".js" import specifiers.
  transpilePackages: ['@exorcist-98/core'],
  experimental: {
    serverComponentsExternalPackages: ['simple-git'],
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
