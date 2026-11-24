import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { BOOT_SCRIPT } from '@/lib/boot';
import './globals.css';

export const metadata: Metadata = {
  title: 'Exorcist 98',
  description:
    'The 90s antivirus, resurrected to protect AI coding agents. Scan a repo for prompt injection, tool poisoning and dangerous hooks.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    // The boot script may set data-boot on <html> before React hydrates.
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* A fixed string from our own code (no user input): decides before first paint whether to show the boot screen. */}
        <script dangerouslySetInnerHTML={{ __html: BOOT_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
