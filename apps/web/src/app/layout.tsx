import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './globals.css';

export const metadata: Metadata = {
  title: 'Exorcist 98',
  description:
    'The 90s antivirus, resurrected to protect AI coding agents. Scan a repo for prompt injection, tool poisoning and dangerous hooks.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
