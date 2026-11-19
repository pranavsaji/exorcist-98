import type { Config } from 'tailwindcss';

// Original haunted-desktop palette. No real operating-system colours or brand assets.
const config: Config = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        desk:     '#23163d', // desktop background
        face:     '#cfc8dc', // window and button face
        hilite:   '#f4f0fa', // bevel light edge
        shade:    '#6b6180', // bevel shadow edge
        ink:      '#120b22', // text on face (AA contrast)
        title:    '#4b2a8a', // title bar start
        title2:   '#8a3fb0', // title bar end
        phosphor: '#39ff88', // log text on black
        crit:     '#ff3b6b',
        high:     '#ff9a3c',
        med:      '#ffd93c',
        low:      '#6bd0ff',
      },
      fontFamily: {
        ui:   ['ui-sans-serif', 'system-ui', 'Segoe UI', 'Helvetica', 'Arial', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};

export default config;
