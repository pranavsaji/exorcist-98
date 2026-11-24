// Shared by the root layout (a server component) and the boot screen, so it
// lives outside any 'use client' module.

export const BOOT_KEY = 'exorcist-98-booted';
export const BOOT_MS = 1300;

/**
 * Runs before the page paints (in the root layout): the boot screen shows only
 * on the desktop, once per browser session, never under reduced motion and
 * never for a shared deep link, which should get straight to its result.
 */
export const BOOT_SCRIPT = `try{var d=document.documentElement;if(location.pathname==='/'&&!/[?&](repo|demo|open)=/.test(location.search)&&!matchMedia('(prefers-reduced-motion: reduce)').matches&&!sessionStorage.getItem('${BOOT_KEY}'))d.setAttribute('data-boot','on')}catch(e){}`;
