import { execFile } from 'node:child_process';

/**
 * Desktop notifications for Shield alerts (S-012). Alerts otherwise only reach
 * stderr and `alerts.jsonl`, which many MCP clients never show.
 *
 * Text goes to the notifier as separate arguments or environment variables,
 * never through a shell, so alert text cannot become a command. Alerts never
 * contain tool arguments or results, only Shield messages.
 */
export type Notifier = (title: string, body: string) => void;

export type NotifyCommand = { file: string; args: string[]; env?: Record<string, string> };

const MAX_BODY = 220;

/** One line, no control or hidden characters, short. */
export function cleanText(s: string, max = MAX_BODY): string {
  const t = s.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]+/g, ' ').replace(/\s+/g, ' ').trim();
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

/** The command that shows one notification on this platform, or null if there is none. */
export function notifyCommand(platform: NodeJS.Platform, title: string, body: string): NotifyCommand | null {
  const t = cleanText(title, 80);
  const b = cleanText(body);
  if (platform === 'darwin') {
    // AppleScript reads the text from argv, so quotes in it are just text.
    return { file: '/usr/bin/osascript', args: ['-e', 'on run argv', '-e', 'display notification (item 2 of argv) with title (item 1 of argv)', '-e', 'end run', t, b] };
  }
  if (platform === 'linux') return { file: 'notify-send', args: ['--app-name=Exorcist 98', '--urgency=critical', t, b] };
  if (platform === 'win32') {
    // PowerShell reads the text from environment variables, so it is never parsed as code.
    const script =
      'Add-Type -AssemblyName System.Windows.Forms;' +
      '$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;' +
      '$n.ShowBalloonTip(10000,$env:X98_TITLE,$env:X98_BODY,[System.Windows.Forms.ToolTipIcon]::Warning);Start-Sleep -Seconds 6;$n.Dispose()';
    return { file: 'powershell.exe', args: ['-NoProfile', '-NonInteractive', '-Command', script], env: { X98_TITLE: t, X98_BODY: b } };
  }
  return null;
}

/** A notifier for this machine. Failures (no notifier installed, no display) are ignored. */
export function desktopNotifier(platform: NodeJS.Platform = process.platform): Notifier {
  return (title, body) => {
    const cmd = notifyCommand(platform, title, body);
    if (!cmd) return;
    try {
      const child = execFile(cmd.file, cmd.args, { timeout: 10_000, windowsHide: true, env: { ...process.env, ...(cmd.env ?? {}) } }, () => undefined);
      child.unref();
    } catch {
      // Not fatal: the alert is still on stderr and in alerts.jsonl.
    }
  };
}

/**
 * Lets through at most one notification per key per `perKeyMs`, and at most
 * `perWindow` in any `windowMs`, so a burst of alerts is one popup, not fifty.
 */
export function throttle(o: { perKeyMs?: number; windowMs?: number; perWindow?: number; now?: () => number } = {}): (key: string) => boolean {
  const perKeyMs = o.perKeyMs ?? 60_000;
  const windowMs = o.windowMs ?? 60_000;
  const perWindow = o.perWindow ?? 5;
  const now = o.now ?? (() => Date.now());
  const lastByKey = new Map<string, number>();
  const recent: number[] = [];
  return (key) => {
    const t = now();
    while (recent.length > 0 && t - (recent[0] ?? 0) >= windowMs) recent.shift();
    const last = lastByKey.get(key);
    if (last !== undefined && t - last < perKeyMs) return false;
    if (recent.length >= perWindow) return false;
    lastByKey.set(key, t);
    recent.push(t);
    return true;
  };
}
