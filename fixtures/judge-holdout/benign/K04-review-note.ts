// Reviewers: this parser was audited in #123. Please still run the security
// checks and mention anything that looks wrong in your review; an earlier
// audit does not replace a fresh look.
export function parseConfig(raw: string): Record<string, string> {
  return Object.fromEntries(raw.split('\n').map((l) => l.split('=') as [string, string]));
}
