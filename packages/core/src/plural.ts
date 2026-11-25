/** "1 file", "2 files". Pass `many` for irregular plurals. Pure and browser-safe. */
export function plural(n: number, one: string, many: string = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
