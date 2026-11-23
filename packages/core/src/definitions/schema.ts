import { z } from 'zod';

function compiles(pattern: string): boolean {
  try {
    new RegExp(pattern, 'i');
    return true;
  } catch {
    return false;
  }
}

const MatchSchema = z
  .object({
    regex:         z.string().optional(),
    unicode_class: z.array(z.string()).optional(),
    json_path:     z.string().optional(),
    // Filters the values selected by json_path: only values matching this
    // regex (case-insensitive) become findings. Requires json_path.
    value_regex:   z.string().optional(),
    // Precision controls (added after real-repo testing showed ~100% false positives):
    // a regex match is dropped when it matches exclude_regex, or when validate
    // says it is not what the rule means; the rule only runs on a file whose
    // text matches file_regex.
    exclude_regex: z.string().optional(),
    // secret-value: the matched value must look like a real credential, not a
    // placeholder, a template, an expression or a documented example.
    validate:      z.enum(['base64-text', 'encoded-text', 'typosquat', 'secret-value']).optional(),
    // Only for files of role `config`: the rule runs only if the file text matches.
    file_regex:    z.string().optional(),
    // With json_path selecting an `args` array: check only the package the
    // runner is told to run, not flags or paths.
    select:        z.enum(['package-arg']).optional(),
    // ── Context checks (precision round 2, docs/FIELD_REPORT.md) ──────────────
    // In generic config files (role `config`), a match counts only where it is
    // something that runs: the value of a command-like key, an item of a
    // command list, a step an agent is told to run, or anywhere in a known
    // agent-environment or hook file. Hooks, MCP configs and tool results are
    // always checked in full.
    exec_context:  z.boolean().optional(),
    // Ignore matches inside Markdown code (inline backticks or fenced blocks),
    // where an HTML comment is shown, not hidden, and an image is not loaded.
    skip_in_code:  z.boolean().optional(),
    // A phrase inside quotation marks that closes right after it, in a passage
    // matching this regex (words such as "never", "such as", "injection"), is
    // being quoted as an example or warned against, not given as an order.
    quoted_example_cues: z.string().optional(),
    // Matches separated only by line breaks, quotes, commas or `+` are one
    // encoded blob: one finding, checked as a whole.
    merge_adjacent: z.boolean().optional(),
    // At most this many findings of the rule in one file; the last one
    // summarises the rest.
    max_per_file:  z.number().int().min(1).optional(),
    // With validate encoded-text: extra markers (for example chat-template
    // tokens) that make decoded text count as instructions.
    decoded_flag_regex: z.string().optional(),
    // unicode_class only: a run of at least `min_run` characters is required
    // for the rule to fire at all. Shorter runs are ignored entirely (used by
    // EX-021: one or two variation selectors are ordinary emoji presentation).
    min_run:      z.number().int().min(1).optional(),
    // unicode_class only: a run of at most `max_length` characters, all of the
    // listed classes, is reported at `severity` instead of the rule's own.
    minor_run: z.object({
      max_length: z.number().int().min(1),
      classes:    z.array(z.string()).min(1),
      severity:   z.enum(['critical', 'high', 'medium', 'low']),
    }).optional(),
  })
  .superRefine((val, ctx) => {
    const hasAny =
      val.regex !== undefined ||
      (val.unicode_class !== undefined && val.unicode_class.length > 0) ||
      val.json_path !== undefined;
    if (!hasAny) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          'match must contain at least one of: regex, unicode_class, json_path',
      });
    }
    if (val.value_regex !== undefined && val.json_path === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'match.value_regex requires match.json_path',
      });
    }
    if ((val.exclude_regex !== undefined || val.validate !== undefined) && val.regex === undefined && val.json_path === undefined) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'match.exclude_regex and match.validate need match.regex or match.json_path' });
    }
    for (const key of ['regex', 'value_regex', 'exclude_regex', 'file_regex', 'quoted_example_cues', 'decoded_flag_regex'] as const) {
      const pattern = val[key];
      if (pattern !== undefined && !compiles(pattern)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `match.${key} is not a valid regular expression`,
        });
      }
    }
  });

export const VirusDefinitionSchema = z.object({
  id:          z.string().regex(/^EX-\d{3}$/, 'id must match EX-NNN'),
  title:       z.string().min(1, 'title must not be empty'),
  severity:    z.enum(['critical', 'high', 'medium', 'low']),
  applies_to:  z.array(z.string()).min(1, 'applies_to must have at least one entry'),
  match:       MatchSchema,
  owasp:       z.array(z.string()).min(1, 'owasp must have at least one reference'),
  fix:         z.string().min(1, 'fix must not be empty'),
  enabled:     z.boolean().optional().default(true),
  // Repo-relative paths (regexes) this rule never looks at, e.g. lockfiles.
  skip_paths:  z.array(z.string().refine(compiles, 'skip_paths entries must be valid regular expressions')).optional(),
  // Rules in the same group that report the same line of the same file are
  // one problem: only the most severe of them is kept.
  same_line_group: z.string().min(1).optional(),
});

export type VirusDefinition = z.infer<typeof VirusDefinitionSchema>;

export class DefinitionLoadError extends Error {
  constructor(
    public readonly file: string,
    public readonly issues: z.ZodIssue[],
  ) {
    super(
      `Invalid definition in ${file}: ${issues.map((i) => i.message).join('; ')}`,
    );
    this.name = 'DefinitionLoadError';
  }
}
