import { z } from 'zod';

const MatchSchema = z
  .object({
    regex:         z.string().optional(),
    unicode_class: z.array(z.string()).optional(),
    json_path:     z.string().optional(),
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
