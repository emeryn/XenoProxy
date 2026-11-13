/**
 * Client-side validation of the scan form.
 *
 * These bounds mirror the Pydantic schema on the backend, which remains the
 * authority: this schema exists to tell the analyst what is wrong before a
 * request is sent, never to replace the server-side check.
 */

import { z } from 'zod';

export const MAX_OBSERVABLE_LENGTH = 2048;
export const MAX_ANALYZERS = 30;
export const MAX_CONNECTORS = 10;
export const MAX_PIVOTS = 10;
export const MAX_TAGS = 20;

export const scanFormSchema = z
  .object({
    observable: z
      .string()
      .min(1, 'An observable is required.')
      .max(
        MAX_OBSERVABLE_LENGTH,
        `The observable cannot exceed ${MAX_OBSERVABLE_LENGTH} characters.`,
      )
      .refine(
        // The rule exists to catch a control character written into a pattern
        // by accident. Here the pattern is the check: the point is to refuse an
        // observable that carries one, so it has to name the range.
        // eslint-disable-next-line no-control-regex
        (value) => !/[\u0000-\u001f]/.test(value),
        'The observable contains control characters.',
      ),
    analyzers: z
      .array(z.string().min(1).max(64))
      .max(MAX_ANALYZERS, `A job cannot run more than ${MAX_ANALYZERS} analyzers.`),
    connectors: z
      .array(z.string().min(1).max(64))
      .max(MAX_CONNECTORS, `A job cannot run more than ${MAX_CONNECTORS} connectors.`),
    pivots: z
      .array(z.string().min(1).max(64))
      .max(MAX_PIVOTS, `A job cannot run more than ${MAX_PIVOTS} pivots.`),
    playbook: z.string().min(1).max(128).nullable(),
    tags: z
      .array(z.string().min(1).max(64))
      .max(MAX_TAGS, `A job cannot carry more than ${MAX_TAGS} tags.`),
    force_rescan: z.boolean(),
  })
  .refine((value) => value.analyzers.length > 0 || value.playbook !== null, {
    message: 'Select at least one analyzer or a playbook.',
    path: ['analyzers'],
  })
  .refine(
    // Connectors publish a verdict and pivots read an analysis, so neither can
    // be the whole of a job. The backend refuses this too; saying so here keeps
    // the analyst from discovering it only after submitting.
    (value) =>
      value.analyzers.length > 0 ||
      value.playbook !== null ||
      (value.connectors.length === 0 && value.pivots.length === 0),
    {
      message: 'Connectors and pivots act on an analysis: add at least one analyzer.',
      path: ['analyzers'],
    },
  );

export type ScanFormValues = z.infer<typeof scanFormSchema>;

/** Return the first message per field, ready to render under the input. */
export function fieldErrors(
  result: z.ZodSafeParseResult<ScanFormValues>,
): Record<string, string> {
  if (result.success) return {};
  const errors: Record<string, string> = {};
  for (const issue of result.error.issues) {
    const key = issue.path.join('.') || 'form';
    if (!errors[key]) errors[key] = issue.message;
  }
  return errors;
}

export function parseTags(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(',')
        .map((tag) => tag.trim().toLowerCase())
        .filter(Boolean)
        .map((tag) => tag.slice(0, 64)),
    ),
  );
}
