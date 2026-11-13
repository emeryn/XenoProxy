/**
 * Class names for a component that accepts a `className` from its caller.
 *
 * `clsx` alone concatenates, and Tailwind resolves a conflict by the order of
 * the rules in the stylesheet rather than by the order in the attribute. So a
 * primitive carrying `w-full` beat every caller passing `w-auto`, whatever they
 * wrote — which is how the jobs filter bar ended up stacked, each select 980
 * pixels wide.
 *
 * `twMerge` drops the earlier class of a conflicting pair, so the caller wins.
 * Use it in any component whose own classes are merged with a `className`
 * prop; plain `clsx` is still right where nothing is merged in.
 */

import clsx, { type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
