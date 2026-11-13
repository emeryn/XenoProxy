/**
 * Who submitted a job.
 *
 * The history is shared across the team, so "who ran this" is part of reading a
 * row, not a detail. An avatar gives the column a fixed anchor to scan down,
 * which a bare name in a list of twenty-five rows does not.
 *
 * The colour is derived from the name rather than stored: it has no meaning, it
 * only has to be stable, so the same person is the same colour on every page.
 */

import { cn } from '@/lib/cn';
import { initialsOf } from '@/lib/format';

// Hues spaced around the wheel, kept away from the verdict colours so an
// avatar can never be mistaken for a status.
const AVATAR_TINTS = [
  'bg-[#2b6cb0] text-white',
  'bg-[#5a4bb8] text-white',
  'bg-[#0f7d8c] text-white',
  'bg-[#8a4a9c] text-white',
  'bg-[#1f7a5a] text-white',
  'bg-[#8a5a2b] text-white',
] as const;

function tintOf(name: string): string {
  let hash = 0;
  for (let index = 0; index < name.length; index += 1) {
    hash = (hash * 31 + name.charCodeAt(index)) % 997;
  }
  return AVATAR_TINTS[hash % AVATAR_TINTS.length] ?? AVATAR_TINTS[0];
}

export function AuthorAvatar({ name, className }: { name: string; className?: string }) {
  return (
    <span
      className={cn(
        'grid h-6 w-6 shrink-0 place-items-center rounded-pill text-[10px] font-semibold',
        tintOf(name),
        className,
      )}
      aria-hidden
    >
      {initialsOf(name)}
    </span>
  );
}

export function Author({
  name,
  className,
  hideName,
}: {
  name: string;
  className?: string;
  /** On a narrow column the avatar carries it, with the name as a tooltip. */
  hideName?: boolean;
}) {
  const label = name || 'Unknown';
  return (
    <span className={cn('flex min-w-0 items-center gap-2', className)} title={label}>
      <AuthorAvatar name={label} />
      {hideName ? (
        <span className="sr-only">{label}</span>
      ) : (
        <span className="truncate text-xs text-muted">{label}</span>
      )}
    </span>
  );
}
