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

import { Bot, GitBranch, Plug, Terminal } from 'lucide-react';

import { cn } from '@/lib/cn';
import { initialsOf } from '@/lib/format';
import type { JobOrigin } from '@/lib/types';

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

/**
 * How the job was submitted, when it was not submitted by hand.
 *
 * The account is the same whoever typed it, so without this a scan the
 * assistant ran for an analyst is indistinguishable from one they ran
 * themselves — and the first thing they do with a job they do not remember is
 * doubt the history. `ui` is the ordinary case and carries no mark.
 */
const ORIGINS: Partial<Record<JobOrigin, { icon: typeof Bot; label: string }>> = {
  assistant: { icon: Bot, label: 'Submitted by the assistant' },
  mcp: { icon: Plug, label: 'Submitted by an agent over MCP' },
  api: { icon: Terminal, label: 'Submitted with an API token' },
  pivot: { icon: GitBranch, label: 'Created by a pivot' },
};

export function OriginMark({ origin, className }: { origin: JobOrigin; className?: string }) {
  const entry = ORIGINS[origin];
  if (!entry) {
    return null;
  }
  const Icon = entry.icon;
  return (
    <span
      className={cn(
        'grid h-4 w-4 shrink-0 place-items-center rounded-full bg-surface-sunken text-muted',
        className,
      )}
      title={entry.label}
    >
      <Icon className="h-2.5 w-2.5" aria-hidden />
      <span className="sr-only">{entry.label}</span>
    </span>
  );
}

export function Author({
  name,
  origin,
  className,
  hideName,
}: {
  name: string;
  origin?: JobOrigin;
  className?: string;
  /** On a narrow column the avatar carries it, with the name as a tooltip. */
  hideName?: boolean;
}) {
  const label = name || 'Unknown';
  return (
    <span className={cn('flex min-w-0 items-center gap-1.5', className)}>
      <AuthorAvatar name={label} className="shrink-0" />
      {hideName ? (
        <span className="sr-only">{label}</span>
      ) : (
        <span className="truncate text-xs text-muted" title={label}>
          {label}
        </span>
      )}
      {origin ? <OriginMark origin={origin} /> : null}
    </span>
  );
}
