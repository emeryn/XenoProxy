/** Locale-aware formatting helpers. Dates arrive in UTC and are shown locally. */

const dateTime = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
});

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? '—' : dateTime.format(parsed);
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return '—';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return '—';

  const seconds = Math.round((parsed.getTime() - Date.now()) / 1000);
  const thresholds: [Intl.RelativeTimeFormatUnit, number][] = [
    ['second', 60],
    ['minute', 60],
    ['hour', 24],
    ['day', 30],
    ['month', 12],
  ];

  let value_ = seconds;
  for (const [unit, limit] of thresholds) {
    if (Math.abs(value_) < limit) return relative.format(Math.round(value_), unit);
    value_ /= limit;
  }
  return relative.format(Math.round(value_), 'year');
}

export function formatDuration(milliseconds: number | null | undefined): string {
  if (milliseconds === null || milliseconds === undefined) return '—';
  if (milliseconds < 1000) return `${milliseconds} ms`;
  if (milliseconds < 60_000) return `${(milliseconds / 1000).toFixed(1)} s`;
  return `${Math.round(milliseconds / 60_000)} min`;
}

export function formatTtl(seconds: number): string {
  if (seconds <= 0) return 'no cache';
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86_400)} d`;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value);
}

/**
 * Initials for an avatar, from whatever form of a name the backend holds.
 *
 * Accounts arrive from a directory as well as from local sign-up, so a name is
 * `alice`, `Alice Durand` or `alice.durand` depending on the source. Splitting
 * on separators rather than on spaces alone is what makes all three give `AD`.
 */
export function initialsOf(name: string): string {
  const parts = name.trim().split(/[\s._@-]+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return (parts[0] ?? '').slice(0, 2).toUpperCase();
  return `${(parts[0] ?? '')[0] ?? ''}${(parts[1] ?? '')[0] ?? ''}`.toUpperCase();
}
