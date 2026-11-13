/** Status and verdict rendering, identical everywhere in the application. */

import { CircleCheck, CircleSlash, Clock, Loader2, ShieldX, TriangleAlert } from 'lucide-react';
import type { ReactNode } from 'react';

import type { JobStatus, ReportStatus, Verdict } from '@/lib/types';
import { Badge } from './index';

const VERDICT_META: Record<
  Verdict,
  { tone: 'neutral' | 'success' | 'warning' | 'danger'; label: string; icon: ReactNode }
> = {
  unknown: {
    tone: 'neutral',
    label: 'Unknown',
    icon: <CircleSlash className="h-3.5 w-3.5" aria-hidden />,
  },
  clean: {
    tone: 'success',
    label: 'Clean',
    icon: <CircleCheck className="h-3.5 w-3.5" aria-hidden />,
  },
  suspicious: {
    tone: 'warning',
    label: 'Suspicious',
    icon: <TriangleAlert className="h-3.5 w-3.5" aria-hidden />,
  },
  malicious: {
    tone: 'danger',
    label: 'Malicious',
    icon: <ShieldX className="h-3.5 w-3.5" aria-hidden />,
  },
};

const HERO_ICON: Record<'neutral' | 'success' | 'warning' | 'danger', ReactNode> = {
  neutral: <CircleSlash className="h-6 w-6" aria-hidden />,
  success: <CircleCheck className="h-6 w-6" aria-hidden />,
  warning: <TriangleAlert className="h-6 w-6" aria-hidden />,
  danger: <ShieldX className="h-6 w-6" aria-hidden />,
};

/** The solid pairing: a fill and the one foreground that is legible on it. */
const VERDICT_CHIP: Record<Verdict, string> = {
  malicious: 'bg-verdict-malicious text-verdict-malicious-fg',
  suspicious: 'bg-verdict-suspicious text-verdict-suspicious-fg',
  clean: 'bg-verdict-clean text-verdict-clean-fg',
  unknown: 'bg-verdict-unknown text-verdict-unknown-fg',
};

/**
 * The rail down the left edge of a row.
 *
 * Unknown draws nothing. A grey rail against the row surface measures 1.6:1,
 * which is not a signal — it is a smudge. An absent rail is the honest form of
 * "no source had an opinion", and it leaves the coloured rails as the only
 * marks on the list.
 */
export const VERDICT_RAIL: Record<Verdict, string> = {
  malicious: 'bg-verdict-malicious',
  suspicious: 'bg-verdict-suspicious',
  clean: 'bg-verdict-clean',
  unknown: 'bg-transparent',
};

/** The same hue with nothing written on it: bars and legend swatches, where a
 *  neutral segment does need to be visible against its neighbours. */
export const VERDICT_FILL: Record<Verdict, string> = {
  malicious: 'bg-verdict-malicious',
  suspicious: 'bg-verdict-suspicious',
  clean: 'bg-verdict-clean',
  unknown: 'bg-verdict-unknown',
};

/**
 * The verdict, as a solid chip.
 *
 * It does not go through `Badge`: every other chip in the interface is a soft
 * tint, and a verdict has to win against all of them. The label is spelled out
 * next to the icon so the meaning never rests on the colour alone.
 */
export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const meta = VERDICT_META[verdict] ?? VERDICT_META.unknown;
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-pill px-2 py-0.5 text-xs font-semibold ${
        VERDICT_CHIP[verdict] ?? VERDICT_CHIP.unknown
      }`}
    >
      {meta.icon}
      {meta.label}
    </span>
  );
}

/**
 * The job's headline verdict.
 *
 * It is the first thing read on a result page, so it is a tinted panel with a
 * large mark rather than a line of coloured text: the colour has to carry from
 * across the room, and the icon has to carry for a reader who cannot rely on
 * the colour at all.
 */
export function VerdictBanner({ verdict, children }: { verdict: Verdict; children?: ReactNode }) {
  const meta = VERDICT_META[verdict] ?? VERDICT_META.unknown;
  const skin = {
    neutral: 'border-border bg-surface',
    success: 'border-success-border bg-success-soft',
    warning: 'border-warning-border bg-warning-soft',
    danger: 'border-danger-border bg-danger-soft',
  }[meta.tone];
  // The headline takes the verdict hue itself, so the large word and the
  // chips further down the page are the same colour.
  const accent = {
    malicious: 'text-verdict-malicious',
    suspicious: 'text-verdict-suspicious',
    clean: 'text-verdict-clean',
    unknown: 'text-content',
  }[verdict];
  const mark = VERDICT_CHIP[verdict] ?? VERDICT_CHIP.unknown;

  return (
    <div className={`rounded-xl border p-5 shadow-sm ${skin}`}>
      <div className="flex items-center gap-4">
        <span className={`grid h-12 w-12 shrink-0 place-items-center rounded-xl ${mark}`}>
          {HERO_ICON[meta.tone]}
        </span>
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.1em] text-faint">Aggregated verdict</p>
          <p className={`text-2xl font-semibold ${accent}`}>{meta.label}</p>
        </div>
      </div>
      {children}
    </div>
  );
}

const JOB_STATUS_META: Record<JobStatus, { tone: 'neutral' | 'primary' | 'success' | 'warning' | 'danger'; label: string }> = {
  PENDING: { tone: 'neutral', label: 'Pending' },
  RUNNING: { tone: 'primary', label: 'Running' },
  SUCCESS: { tone: 'success', label: 'Success' },
  PARTIAL_FAILURE: { tone: 'warning', label: 'Partial' },
  FAILED: { tone: 'danger', label: 'Failed' },
  KILLED: { tone: 'warning', label: 'Stopped' },
};

export function JobStatusBadge({ status }: { status: JobStatus }) {
  const meta = JOB_STATUS_META[status] ?? JOB_STATUS_META.PENDING;
  return (
    <Badge tone={meta.tone}>
      {status === 'RUNNING' ? <Loader2 className="h-3 w-3 animate-spin" aria-hidden /> : null}
      {meta.label}
    </Badge>
  );
}

const REPORT_STATUS_META: Record<
  ReportStatus,
  { tone: 'neutral' | 'primary' | 'success' | 'danger' | 'warning'; label: string }
> = {
  PENDING: { tone: 'neutral', label: 'Queued' },
  RUNNING: { tone: 'primary', label: 'Running' },
  SUCCESS: { tone: 'success', label: 'Success' },
  FAILED: { tone: 'danger', label: 'Failed' },
  SKIPPED: { tone: 'neutral', label: 'Skipped' },
  KILLED: { tone: 'warning', label: 'Stopped' },
};

export function ReportStatusBadge({ status }: { status: ReportStatus }) {
  const meta = REPORT_STATUS_META[status] ?? REPORT_STATUS_META.PENDING;
  return (
    <Badge tone={meta.tone}>
      {status === 'RUNNING' ? <Loader2 className="h-3 w-3 animate-spin" aria-hidden /> : null}
      {status === 'PENDING' ? <Clock className="h-3 w-3" aria-hidden /> : null}
      {meta.label}
    </Badge>
  );
}

const TYPE_LABEL: Record<string, string> = {
  ip: 'IP',
  domain: 'Domain',
  url: 'URL',
  hash: 'Hash',
  file: 'File',
  generic: 'Generic',
};

export function ObservableTypeBadge({ type }: { type: string }) {
  return <Badge tone="info">{TYPE_LABEL[type] ?? type}</Badge>;
}
