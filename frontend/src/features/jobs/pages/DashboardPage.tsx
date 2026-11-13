/** Dashboard: counters that each link to the filtered job list. */

import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  ArrowRight,
  CircleCheck,
  Database,
  Layers,
  ShieldX,
  TriangleAlert,
} from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';

import { PageHeader } from '@/app/AppShell';
import { Button, Card, EmptyState, ErrorBanner, Skeleton, Stat } from '@/components/ui';
import {
  JobStatusBadge,
  VERDICT_FILL,
  VERDICT_RAIL,
  VerdictBadge,
} from '@/components/ui/verdict';
import { Author } from '../components/Author';
import { ApiError } from '@/lib/api-client';
import { formatNumber, formatRelative } from '@/lib/format';
import type { Verdict } from '@/lib/types';
import { jobsApi } from '../api';

const VERDICT_ORDER: Verdict[] = ['malicious', 'suspicious', 'clean', 'unknown'];

/**
 * One template for the header and every row.
 *
 * A flex row sized each badge to its own label, so `Malicious` and `Clean`
 * pushed the columns to different places on every line. Fixed columns line
 * them up by construction, which is the whole reason to read a list like
 * this one vertically.
 */
const ROW_COLUMNS = 'minmax(0, 1fr) 9rem 7.5rem 6rem 7rem';

/**
 * The distribution as one bar rather than four numbers.
 *
 * Four counters make the reader do the division; a single bar shows the shape
 * of the week at a glance, and the figures stay underneath for the exact value.
 */
function VerdictBar({ counts, total }: { counts: Partial<Record<Verdict, number>>; total: number }) {
  if (total === 0) {
    return <p className="text-sm text-muted">No job has been run yet.</p>;
  }
  return (
    <div>
      <div
        className="flex h-2.5 overflow-hidden rounded-pill bg-surface-sunken"
        role="img"
        aria-label={VERDICT_ORDER.map((key) => `${counts[key] ?? 0} ${key}`).join(', ')}
      >
        {VERDICT_ORDER.map((key) => {
          const value = counts[key] ?? 0;
          if (value === 0) return null;
          return (
            <span
              key={key}
              className={`${VERDICT_FILL[key]} transition-[width] duration-slow ease-out`}
              style={{ width: `${(value / total) * 100}%` }}
            />
          );
        })}
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
        {VERDICT_ORDER.map((key) => (
          <div key={key} className="flex items-center gap-2">
            <span className={`h-2.5 w-2.5 shrink-0 rounded-sm ${VERDICT_FILL[key]}`} aria-hidden />
            <dt className="text-xs capitalize text-muted">{key}</dt>
            <dd className="ml-auto text-sm font-medium tabular">
              {formatNumber(counts[key] ?? 0)}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function DashboardPage() {
  const navigate = useNavigate();
  const statsQuery = useQuery({ queryKey: ['job-stats'], queryFn: jobsApi.stats });
  const recentQuery = useQuery({
    queryKey: ['jobs', 'recent'],
    queryFn: () => jobsApi.list({ page: 1, page_size: 8 }),
  });

  if (statsQuery.isLoading) {
    return (
      <div>
        <PageHeader breadcrumb={['Home', 'Dashboard']} title="Dashboard" />
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, index) => (
            <Skeleton key={index} className="h-24 rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  if (statsQuery.error) {
    return (
      <ErrorBanner
        message={
          statsQuery.error instanceof ApiError
            ? statsQuery.error.message
            : 'The dashboard could not be loaded.'
        }
        onRetry={() => void statsQuery.refetch()}
      />
    );
  }

  const stats = statsQuery.data;
  const verdicts = stats?.jobs_by_verdict ?? {};
  const statuses = stats?.jobs_by_status ?? {};
  const total = Object.values(verdicts).reduce((sum, value) => sum + value, 0);
  const cached = stats?.reports_from_cache ?? 0;
  const reports = stats?.reports_total ?? 0;
  const ratio = Math.round((stats?.cache_hit_ratio ?? 0) * 100);

  return (
    <div>
      <PageHeader
        breadcrumb={['Home', 'Dashboard']}
        title="Dashboard"
        description="Team activity and the quota saved by the report cache."
        actions={
          <Button onClick={() => navigate('/jobs')} icon={<Layers className="h-4 w-4" aria-hidden />}>
            All jobs
          </Button>
        }
      />

      <div className="mb-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Jobs total"
          value={formatNumber(total)}
          hint={`${formatNumber(statuses.RUNNING ?? 0)} running now`}
          icon={<Activity className="h-4 w-4" aria-hidden />}
          onClick={() => navigate('/jobs')}
        />
        <Stat
          label="Malicious"
          value={formatNumber(verdicts.malicious ?? 0)}
          hint={total > 0 ? `${Math.round(((verdicts.malicious ?? 0) / total) * 100)}% of all jobs` : undefined}
          tone="danger"
          icon={<ShieldX className="h-4 w-4" aria-hidden />}
          onClick={() => navigate('/jobs?verdict=malicious')}
        />
        <Stat
          label="Suspicious"
          value={formatNumber(verdicts.suspicious ?? 0)}
          hint="Worth a second look"
          tone="warning"
          icon={<TriangleAlert className="h-4 w-4" aria-hidden />}
          onClick={() => navigate('/jobs?verdict=suspicious')}
        />
        <Stat
          label="Clean"
          value={formatNumber(verdicts.clean ?? 0)}
          hint="No source raised anything"
          tone="success"
          icon={<CircleCheck className="h-4 w-4" aria-hidden />}
          onClick={() => navigate('/jobs?verdict=clean')}
        />
      </div>

      <div className="mb-4 grid gap-4 lg:grid-cols-2">
        <Card
          title="Verdict distribution"
          description="Across every job the team can see."
          icon={<Layers className="h-4 w-4" aria-hidden />}
        >
          <VerdictBar counts={verdicts} total={total} />
          {(statuses.PARTIAL_FAILURE ?? 0) > 0 ? (
            <Link
              to="/jobs?status=PARTIAL_FAILURE"
              className="mt-4 flex items-center gap-2 rounded-lg border border-warning-border bg-warning-soft px-3 py-2 text-xs text-warning transition-colors duration-fast ease-out hover:border-warning"
            >
              <TriangleAlert className="h-3.5 w-3.5 shrink-0" aria-hidden />
              {formatNumber(statuses.PARTIAL_FAILURE ?? 0)} job(s) finished with at least one
              source failing.
            </Link>
          ) : null}
        </Card>

        <Card
          title="Quota saved"
          description="Every cached report is one external API call that was not spent."
          icon={<Database className="h-4 w-4" aria-hidden />}
        >
          <div className="flex items-end justify-between gap-4">
            <div>
              <p className="text-3xl font-semibold tabular text-info">{ratio}%</p>
              <p className="mt-1 text-xs text-muted">served from the cache</p>
            </div>
            <p className="text-right text-xs text-muted">
              <span className="block text-sm font-medium tabular text-content">
                {formatNumber(cached)} / {formatNumber(reports)}
              </span>
              reports stored
            </p>
          </div>
          <div
            className="mt-3 h-2.5 overflow-hidden rounded-pill bg-surface-sunken"
            role="img"
            aria-label={`${ratio}% of reports served from the cache`}
          >
            <span
              className="block h-full rounded-pill bg-gradient-to-r from-accent-from to-accent-to transition-[width] duration-slow ease-out"
              style={{ width: `${Math.min(100, Math.max(0, ratio))}%` }}
            />
          </div>
        </Card>
      </div>

      <Card
        title="Latest jobs"
        icon={<Activity className="h-4 w-4" aria-hidden />}
        actions={
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate('/jobs')}
            trailing={<ArrowRight className="h-3.5 w-3.5" aria-hidden />}
          >
            View all
          </Button>
        }
        bodyClassName="p-0"
      >
        {recentQuery.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }).map((_, index) => (
              <Skeleton key={index} className="h-9 rounded-md" />
            ))}
          </div>
        ) : (recentQuery.data?.items ?? []).length === 0 ? (
          <EmptyState
            icon={<Activity className="h-5 w-5" aria-hidden />}
            title="Nothing has run yet"
            description="The jobs the team submits appear here."
            action={
              <Button variant="primary" onClick={() => navigate('/scan')}>
                New scan
              </Button>
            }
          />
        ) : (
          <ul>
            {/* A header, because the rows below are a table of data and the
                columns are easier to read once they are named. */}
            <li
              className="grid items-center gap-3 border-b border-border py-2 pl-4 pr-4 text-[11px] font-medium text-faint"
              style={{ gridTemplateColumns: ROW_COLUMNS }}
            >
              <span>Observable</span>
              <span className="hidden md:block">Requested by</span>
              <span>Verdict</span>
              <span>Status</span>
              <span className="hidden text-right sm:block">Created</span>
            </li>
            {(recentQuery.data?.items ?? []).map((job) => (
              <li key={job.id} className="border-b border-border-subtle last:border-0">
                <Link
                  to={`/jobs/${job.id}`}
                  className="group relative grid items-center gap-3 py-2.5 pl-4 pr-4 transition-colors duration-fast ease-out hover:bg-surface-hover"
                  style={{ gridTemplateColumns: ROW_COLUMNS }}
                >
                  <span
                    className={`absolute inset-y-0 left-0 w-[3px] ${VERDICT_RAIL[job.verdict]}`}
                    aria-hidden
                  />
                  <span className="min-w-0 truncate font-mono text-xs group-hover:text-primary">
                    {job.observable_value}
                  </span>
                  <Author name={job.requested_by_name} className="hidden md:flex" />
                  {/* The badges size to their own text, so each sits in a cell
                      of its own rather than pushing the next one along. */}
                  <span className="min-w-0">
                    <VerdictBadge verdict={job.verdict} />
                  </span>
                  <span className="min-w-0">
                    <JobStatusBadge status={job.status} />
                  </span>
                  <span className="hidden whitespace-nowrap text-right text-xs text-muted sm:block">
                    {formatRelative(job.created_at)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
