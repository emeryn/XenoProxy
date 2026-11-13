/**
 * Team job history.
 *
 * Filters, sort and pagination live in the query string, so the back button and a
 * shared link restore the exact same view.
 */

import { useQuery } from '@tanstack/react-query';
import { ChevronLeft, ChevronRight, Radar, Search, SlidersHorizontal, X } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';

import { PageHeader } from '@/app/AppShell';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  Input,
  Select,
  TableSkeleton,
} from '@/components/ui';
import {
  JobStatusBadge,
  ObservableTypeBadge,
  VERDICT_RAIL,
  VerdictBadge,
} from '@/components/ui/verdict';
import { Author } from '../components/Author';
import { ApiError } from '@/lib/api-client';
import { formatRelative } from '@/lib/format';
import type { JobStatus, ObservableType, Verdict } from '@/lib/types';
import { jobsApi } from '../api';

const PAGE_SIZES = [25, 50, 100];

const FILTER_KEYS = ['search', 'status', 'verdict', 'observable_type', 'tag'] as const;

const FILTER_LABELS: Record<(typeof FILTER_KEYS)[number], string> = {
  search: 'Observable',
  status: 'Status',
  verdict: 'Verdict',
  observable_type: 'Type',
  tag: 'Tag',
};

export function JobsPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();

  const page = Number(params.get('page') ?? '1');
  const pageSize = Number(params.get('page_size') ?? '25');
  const search = params.get('search') ?? '';
  const status = params.get('status') ?? '';
  const verdict = params.get('verdict') ?? '';
  const observableType = params.get('observable_type') ?? '';
  const tag = params.get('tag') ?? '';

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page') next.delete('page');
    setParams(next, { replace: true });
  }

  function clearFilters() {
    const next = new URLSearchParams(params);
    for (const key of FILTER_KEYS) next.delete(key);
    next.delete('page');
    setParams(next, { replace: true });
  }

  const active = FILTER_KEYS.map((key) => ({ key, value: params.get(key) ?? '' })).filter(
    (entry) => entry.value !== '',
  );

  const query = useQuery({
    queryKey: ['jobs', { page, pageSize, search, status, verdict, observableType, tag }],
    queryFn: () =>
      jobsApi.list({
        page,
        page_size: pageSize,
        ...(search ? { search } : {}),
        ...(status ? { status } : {}),
        ...(verdict ? { verdict } : {}),
        ...(observableType ? { observable_type: observableType } : {}),
        ...(tag ? { tag } : {}),
      }),
    refetchInterval: 15_000,
  });

  const totalPages = query.data ? Math.max(1, Math.ceil(query.data.total / pageSize)) : 1;
  const first = query.data && query.data.total > 0 ? (page - 1) * pageSize + 1 : 0;
  const last = query.data ? Math.min(page * pageSize, query.data.total) : 0;

  return (
    <div>
      <PageHeader
        breadcrumb={['Home', 'Jobs']}
        title="Jobs"
        description="Every analysis run by the team, with its cached and live results."
        actions={
          <Button
            variant="primary"
            onClick={() => navigate('/scan')}
            icon={<Radar className="h-4 w-4" aria-hidden />}
          >
            New scan
          </Button>
        }
      />

      {/* One toolbar rather than a panel of labelled fields: filtering a list
          is a quick adjustment, not a form to fill in. */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative min-w-56 flex-1">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint"
            aria-hidden
          />
          <Input
            id="filter-search"
            aria-label="Search by observable"
            defaultValue={search}
            placeholder="Search an observable…"
            className="rounded-pill pl-9"
            onKeyDown={(event) => {
              if (event.key === 'Enter') setParam('search', event.currentTarget.value.trim());
            }}
            onBlur={(event) => setParam('search', event.currentTarget.value.trim())}
          />
        </div>

        <Select
          aria-label="Filter by observable type"
          value={observableType}
          onChange={(event) => setParam('observable_type', event.target.value)}
          className="w-auto min-w-32"
        >
          <option value="">All types</option>
          {(['ip', 'domain', 'url', 'hash', 'generic'] satisfies ObservableType[]).map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </Select>

        <Select
          aria-label="Filter by verdict"
          value={verdict}
          onChange={(event) => setParam('verdict', event.target.value)}
          className="w-auto min-w-36"
        >
          <option value="">All verdicts</option>
          {(['clean', 'suspicious', 'malicious', 'unknown'] satisfies Verdict[]).map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </Select>

        <Select
          aria-label="Filter by status"
          value={status}
          onChange={(event) => setParam('status', event.target.value)}
          className="w-auto min-w-36"
        >
          <option value="">All statuses</option>
          {(
            ['PENDING', 'RUNNING', 'SUCCESS', 'PARTIAL_FAILURE', 'FAILED'] satisfies JobStatus[]
          ).map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </Select>

        <Input
          aria-label="Filter by tag"
          defaultValue={tag}
          placeholder="Tag"
          className="w-auto min-w-28 rounded-pill"
          onKeyDown={(event) => {
            if (event.key === 'Enter') setParam('tag', event.currentTarget.value.trim());
          }}
          onBlur={(event) => setParam('tag', event.currentTarget.value.trim())}
        />
      </div>

      {active.length > 0 ? (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <SlidersHorizontal className="h-3.5 w-3.5 text-faint" aria-hidden />
          {active.map((entry) => (
            <button
              key={entry.key}
              type="button"
              onClick={() => setParam(entry.key, '')}
              className="group inline-flex items-center gap-1.5 rounded-pill border border-primary-border bg-primary-soft px-2.5 py-0.5 text-xs font-medium text-primary transition-colors duration-fast ease-out hover:border-primary"
            >
              <span className="text-faint">{FILTER_LABELS[entry.key]}</span>
              {entry.value}
              <X className="h-3 w-3" aria-hidden />
              <span className="sr-only">Remove this filter</span>
            </button>
          ))}
          <Button variant="ghost" size="sm" onClick={clearFilters}>
            Clear all
          </Button>
        </div>
      ) : null}

      <Card bodyClassName="p-0">
        {query.isLoading ? (
          <TableSkeleton rows={6} columns={6} />
        ) : query.error ? (
          <div className="p-4">
            <ErrorBanner
              message={
                query.error instanceof ApiError
                  ? query.error.message
                  : 'The jobs could not be loaded.'
              }
              requestId={query.error instanceof ApiError ? query.error.requestId : undefined}
              onRetry={() => void query.refetch()}
            />
          </div>
        ) : !query.data || query.data.items.length === 0 ? (
          <EmptyState
            icon={<Radar className="h-5 w-5" aria-hidden />}
            title={active.length > 0 ? 'No job matches these filters' : 'No job yet'}
            description={
              active.length > 0
                ? 'Try removing a filter, or widen the observable search.'
                : 'Submit an observable to start building the team history.'
            }
            action={
              active.length > 0 ? (
                <Button onClick={clearFilters}>Clear the filters</Button>
              ) : (
                <Button variant="primary" onClick={() => navigate('/scan')}>
                  New scan
                </Button>
              )
            }
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full table-fixed text-sm">
                <caption className="sr-only">Team analysis jobs</caption>
                <thead>
                  <tr className="border-b border-border text-xs font-medium text-faint">
                    <th scope="col" className="px-4 py-2.5 text-left">
                      Observable
                    </th>
                    <th scope="col" className="w-24 px-3 py-2.5 text-left">
                      Type
                    </th>
                    <th scope="col" className="w-32 px-3 py-2.5 text-left">
                      Verdict
                    </th>
                    <th scope="col" className="w-28 px-3 py-2.5 text-left">
                      Status
                    </th>
                    <th scope="col" className="w-20 px-3 py-2.5 text-right">
                      Sources
                    </th>
                    <th scope="col" className="w-40 px-3 py-2.5 text-left">
                      Requested by
                    </th>
                    <th scope="col" className="w-28 px-4 py-2.5 text-left">
                      Created
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.items.map((job) => (
                    <tr
                      key={job.id}
                      onClick={() => navigate(`/jobs/${job.id}`)}
                      className="group cursor-pointer border-b border-border-subtle transition-colors duration-fast ease-out last:border-0 hover:bg-surface-hover"
                    >
                      <td className="relative overflow-hidden py-2.5 pl-4 pr-3">
                        <span
                          className={`absolute inset-y-0 left-0 w-[3px] ${VERDICT_RAIL[job.verdict]}`}
                          aria-hidden
                        />
                        <span className="block truncate font-mono text-xs text-content group-hover:text-primary">
                          {job.observable_value}
                        </span>
                        {job.tags.length > 0 ? (
                          <span className="mt-1.5 flex flex-wrap gap-1">
                            {job.tags.slice(0, 4).map((entry) => (
                              <Badge key={entry}>{entry}</Badge>
                            ))}
                          </span>
                        ) : null}
                      </td>
                      <td className="px-3 py-2.5">
                        <ObservableTypeBadge type={job.observable_type} />
                      </td>
                      <td className="px-3 py-2.5">
                        <VerdictBadge verdict={job.verdict} />
                      </td>
                      <td className="px-3 py-2.5">
                        <JobStatusBadge status={job.status} />
                      </td>
                      <td className="px-3 py-2.5 text-right text-muted">{job.analyzer_count}</td>
                      <td className="px-3 py-2.5">
                        <Author name={job.requested_by_name} origin={job.origin} />
                      </td>
                      <td className="whitespace-nowrap px-4 py-2.5 text-muted">
                        {formatRelative(job.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-3">
              <p className="text-xs text-muted">
                <span className="font-medium text-content">
                  {first}–{last}
                </span>{' '}
                of {query.data.total}
              </p>
              <div className="flex items-center gap-2">
                <Select
                  aria-label="Jobs per page"
                  value={String(pageSize)}
                  onChange={(event) => setParam('page_size', event.target.value)}
                  className="w-auto"
                >
                  {PAGE_SIZES.map((size) => (
                    <option key={size} value={size}>
                      {size} per page
                    </option>
                  ))}
                </Select>
                <Button
                  size="sm"
                  aria-label="Previous page"
                  disabled={page <= 1}
                  onClick={() => setParam('page', String(page - 1))}
                  icon={<ChevronLeft className="h-4 w-4" aria-hidden />}
                />
                <span className="text-xs text-muted">
                  {page} / {totalPages}
                </span>
                <Button
                  size="sm"
                  aria-label="Next page"
                  disabled={page >= totalPages}
                  onClick={() => setParam('page', String(page + 1))}
                  icon={<ChevronRight className="h-4 w-4" aria-hidden />}
                />
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
