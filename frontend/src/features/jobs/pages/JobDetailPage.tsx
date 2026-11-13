/**
 * Job detail with live progress.
 *
 * While the job is running the page polls at a short interval; it stops as soon
 * as the job reaches a terminal status, so an idle tab costs nothing.
 *
 * The reports are grouped by lifecycle phase — analyzers, then connectors, then
 * pivots — because that is the order they ran in and the only order in which
 * the outcome reads correctly: a connector's "exported" line means nothing until
 * the verdict above it exists.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  CircleStop,
  Database,
  Download,
  ExternalLink,
  FileText,
  Camera,
  GitBranch,
  Paperclip,
  RefreshCw,
  RotateCcw,
  Send,
  Server,
  ServerCrash,
  ShieldAlert,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';

import { PageHeader } from '@/app/AppShell';
import { Badge, Button, Card, ErrorBanner, Skeleton } from '@/components/ui';
import { JsonViewer } from '@/components/ui/JsonViewer';
import { useToast } from '@/components/ui/Toast';
import {
  JobStatusBadge,
  ObservableTypeBadge,
  ReportStatusBadge,
  VerdictBadge,
  VerdictBanner,
} from '@/components/ui/verdict';
import { ApiError } from '@/lib/api-client';
import { cn } from '@/lib/cn';
import { formatDateTime, formatDuration, formatRelative } from '@/lib/format';
import type { Detection, JobDetail, PluginReport, PluginType } from '@/lib/types';
import { jobsApi } from '../api';
import { Author } from '../components/Author';

const TERMINAL = new Set(['SUCCESS', 'PARTIAL_FAILURE', 'FAILED', 'KILLED']);

/** A report that has stopped without a result can be re-armed on its own. */
const RETRYABLE = new Set(['FAILED', 'KILLED', 'SKIPPED']);

const PHASES: { type: PluginType; title: string; description: string }[] = [
  {
    type: 'analyzer',
    title: 'Analyzers',
    description: 'One row per source, with its individual outcome. These decide the verdict.',
  },
  {
    type: 'connector',
    title: 'Exports',
    description: 'Ran once the verdict was aggregated, and published the result elsewhere.',
  },
  {
    type: 'pivot',
    title: 'Pivots',
    description: 'Derived the observables worth analysing next, and created a job for each.',
  },
];

const PHASE_ICON: Record<PluginType, typeof Send> = {
  analyzer: Database,
  connector: Send,
  pivot: GitBranch,
};

function SummaryFacts({ job }: { job: JobDetail }) {
  const summary = job.summary ?? {};
  const facts: { label: string; value: string }[] = [
    { label: 'Open ports', value: (summary.open_ports ?? []).join(', ') || '—' },
    { label: 'Known CVEs', value: (summary.cves ?? []).join(', ') || '—' },
    { label: 'Geolocation', value: (summary.countries ?? []).join(', ') || '—' },
    { label: 'Networks', value: (summary.asns ?? []).join(', ') || '—' },
    { label: 'Organisations', value: (summary.organisations ?? []).join(', ') || '—' },
    { label: 'Hostnames', value: (summary.hostnames ?? []).slice(0, 8).join(', ') || '—' },
  ];
  const ratios = Object.entries(summary.detection_ratios ?? {});

  return (
    <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {facts.map((fact) => (
        <div key={fact.label}>
          <dt className="text-xs font-medium text-faint">{fact.label}</dt>
          <dd className="mt-0.5 break-words font-mono text-xs">{fact.value}</dd>
        </div>
      ))}
      {ratios.length > 0 ? (
        <div>
          <dt className="text-xs font-medium text-faint">Detection ratios</dt>
          <dd className="mt-0.5 font-mono text-xs">
            {ratios.map(([name, ratio]) => `${name}: ${ratio}`).join(', ')}
          </dd>
        </div>
      ) : null}
    </dl>
  );
}

/** Re-run one plugin of a job, leaving the other reports and their quota alone. */
function RetryReportButton({ jobId, report }: { jobId: string; report: PluginReport }) {
  const queryClient = useQueryClient();
  const toast = useToast();

  const mutation = useMutation({
    mutationFn: () => jobsApi.retryReport(jobId, report.id),
    onSuccess: () => {
      toast.success(`${report.plugin_name} has been queued again.`);
      void queryClient.invalidateQueries({ queryKey: ['job', jobId] });
    },
    onError: (error) => {
      toast.error(
        'The retry was refused',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  if (!RETRYABLE.has(report.status)) return null;

  return (
    <Button
      variant="ghost"
      loading={mutation.isPending}
      onClick={(event) => {
        event.stopPropagation();
        mutation.mutate();
      }}
      icon={<RotateCcw className="h-3.5 w-3.5" aria-hidden />}
      aria-label={`Run ${report.plugin_name} again`}
    >
      Retry
    </Button>
  );
}

/**
 * Which engines actually flagged the observable, for a source that runs many.
 *
 * "3/70" tells an analyst how loud the alarm is and nothing about whether to
 * believe it. Three agreeing vendors with the same family name is a finding;
 * three heuristic engines each calling it something different, on a file none
 * of the majors touched, is the background noise of a multi-engine service.
 * That judgement needs the names and what each one called it, which is what
 * this shows — and it shows them whatever the verdict, so a lone detection is
 * visible even when it was not loud enough to change the verdict.
 */
function EngineDetections({ detections }: { detections: Detection[] }) {
  if (detections.length === 0) {
    return null;
  }
  const malicious = detections.filter((entry) => entry.category === 'malicious').length;
  return (
    <section className="rounded-lg border border-border bg-surface-sunken p-3">
      <h4 className="mb-2 flex items-center gap-1.5 text-xs font-medium text-faint">
        <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
        {detections.length} engine{detections.length > 1 ? 's' : ''} flagged this
        {malicious > 0 ? ` — ${malicious} as malicious` : ''}
      </h4>
      <ul className="flex flex-wrap gap-1.5">
        {detections.map((entry) => (
          <li
            key={`${entry.engine}-${entry.result ?? ''}`}
            className={cn(
              'flex items-baseline gap-1.5 rounded-md border px-2 py-1 text-[11px]',
              entry.category === 'malicious'
                ? 'border-danger-border bg-danger-soft'
                : 'border-warning-border bg-warning-soft',
            )}
          >
            <span className="font-medium">{entry.engine}</span>
            {entry.result ? <span className="font-mono text-muted">{entry.result}</span> : null}
          </li>
        ))}
      </ul>
    </section>
  );
}

/** What a pivot derived, and the jobs it created. */
function PivotOutcome({ report }: { report: PluginReport }) {
  const derived = report.derived_observables ?? [];
  const spawned = report.spawned_job_ids ?? [];

  if (derived.length === 0) {
    return (
      <p className="text-sm text-muted">
        {report.summary_data?.headline ?? 'This pivot found nothing to follow.'}
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-sm">{report.summary_data?.headline}</p>
      <ul className="space-y-1">
        {derived.map((entry, index) => (
          <li key={entry.value} className="flex flex-wrap items-center gap-2 text-sm">
            <code className="rounded-md border border-border bg-surface-sunken px-2 py-0.5 font-mono text-xs">{entry.value}</code>
            {entry.reason ? <span className="text-xs text-muted">{entry.reason}</span> : null}
            {spawned[index] ? (
              <Link
                to={`/jobs/${spawned[index]}`}
                className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
              >
                Open the child job
                <ExternalLink className="h-3 w-3" aria-hidden />
              </Link>
            ) : (
              <Badge tone="neutral">No job created</Badge>
            )}
          </li>
        ))}
      </ul>
      {spawned.length === 0 ? (
        <p className="text-xs text-muted">
          No child job was created: pivoting may be turned off for this instance, or the depth
          limit was already reached.
        </p>
      ) : null}
    </div>
  );
}

function ReportPanel({ jobId, report }: { jobId: string; report: PluginReport }) {
  const summary = report.summary_data ?? {};
  const detailQuery = useQuery({
    queryKey: ['job', jobId, 'report', report.plugin_name],
    queryFn: () => jobsApi.report(jobId, report.plugin_name),
    enabled: report.status === 'SUCCESS' || report.status === 'FAILED',
  });

  if (report.status === 'PENDING' || report.status === 'RUNNING') {
    return (
      <div className="space-y-2 p-4">
        <Skeleton className="h-4 w-1/3" />
        <Skeleton className="h-4 w-2/3" />
        <Skeleton className="h-4 w-1/2" />
      </div>
    );
  }

  if (report.status === 'FAILED') {
    return (
      <div className="p-4">
        <div className="flex items-start gap-2.5 rounded-lg border border-danger-border bg-danger-soft p-3.5">
          <ServerCrash className="mt-0.5 h-4 w-4 shrink-0 text-danger" aria-hidden />
          <div>
            <p className="text-sm font-medium text-danger">
              This {report.plugin_type} failed.
            </p>
            <p className="mt-1 text-xs text-muted">{report.errors ?? 'No reason reported.'}</p>
            <p className="mt-2 text-xs text-muted">
              The other plugins of this job were unaffected.
            </p>
            <div className="mt-2">
              <RetryReportButton jobId={jobId} report={report} />
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (report.status === 'KILLED') {
    return (
      <div className="p-4">
        <p className="text-sm text-muted">
          {report.errors ?? 'This plugin was stopped before it produced a result.'}
        </p>
        <div className="mt-2">
          <RetryReportButton jobId={jobId} report={report} />
        </div>
      </div>
    );
  }

  if (report.status === 'SKIPPED') {
    return (
      <div className="p-4">
        <p className="text-sm text-muted">
          {report.errors ?? `This ${report.plugin_type} was skipped.`}
        </p>
        <div className="mt-2">
          <RetryReportButton jobId={jobId} report={report} />
        </div>
      </div>
    );
  }

  if (report.plugin_type === 'pivot') {
    return (
      <div className="space-y-4 p-4">
        <PivotOutcome report={report} />
        <JsonViewer data={detailQuery.data?.raw_output ?? null} />
      </div>
    );
  }

  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-center gap-2">
        {summary.verdict ? <VerdictBadge verdict={summary.verdict} /> : null}
        {report.from_cache ? (
          <Badge tone="info" title="Served from a previous identical lookup">
            <Database className="h-3 w-3" aria-hidden />
            From cache
          </Badge>
        ) : null}
        {summary.score !== null && summary.score !== undefined ? (
          <Badge>Score {summary.score}</Badge>
        ) : null}
        {summary.detection_ratio ? <Badge>Detections {summary.detection_ratio}</Badge> : null}
        <span className="text-xs text-muted">{formatDuration(report.execution_time_ms)}</span>
      </div>

      {summary.headline ? <p className="text-sm">{summary.headline}</p> : null}

      <EngineDetections detections={summary.detections ?? []} />

      {/* The capture comes back through the API, never from the provider: the
          analyst's address stays private and the content policy stays closed
          to remote images. It is a picture of a hostile page, so it is not
          enlarged on hover and nothing in it is clickable. */}
      {summary.screenshot_url ? (
        <figure className="overflow-hidden rounded-lg border border-border bg-surface-sunken">
          <img
            src={`/api/v1/jobs/${jobId}/reports/${report.id}/screenshot`}
            alt={`Page capture taken by ${report.plugin_name}`}
            loading="lazy"
            className="max-h-96 w-full object-contain object-top"
          />
          <figcaption className="flex items-center gap-1.5 border-t border-border-subtle px-3 py-1.5 text-[11px] text-faint">
            <Camera className="h-3 w-3" aria-hidden />
            Captured by {report.plugin_name}. Served from this instance, not from the provider.
          </figcaption>
        </figure>
      ) : null}

      {(summary.tags ?? []).length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {(summary.tags ?? []).map((tag) => (
            <Badge key={tag}>{tag}</Badge>
          ))}
        </div>
      ) : null}

      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: 'Open ports', value: (summary.open_ports ?? []).join(', ') },
          { label: 'Country', value: summary.country ?? '' },
          { label: 'Network', value: summary.asn ?? '' },
          { label: 'Organisation', value: summary.organisation ?? '' },
          { label: 'Hostnames', value: (summary.hostnames ?? []).slice(0, 6).join(', ') },
          { label: 'Running', value: (summary.technologies ?? []).join(', ') },
          { label: 'CVEs', value: (summary.cves ?? []).join(', ') },
        ]
          .filter((entry) => entry.value)
          .map((entry) => (
            <div key={entry.label}>
              <dt className="text-xs font-medium text-faint">{entry.label}</dt>
              <dd className="mt-0.5 break-words font-mono text-xs">{entry.value}</dd>
            </div>
          ))}
      </dl>

      {(summary.links ?? []).filter((link) => link.url).length > 0 ? (
        <div className="flex flex-wrap gap-3">
          {(summary.links ?? [])
            .filter((link) => link.url)
            .map((link) => (
              <a
                key={link.url}
                href={link.url}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
              >
                {link.label}
                <ExternalLink className="h-3 w-3" aria-hidden />
              </a>
            ))}
        </div>
      ) : null}

      <JsonViewer data={detailQuery.data?.raw_output ?? null} />
    </div>
  );
}

/** One table of reports, for one lifecycle phase. */
function PhaseTable({
  job,
  phase,
  onSelect,
}: {
  job: JobDetail;
  phase: (typeof PHASES)[number];
  onSelect: (pluginName: string) => void;
}) {
  const reports = job.reports.filter((report) => report.plugin_type === phase.type);
  if (reports.length === 0) return null;
  const Icon = PHASE_ICON[phase.type];

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted" aria-hidden />
          {phase.title}
        </span>
      }
      description={phase.description}
      className="mb-4"
    >
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <caption className="sr-only">
            {phase.title} results for this job
          </caption>
          <thead>
            <tr className="border-b border-border text-xs font-medium text-faint">
              <th scope="col" className="table-cell">
                Plugin
              </th>
              <th scope="col" className="table-cell">
                Status
              </th>
              {phase.type === 'analyzer' ? (
                <th scope="col" className="table-cell">
                  Verdict
                </th>
              ) : null}
              <th scope="col" className="table-cell">
                Summary
              </th>
              <th scope="col" className="table-cell">
                Duration
              </th>
              <th scope="col" className="table-cell">
                Finished
              </th>
              <th scope="col" className="table-cell">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {reports.map((report) => (
              <tr
                key={report.id}
                className="cursor-pointer transition-colors duration-fast ease-out hover:bg-surface-hover"
                onClick={() => onSelect(report.plugin_name)}
              >
                <td className="table-cell font-medium">
                  {report.plugin_name}
                  {report.from_cache ? (
                    <Badge tone="info" className="ml-2">
                      cache
                    </Badge>
                  ) : null}
                </td>
                <td className="table-cell">
                  <ReportStatusBadge status={report.status} />
                </td>
                {phase.type === 'analyzer' ? (
                  <td className="table-cell">
                    {report.summary_data?.verdict ? (
                      <VerdictBadge verdict={report.summary_data.verdict} />
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </td>
                ) : null}
                <td className="table-cell text-xs text-muted">
                  {report.status === 'FAILED' || report.status === 'SKIPPED'
                    ? report.errors
                    : (report.summary_data?.headline ?? '—')}
                </td>
                <td className="table-cell text-xs text-muted">
                  {formatDuration(report.execution_time_ms)}
                </td>
                <td className="table-cell text-xs text-muted">
                  {formatDateTime(report.finished_at)}
                </td>
                <td className="table-cell">
                  <RetryReportButton jobId={job.id} report={report} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function JobDetailPage() {
  const { jobId = '' } = useParams();
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [exporting, setExporting] = useState<'json' | 'markdown' | null>(null);

  const query = useQuery({
    queryKey: ['job', jobId],
    queryFn: () => jobsApi.get(jobId),
    refetchInterval: (currentQuery) => {
      const data = currentQuery.state.data;
      return data && TERMINAL.has(data.status) ? false : 2000;
    },
  });

  const job = query.data;

  const childrenQuery = useQuery({
    queryKey: ['job', jobId, 'children'],
    queryFn: () => jobsApi.children(jobId),
    // Only worth asking once the job ran a pivot.
    enabled: Boolean(job && (job.requested_pivots ?? []).length > 0),
  });

  const rerunMutation = useMutation({
    mutationFn: () => jobsApi.rerun(jobId),
    onSuccess: (newJob) => {
      toast.success('A fresh run has been queued.');
      void queryClient.invalidateQueries({ queryKey: ['jobs'] });
      window.location.assign(`/jobs/${newJob.id}`);
    },
    onError: (error) => {
      toast.error(
        'The re-run was refused',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const killMutation = useMutation({
    mutationFn: () => jobsApi.kill(jobId),
    onSuccess: (response) => {
      toast.success('Stop requested', response.message);
      void queryClient.invalidateQueries({ queryKey: ['job', jobId] });
    },
    onError: (error) => {
      toast.error(
        'The job could not be stopped',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const activeTab = params.get('tab') ?? 'overview';

  const progress = useMemo(() => {
    if (!job) return { done: 0, total: 0 };
    const done = job.reports.filter(
      (report) => !['PENDING', 'RUNNING'].includes(report.status),
    ).length;
    return { done, total: job.reports.length };
  }, [job]);

  async function download(format: 'json' | 'markdown') {
    setExporting(format);
    try {
      await jobsApi.download(jobId, format);
    } catch (error) {
      toast.error(
        'The export failed',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    } finally {
      setExporting(null);
    }
  }

  function setTab(tab: string) {
    const next = new URLSearchParams(params);
    next.set('tab', tab);
    setParams(next, { replace: true });
  }

  if (query.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-24" />
        <Skeleton className="h-48" />
      </div>
    );
  }

  if (query.error || !job) {
    return (
      <ErrorBanner
        message={
          query.error instanceof ApiError ? query.error.message : 'The job could not be loaded.'
        }
        requestId={query.error instanceof ApiError ? query.error.requestId : undefined}
        onRetry={() => void query.refetch()}
      />
    );
  }

  const running = !TERMINAL.has(job.status);
  const children = childrenQuery.data ?? [];

  return (
    <div>
      <PageHeader
        breadcrumb={['Home', 'Jobs', job.observable_value]}
        title={job.observable_value}
        description={`Submitted ${formatRelative(job.created_at)}.`}
        actions={
          <>
            {running ? (
              <Button
                variant="danger"
                onClick={() => killMutation.mutate()}
                loading={killMutation.isPending}
                icon={<CircleStop className="h-4 w-4" aria-hidden />}
              >
                Stop
              </Button>
            ) : null}
            <Button
              onClick={() => void download('markdown')}
              loading={exporting === 'markdown'}
              icon={<FileText className="h-4 w-4" aria-hidden />}
            >
              Markdown
            </Button>
            <Button
              onClick={() => void download('json')}
              loading={exporting === 'json'}
              icon={<Download className="h-4 w-4" aria-hidden />}
            >
              JSON
            </Button>
            <Button
              variant="primary"
              onClick={() => rerunMutation.mutate()}
              loading={rerunMutation.isPending}
              icon={<RefreshCw className="h-4 w-4" aria-hidden />}
            >
              Re-run
            </Button>
          </>
        }
      />

      {job.parent_job_id ? (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-lg border border-border bg-surface-sunken p-3.5 text-sm">
          <GitBranch className="h-4 w-4 text-muted" aria-hidden />
          <span>
            This job was derived by the <strong>{job.pivot_name}</strong> pivot, at depth{' '}
            {job.depth}.
          </span>
          <Link to={`/jobs/${job.parent_job_id}`} className="text-primary hover:underline">
            Open the parent job
          </Link>
        </div>
      ) : null}

      <VerdictBanner verdict={job.verdict}>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Author name={job.requested_by_name} origin={job.origin} />
          {job.file_name ? (
            <Badge tone="primary" title="Submitted as a file; the observable is its digest">
              <Paperclip className="h-3 w-3" aria-hidden />
              {job.file_name}
              {job.file_size ? ` · ${Math.max(1, Math.round(job.file_size / 1024))} KiB` : ''}
            </Badge>
          ) : null}
          <span className="h-4 w-px bg-border" aria-hidden />
          <ObservableTypeBadge type={job.observable_type} />
          <JobStatusBadge status={job.status} />
          <Badge tone="neutral">TLP:{job.tlp.toUpperCase()}</Badge>
          {job.playbook_name ? <Badge tone="primary">{job.playbook_name}</Badge> : null}
          {job.force_rescan ? <Badge tone="warning">Cache bypassed</Badge> : null}
          {(job.summary?.analyzers_from_cache ?? 0) > 0 ? (
            <Badge tone="info">
              <Database className="h-3 w-3" aria-hidden />
              {job.summary.analyzers_from_cache} from cache
            </Badge>
          ) : null}
          {job.tags.map((tag) => (
            <Badge key={tag}>{tag}</Badge>
          ))}
        </div>

        {/* What is running there, next to the verdict rather than four
            screens down in a raw payload. An analyst reading "malicious" on an
            address asks what it is serving immediately afterwards, and a
            version next to a CVE list is most of the triage. */}
        {(job.summary?.technologies ?? []).length > 0 ? (
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            <span className="flex items-center gap-1 text-xs text-faint">
              <Server className="h-3.5 w-3.5" aria-hidden />
              Running
            </span>
            {(job.summary.technologies ?? []).map((entry) => (
              <span
                key={entry}
                className="rounded-md border border-border bg-surface-sunken px-2 py-0.5 font-mono text-[11px]"
              >
                {entry}
              </span>
            ))}
          </div>
        ) : null}

        {running ? (
          <div className="mt-4">
            <div className="mb-1 flex justify-between text-xs text-muted">
              <span>
                {progress.done} of {progress.total} plugin(s) finished
              </span>
              <span>Updating live</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-pill bg-surface-sunken">
              <div
                className="h-full rounded-pill bg-gradient-to-r from-accent-from to-accent-to transition-[width] duration-slow ease-out"
                style={{
                  width: `${progress.total ? (progress.done / progress.total) * 100 : 0}%`,
                }}
              />
            </div>
          </div>
        ) : null}

        <SummaryFacts job={job} />
      </VerdictBanner>

      <div
        className="mt-5 flex gap-1 overflow-x-auto rounded-lg border border-border bg-surface-sunken p-1"
        role="tablist"
      >
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'overview'}
          onClick={() => setTab('overview')}
          className={`shrink-0 rounded-md px-3 py-1.5 text-sm font-medium transition-colors duration-fast ease-out focus-visible:shadow-focus focus-visible:outline-none ${
            activeTab === 'overview'
              ? 'bg-surface-raised text-content shadow-sm'
              : 'text-muted hover:text-content'
          }`}
        >
          Overview
        </button>
        {job.reports.map((report) => (
          <button
            key={report.plugin_name}
            type="button"
            role="tab"
            aria-selected={activeTab === report.plugin_name}
            onClick={() => setTab(report.plugin_name)}
            className={`flex shrink-0 items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors duration-fast ease-out focus-visible:shadow-focus focus-visible:outline-none ${
              activeTab === report.plugin_name
                ? 'bg-surface-raised text-content shadow-sm'
                : 'text-muted hover:text-content'
            }`}
          >
            {report.plugin_name}
            <ReportStatusBadge status={report.status} />
          </button>
        ))}
      </div>

      <div className="mt-4">
        {activeTab === 'overview' ? (
          <>
            {PHASES.map((phase) => (
              <PhaseTable key={phase.type} job={job} phase={phase} onSelect={setTab} />
            ))}

            {children.length > 0 ? (
              <Card
                title={
                  <span className="flex items-center gap-2">
                    <GitBranch className="h-4 w-4 text-muted" aria-hidden />
                    Child jobs
                  </span>
                }
                description="Jobs a pivot created from this one."
              >
                <ul className="space-y-2">
                  {children.map((child) => (
                    <li key={child.id} className="flex flex-wrap items-center gap-2 text-sm">
                      <Link
                        to={`/jobs/${child.id}`}
                        className="font-mono text-xs text-primary hover:underline"
                      >
                        {child.observable_value}
                      </Link>
                      <ObservableTypeBadge type={child.observable_type} />
                      <JobStatusBadge status={child.status} />
                      <VerdictBadge verdict={child.verdict} />
                      {child.pivot_name ? (
                        <span className="text-xs text-muted">via {child.pivot_name}</span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </Card>
            ) : null}

            {(job.summary?.skipped_plugins ?? []).length > 0 ? (
              <details className="mt-4">
                <summary className="cursor-pointer text-xs text-muted">
                  {job.summary.skipped_plugins?.length} plugin(s) were asked for but could not run
                </summary>
                <ul className="mt-2 space-y-1">
                  {(job.summary.skipped_plugins ?? []).map((entry) => (
                    <li key={`${entry.type}-${entry.name}`} className="text-xs text-muted">
                      <span className="font-medium text-content">{entry.name}</span>
                      {` (${entry.type}) — ${entry.reason}`}
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
          </>
        ) : (
          (() => {
            const report = job.reports.find((entry) => entry.plugin_name === activeTab);
            if (!report) return <Card>No such plugin in this job.</Card>;
            return (
              <Card
                title={
                  <span className="flex items-center gap-2">
                    {report.plugin_name}
                    <Badge tone={report.plugin_type === 'analyzer' ? 'neutral' : 'info'}>
                      {report.plugin_type}
                    </Badge>
                  </span>
                }
              >
                <ReportPanel jobId={job.id} report={report} />
              </Card>
            );
          })()
        )}
      </div>
    </div>
  );
}
