/**
 * New scan page.
 *
 * The observable is classified by the backend while the analyst types, which
 * drives the plugin and playbook filtering: only what can actually run on the
 * detected type is offered.
 *
 * The page is built around the input rather than around a form. Everything
 * below it appears once there is something to analyse, so an analyst with an
 * address on the clipboard sees one field and nothing else.
 *
 * Analyzers are front and centre. Connectors and pivots sit in their own
 * section and are never pre-selected, because one sends the result to a third
 * party and the other creates further jobs — both have to be a deliberate
 * choice, not something an analyst trips over.
 */

import { useMutation, useQuery } from '@tanstack/react-query';
import {
  CircleAlert,
  GitBranch,
  Paperclip,
  Play,
  RefreshCw,
  Send,
  History,
  Sparkles,
  Star,
  StarOff,
  Tag,
  Wand,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { useAuth } from '@/app/auth-context';

import {
  Badge,
  Button,
  Card,
  ErrorBanner,
  Field,
  Input,
  SelectTile,
  Skeleton,
  Toggle,
} from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ObservableTypeBadge, VerdictBadge } from '@/components/ui/verdict';
import { LogoMark } from '@/components/ui/Logo';
import { ApiError } from '@/lib/api-client';
import { formatRelative, formatTtl } from '@/lib/format';
import type { Plugin } from '@/lib/types';
import { scanApi, type SubmitPayload } from '../api';
import { fieldErrors, parseTags, scanFormSchema } from '../schemas';

const DEBOUNCE_MS = 350;

/** The plugins the backend said can run on this observable, of one phase. */
function runnable(plugins: Plugin[] | undefined, names: string[] | undefined): Plugin[] {
  if (!plugins || !names) return [];
  const allowed = new Set(names);
  return plugins.filter((plugin) => allowed.has(plugin.name));
}

// Used when the analyst has expressed no preference: it needs no credential,
// so it works on a deployment where nothing has been configured yet.
const FALLBACK_PLAYBOOK = 'Free sources only';

const EXAMPLES = ['8.8.8.8', 'example.com', 'https://example.com/login', '44d88612fea8a8f36de82e1278abb02f'];


/** The digest of a file, computed in the browser so it can drive the preview.
 *
 * The backend hashes the bytes again and uses its own result, so this is a
 * convenience rather than a claim: it lets a picked file flow through the same
 * classification, compatibility and playbook machinery as a typed hash.
 */
async function digestOf(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const hashed = await window.crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashed))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export function NewScanPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const { user, refresh } = useAuth();

  const [raw, setRaw] = useState('');
  const [debounced, setDebounced] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [selectedConnectors, setSelectedConnectors] = useState<string[]>([]);
  const [selectedPivots, setSelectedPivots] = useState<string[]>([]);
  const [playbook, setPlaybook] = useState<string | null>(null);
  const [tagInput, setTagInput] = useState('');
  const [forceRescan, setForceRescan] = useState(false);
  const [sample, setSample] = useState<File | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  // Set once the user's default playbook has been applied, so reopening the
  // page does not re-apply it over a selection they have since changed.
  const defaultApplied = useRef(false);

  useEffect(() => {
    const handle = window.setTimeout(() => setDebounced(raw.trim()), DEBOUNCE_MS);
    return () => window.clearTimeout(handle);
  }, [raw]);

  const previewQuery = useQuery({
    queryKey: ['preview', debounced],
    queryFn: () => scanApi.preview(debounced),
    enabled: debounced.length > 0,
    retry: false,
  });

  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: () => scanApi.plugins() });
  const playbooksQuery = useQuery({ queryKey: ['playbooks'], queryFn: scanApi.playbooks });
  const recentQuery = useQuery({
    queryKey: ['jobs', 'recent', 5],
    queryFn: () => scanApi.recent(5),
  });

  const preview = previewQuery.data;
  const previewError = previewQuery.error;

  const plugins = pluginsQuery.data;

  const compatible = useMemo(
    () => runnable(plugins, preview?.compatible_analyzers),
    [plugins, preview?.compatible_analyzers],
  );
  const connectors = useMemo(
    () => runnable(plugins, preview?.compatible_connectors),
    [plugins, preview?.compatible_connectors],
  );
  const pivots = useMemo(
    () => runnable(plugins, preview?.compatible_pivots),
    [plugins, preview?.compatible_pivots],
  );

  const unavailable = useMemo<Plugin[]>(() => {
    if (!preview || !plugins) return [];
    const allowed = new Set(preview.compatible_analyzers);
    return plugins.filter(
      (plugin) =>
        plugin.plugin_type === 'analyzer' &&
        !allowed.has(plugin.name) &&
        plugin.supported_types.includes(preview.type),
    );
  }, [preview, plugins]);

  const availablePlaybooks = useMemo(() => {
    if (!preview || !playbooksQuery.data) return [];
    const names = new Set(preview.compatible_playbooks);
    return playbooksQuery.data.filter((entry) => names.has(entry.name));
  }, [preview, playbooksQuery.data]);

  /**
   * Choosing a playbook ticks the analyzers it contains.
   *
   * A playbook is a starting point, not a sealed box: the boxes it ticks are
   * ordinary selections afterwards, so an analyst can drop the one source they
   * do not want without abandoning the preset. The backend honours the explicit
   * list over the playbook's for exactly this reason.
   */
  function choosePlaybook(entry: { name: string; analyzers: string[] } | null) {
    if (entry === null) {
      setPlaybook(null);
      setSelected([]);
      return;
    }
    setPlaybook(entry.name);
    const runnable = new Set(compatible.map((plugin) => plugin.name));
    setSelected(entry.analyzers.filter((analyzer) => runnable.has(analyzer)));
  }

  /**
   * The playbook a scan starts from, applied once the catalogue is known.
   *
   * The analyst's own choice wins. Without one, the page falls back to the
   * keyless preset, so a first scan runs something rather than presenting an
   * empty list of ticks to an analyst who has not configured anything yet.
   */
  useEffect(() => {
    if (defaultApplied.current || compatible.length === 0 || availablePlaybooks.length === 0) {
      return;
    }
    const entry =
      availablePlaybooks.find((item) => item.name === user?.default_playbook) ??
      availablePlaybooks.find((item) => item.name === FALLBACK_PLAYBOOK);
    defaultApplied.current = true;
    if (entry) choosePlaybook(entry);
  }, [user?.default_playbook, availablePlaybooks, compatible]);

  // Keep only selections that remain valid when the observable type changes.
  useEffect(() => {
    if (!preview) return;
    const allowedAnalyzers = new Set(preview.compatible_analyzers);
    const allowedConnectors = new Set(preview.compatible_connectors);
    const allowedPivots = new Set(preview.compatible_pivots);
    setSelected((current) => current.filter((name) => allowedAnalyzers.has(name)));
    setSelectedConnectors((current) => current.filter((name) => allowedConnectors.has(name)));
    setSelectedPivots((current) => current.filter((name) => allowedPivots.has(name)));
    setPlaybook((current) =>
      current && preview.compatible_playbooks.includes(current) ? current : null,
    );
  }, [preview]);

  const tags = useMemo(() => parseTags(tagInput), [tagInput]);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const submitMutation = useMutation({
    mutationFn: scanApi.submit,
    onSuccess: (job) => {
      const analyzerCount = job.reports.filter(
        (report) => report.plugin_type === 'analyzer',
      ).length;
      toast.success('The job has been queued.', `${analyzerCount} analyzer(s) running.`);
      navigate(`/jobs/${job.id}`);
    },
    onError: (error) => {
      const message = error instanceof ApiError ? error.message : 'The job could not be submitted.';
      toast.error('Submission refused', message);
    },
  });

  const fileMutation = useMutation({
    mutationFn: ({ file, options }: { file: File; options: Omit<SubmitPayload, 'observable'> }) =>
      scanApi.submitFile(file, options),
    onSuccess: (job) => {
      toast.success('The sample has been queued.', `${job.reports.length} source(s) running.`);
      navigate(`/jobs/${job.id}`);
    },
    onError: (error) => {
      const message = error instanceof ApiError ? error.message : 'The file could not be submitted.';
      toast.error('Submission refused', message);
    },
  });

  const preferenceMutation = useMutation({
    mutationFn: (name: string | null) => scanApi.savePreferences(name),
    onSuccess: async (_result, name) => {
      await refresh();
      toast.success(name ? `${name} is now your default.` : 'Default playbook cleared.');
    },
    onError: (error) => {
      const message = error instanceof ApiError ? error.message : 'The preference was refused.';
      toast.error('Preference not saved', message);
    },
  });

  function toggleIn(setter: React.Dispatch<React.SetStateAction<string[]>>, name: string) {
    setter((current) =>
      current.includes(name) ? current.filter((item) => item !== name) : [...current, name],
    );
  }

  const selectedPlaybook = availablePlaybooks.find((entry) => entry.name === playbook);
  const canSubmit =
    Boolean(preview) && !submitMutation.isPending && (selected.length > 0 || playbook !== null);

  function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!preview) return;

    const candidate = {
      observable: preview.value,
      analyzers: selected,
      connectors: selectedConnectors,
      pivots: selectedPivots,
      playbook,
      tags,
      force_rescan: forceRescan,
    };
    const result = scanFormSchema.safeParse(candidate);
    if (!result.success) {
      setErrors(fieldErrors(result));
      return;
    }
    setErrors({});
    if (sample) {
      // The digest travels as the file, not as a value: the backend computes
      // it from the bytes and ignores anything the caller claims.
      const { observable, ...rest } = result.data;
      void observable;
      fileMutation.mutate({ file: sample, options: rest });
      return;
    }
    submitMutation.mutate(result.data);
  }

  async function chooseSample(file: File | null) {
    setSample(file);
    if (!file) {
      setRaw('');
      return;
    }
    // Showing the digest is also how the analyst can tell at a glance whether
    // the team has already looked at this sample.
    setRaw(await digestOf(file));
  }

  const willSpawnChildren =
    selectedPivots.length > 0 || (selectedPlaybook?.pivots ?? []).length > 0;

  return (
    <form onSubmit={submit} className="mx-auto max-w-5xl pb-24">
      {/* The input is the page, so it gets the first screen rather than a
          breadcrumb and a title the analyst does not need to read twice. */}
      <section className="mb-7 text-center">
        <LogoMark size={44} className="mx-auto" />
        <h1 className="mt-3.5 text-3xl font-semibold">
          What are we <span className="text-gradient">looking at</span>?
        </h1>
        <p className="mx-auto mt-2 max-w-xl text-sm text-muted">
          Paste an address, a domain, a URL or a hash. XenoProxy detects the type and queries every
          source you pick in parallel.
        </p>

        <div className="relative mx-auto mt-6 max-w-2xl">
          <Input
            id="observable"
            value={raw}
            onChange={(event) => {
              setRaw(event.target.value);
              // Typing over a digest means the analyst moved on from the file.
              if (sample) setSample(null);
            }}
            placeholder="8.8.8.8 · example.com · https://example.com/path · a file hash"
            autoFocus
            maxLength={2048}
            spellCheck={false}
            aria-label="Observable to analyse"
            className="h-14 rounded-xl px-5 text-center font-mono text-base shadow-md"
          />
        </div>

        {/* A sample, for the analyst who holds the file rather than its hash.
            The digest is computed here and fills the field above, so the file
            goes through the same classification and playbook machinery. */}
        <input
          ref={fileInput}
          type="file"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.[0] ?? null;
            event.target.value = '';
            void chooseSample(file);
          }}
        />
        <div className="mx-auto mt-3 flex max-w-2xl items-center justify-center gap-2">
          {sample ? (
            <span className="flex items-center gap-2 rounded-pill border border-primary-border bg-primary-soft px-3 py-1 text-xs text-primary">
              <Paperclip className="h-3.5 w-3.5" aria-hidden />
              <span className="max-w-64 truncate font-medium">{sample.name}</span>
              <span className="text-faint">{Math.max(1, Math.round(sample.size / 1024))} KiB</span>
              <button
                type="button"
                aria-label="Remove the sample"
                onClick={() => void chooseSample(null)}
                className="rounded-pill p-0.5 hover:bg-primary-border"
              >
                <X className="h-3 w-3" aria-hidden />
              </button>
            </span>
          ) : (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => fileInput.current?.click()}
              icon={<Paperclip className="h-3.5 w-3.5" aria-hidden />}
            >
              Analyse a file instead
            </Button>
          )}
        </div>

        {/* The detection tray: it reports what the backend made of the input,
            which is the one thing the analyst must confirm before running. */}
        <div className="mx-auto mt-3.5 flex min-h-8 max-w-2xl items-center justify-center">
          {previewQuery.isFetching && debounced ? (
            <Skeleton className="h-6 w-56 rounded-pill" />
          ) : preview ? (
            <div className="flex flex-wrap items-center justify-center gap-2 animate-fade-rise">
              <ObservableTypeBadge type={preview.type} />
              <code className="rounded-pill border border-border bg-surface-sunken px-2.5 py-0.5 font-mono text-xs">
                {preview.value}
              </code>
              {preview.refanged ? <Badge tone="info">Refanged</Badge> : null}
              {preview.hash_algorithm ? (
                <Badge tone="neutral">{preview.hash_algorithm.toUpperCase()}</Badge>
              ) : null}
              {preview.is_private ? <Badge tone="warning">Non-routable</Badge> : null}
              <Badge tone="neutral" title="Caps which sources may run and who may read the job">
                TLP:{preview.tlp.toUpperCase()}
              </Badge>
            </div>
          ) : previewError ? (
            <div className="w-full text-left">
              <ErrorBanner
                message={
                  previewError instanceof ApiError
                    ? previewError.message
                    : 'The observable could not be classified.'
                }
                requestId={previewError instanceof ApiError ? previewError.requestId : undefined}
              />
            </div>
          ) : (
            <div className="flex flex-wrap items-center justify-center gap-1.5 text-xs text-faint">
              <span>Try</span>
              {EXAMPLES.map((example) => (
                <button
                  key={example}
                  type="button"
                  onClick={() => setRaw(example)}
                  className="rounded-pill border border-border bg-surface-raised px-2.5 py-0.5 font-mono text-xs text-muted transition-colors duration-fast ease-out hover:border-primary-border hover:text-primary"
                >
                  {example}
                </button>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* What the team just looked at. It fills the page before anything is
          typed, and it is the shortest path to the common case: the analyst
          wants the job they ran five minutes ago, not a new one. */}
      {!preview && !previewQuery.isFetching ? (
        <section className="mx-auto max-w-3xl animate-fade-rise">
          <p className="mb-2 flex items-center gap-1.5 px-1 text-[11px] font-semibold uppercase tracking-wide text-faint">
            <History className="h-3 w-3" aria-hidden />
            Recent scans
          </p>
          {recentQuery.isLoading ? (
            <div className="space-y-1.5">
              {Array.from({ length: 5 }).map((_, index) => (
                <Skeleton key={index} className="h-11 rounded-lg" />
              ))}
            </div>
          ) : (recentQuery.data?.items ?? []).length === 0 ? (
            <p className="px-1 text-xs text-faint">
              Nothing yet. The team's scans appear here as they are run.
            </p>
          ) : (
            <ul className="space-y-1.5">
              {(recentQuery.data?.items ?? []).map((job) => (
                <li key={job.id}>
                  <Link
                    to={`/jobs/${job.id}`}
                    className="group flex items-center gap-3 rounded-lg border border-border bg-surface-raised px-3 py-2 transition-colors duration-fast ease-out hover:border-border-strong"
                  >
                    <span className="min-w-0 flex-1 truncate text-left font-mono text-xs group-hover:text-primary">
                      {job.observable_value}
                    </span>
                    <span className="hidden shrink-0 sm:block">
                      <ObservableTypeBadge type={job.observable_type} />
                    </span>
                    <span className="w-28 shrink-0">
                      <VerdictBadge verdict={job.verdict} />
                    </span>
                    <span className="hidden w-24 shrink-0 text-right text-[11px] text-faint md:block">
                      {formatRelative(job.created_at)}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : null}

      {preview ? (
        <div className="space-y-4 animate-fade-rise">
          <Card
            title="Playbook"
            description="A preset pipeline for this observable type. Pick one, or choose sources yourself below."
            icon={<Wand className="h-4 w-4" aria-hidden />}
            actions={
              playbook ? (
                <>
                  <Button
                    variant="ghost"
                    size="sm"
                    type="button"
                    loading={preferenceMutation.isPending}
                    onClick={() =>
                      preferenceMutation.mutate(
                        user?.default_playbook === playbook ? null : playbook,
                      )
                    }
                    icon={
                      user?.default_playbook === playbook ? (
                        <StarOff className="h-3.5 w-3.5" aria-hidden />
                      ) : (
                        <Star className="h-3.5 w-3.5" aria-hidden />
                      )
                    }
                  >
                    {user?.default_playbook === playbook ? 'Not my default' : 'Make default'}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    type="button"
                    onClick={() => choosePlaybook(null)}
                  >
                    Clear
                  </Button>
                </>
              ) : null
            }
          >
            {availablePlaybooks.length === 0 ? (
              <p className="text-sm text-muted">
                No playbook applies to a {preview.type} observable yet.
              </p>
            ) : (
              <div
                role="radiogroup"
                aria-label="Playbook"
                className="grid gap-2.5 sm:grid-cols-2"
              >
                {availablePlaybooks.map((entry) => {
                  const entryPivots = entry.pivots ?? [];
                  const entryConnectors = entry.connectors ?? [];
                  return (
                    <SelectTile
                      key={entry.id}
                      multiple={false}
                      selected={playbook === entry.name}
                      onToggle={() =>
                        choosePlaybook(playbook === entry.name ? null : entry)
                      }
                      title={entry.name}
                      description={entry.description}
                      badges={
                        <>
                          {user?.default_playbook === entry.name ? (
                            <Badge tone="primary">Your default</Badge>
                          ) : null}
                          {entryPivots.length > 0 ? (
                            <Badge tone="warning">Creates child jobs</Badge>
                          ) : null}
                          {entryConnectors.length > 0 ? (
                            <Badge tone="info">Exports results</Badge>
                          ) : null}
                        </>
                      }
                      footer={
                        <>
                          {entry.analyzers.length} analyzer(s)
                          {entryConnectors.length > 0
                            ? `, ${entryConnectors.length} connector(s)`
                            : ''}
                          {entryPivots.length > 0 ? `, ${entryPivots.length} pivot(s)` : ''}
                        </>
                      }
                    />
                  );
                })}
              </div>
            )}
          </Card>

          <Card
            title="Analyzers"
            description="Only configured and enabled sources supporting this type are listed."
            icon={<Sparkles className="h-4 w-4" aria-hidden />}
            actions={
              compatible.length > 0 ? (
                <>
                  <Badge tone={selected.length > 0 ? 'primary' : 'neutral'}>
                    {selected.length} / {compatible.length}
                  </Badge>
                  <Button
                    variant="ghost"
                    size="sm"
                    type="button"
                    onClick={() => setSelected(compatible.map((plugin) => plugin.name))}
                  >
                    All
                  </Button>
                  <Button variant="ghost" size="sm" type="button" onClick={() => setSelected([])}>
                    None
                  </Button>
                </>
              ) : null
            }
          >
            {pluginsQuery.isLoading ? (
              <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
                {Array.from({ length: 6 }).map((_, index) => (
                  <Skeleton key={index} className="h-20 rounded-lg" />
                ))}
              </div>
            ) : compatible.length === 0 ? (
              <div className="flex items-start gap-3 rounded-lg border border-warning-border bg-warning-soft p-3.5">
                <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
                <div className="text-sm">
                  <p className="font-medium">No analyzer is ready for this observable type.</p>
                  <p className="mt-1 text-xs text-muted">
                    An administrator must configure an API key and enable the source in Admin,
                    Plugins &amp; keys.
                  </p>
                </div>
              </div>
            ) : (
              <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
                {compatible.map((plugin) => (
                  <SelectTile
                    key={plugin.name}
                    selected={selected.includes(plugin.name)}
                    onToggle={() => toggleIn(setSelected, plugin.name)}
                    title={plugin.label}
                    description={plugin.description}
                    badges={plugin.free_tier ? <Badge tone="success">Free</Badge> : null}
                    footer={`Cache ${formatTtl(plugin.cache_ttl_seconds)}`}
                  />
                ))}
              </div>
            )}

            {unavailable.length > 0 ? (
              <details className="group mt-4 rounded-lg border border-border-subtle bg-surface-sunken px-3 py-2">
                <summary className="cursor-pointer text-xs text-muted marker:text-faint">
                  {unavailable.length} compatible source(s) are not available yet
                </summary>
                <ul className="mt-2 space-y-1.5">
                  {unavailable.map((plugin) => (
                    <li key={plugin.name} className="text-xs text-muted">
                      <span className="font-medium text-content">{plugin.label}</span>
                      {' — '}
                      {plugin.missing_secrets.length > 0
                        ? `missing credential: ${plugin.missing_secrets.join(', ')}`
                        : 'disabled by an administrator'}
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
          </Card>

          {connectors.length > 0 || pivots.length > 0 ? (
            <Card
              title="After the analysis"
              description="Optional. Neither runs unless you pick it here or the playbook includes it."
              icon={<Send className="h-4 w-4" aria-hidden />}
            >
              {connectors.length > 0 ? (
                <fieldset className={pivots.length > 0 ? 'mb-5' : undefined}>
                  <legend className="field-label flex items-center gap-1.5">
                    <Send className="h-3.5 w-3.5" aria-hidden />
                    Publish the result
                  </legend>
                  <p className="mb-2.5 text-xs text-muted">
                    The observable, its verdict and its tags leave this instance for the platform
                    you choose.
                  </p>
                  <div className="grid gap-2.5 sm:grid-cols-2">
                    {connectors.map((plugin) => (
                      <SelectTile
                        key={plugin.name}
                        selected={selectedConnectors.includes(plugin.name)}
                        onToggle={() => toggleIn(setSelectedConnectors, plugin.name)}
                        title={plugin.label}
                        description={plugin.description}
                        footer={
                          plugin.run_on_verdicts && plugin.run_on_verdicts.length > 0
                            ? `Only on: ${plugin.run_on_verdicts.join(', ')}`
                            : undefined
                        }
                      />
                    ))}
                  </div>
                </fieldset>
              ) : null}

              {pivots.length > 0 ? (
                <fieldset>
                  <legend className="field-label flex items-center gap-1.5">
                    <GitBranch className="h-3.5 w-3.5" aria-hidden />
                    Follow the result
                  </legend>
                  <p className="mb-2.5 text-xs text-muted">
                    A pivot analyses what it derives from this job, creating a child job for each
                    observable. It only acts on a suspicious or malicious verdict.
                  </p>
                  <div className="grid gap-2.5 sm:grid-cols-2">
                    {pivots.map((plugin) => (
                      <SelectTile
                        key={plugin.name}
                        selected={selectedPivots.includes(plugin.name)}
                        onToggle={() => toggleIn(setSelectedPivots, plugin.name)}
                        title={plugin.label}
                        description={plugin.description}
                        footer={`Up to ${plugin.max_children ?? 1} child job(s)${
                          plugin.child_playbook ? `, running “${plugin.child_playbook}”` : ''
                        }`}
                      />
                    ))}
                  </div>
                </fieldset>
              ) : null}
            </Card>
          ) : null}

          <Card title="Options" icon={<Tag className="h-4 w-4" aria-hidden />}>
            <Field
              label="Tags"
              htmlFor="tags"
              hint="Comma-separated. Tags make the job easier to find in the team history."
            >
              <Input
                id="tags"
                value={tagInput}
                onChange={(event) => setTagInput(event.target.value)}
                placeholder="phishing, incident-2026-04"
                maxLength={512}
              />
              {tags.length > 0 ? (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {tags.map((tag) => (
                    <Badge key={tag} tone="primary">
                      {tag}
                    </Badge>
                  ))}
                </div>
              ) : null}
            </Field>

            <Toggle
              checked={forceRescan}
              onChange={setForceRescan}
              label={
                <span className="flex items-center gap-1.5">
                  <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                  Force a refresh, ignoring the cache
                </span>
              }
              description="Every selected source is queried again and consumes its API quota."
            />
          </Card>
        </div>
      ) : null}

      {/* The action bar floats over the page so the count and the button are
          reachable without scrolling back, however long the source list is. */}
      {preview ? (
        <div className="fixed inset-x-0 bottom-0 z-20 px-4 pb-4 lg:pl-[calc(var(--sidebar-width)+2rem)] lg:pr-8">
          <div className="glass mx-auto flex max-w-3xl flex-wrap items-center justify-between gap-3 rounded-xl border border-border p-3 shadow-lg">
            <div className="min-w-0">
              <p className="text-sm">
                {playbook ? (
                  <span className="font-medium text-primary">{playbook}</span>
                ) : null}
                <span className={playbook ? 'text-muted' : 'font-medium'}>
                  {playbook ? ' · ' : ''}
                  {selected.length} analyzer{selected.length === 1 ? '' : 's'}
                  {selectedConnectors.length > 0 ? ` · ${selectedConnectors.length} export(s)` : ''}
                  {selectedPivots.length > 0 ? ` · ${selectedPivots.length} pivot(s)` : ''}
                </span>
              </p>
              {willSpawnChildren ? (
                <p className="mt-0.5 text-xs text-warning">
                  May create child jobs on a suspicious or malicious verdict.
                </p>
              ) : null}
              {errors.analyzers || errors.observable || errors.tags ? (
                <p className="mt-0.5 text-xs text-danger" role="alert">
                  {errors.analyzers ?? errors.observable ?? errors.tags}
                </p>
              ) : null}
            </div>
            <Button
              type="submit"
              variant="primary"
              size="lg"
              disabled={!canSubmit}
              loading={submitMutation.isPending}
              icon={<Play className="h-4 w-4" aria-hidden />}
            >
              Run the analysis
            </Button>
          </div>
        </div>
      ) : null}
    </form>
  );
}
