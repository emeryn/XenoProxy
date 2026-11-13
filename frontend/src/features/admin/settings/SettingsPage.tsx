/**
 * Instance settings: vertical tabs on the left, one section saved at a time.
 *
 * The selected tab lives in the URL, so a link points at a section and the back
 * button works. Saving is per section, because a section is validated as a
 * whole on the backend and a partial save would be a partial subsystem.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, Upload } from 'lucide-react';
import { useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { PageHeader } from '@/app/AppShell';
import { Badge, Button, Card, ErrorBanner, Skeleton } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError } from '@/lib/api-client';
import type { ProbeResult, SectionValues } from '@/lib/types';
import { ScalarSection } from './ScalarSection';
import { AssistantProfiles, PROFILE_OWNED } from './AssistantProfiles';
import { SectionForm } from './SectionForm';
import { settingsApi } from './api';

type TabKind = 'scalar' | 'section';

interface Tab {
  id: string;
  label: string;
  kind: TabKind;
  description: string;
  /** The probe's target field, for the sections whose test needs one. */
  testTarget?: { label: string; placeholder: string; required?: boolean };
  /** A section with no probe gets no Test button. */
  testable?: boolean;
}

const SECURITY_TAB: Tab = {
  id: 'security',
  label: 'Security',
  kind: 'scalar',
  description: 'Sessions, two-factor requirements and what a first sign-in demands.',
};

const TABS: Tab[] = [
  SECURITY_TAB,
  {
    id: 'scanning',
    label: 'Scanning',
    kind: 'scalar',
    description: 'Defaults for a new job, cache reuse, concurrency and the pivot limits.',
  },
  {
    id: 'retention',
    label: 'Retention',
    kind: 'scalar',
    description: 'How long jobs and inactive accounts are kept.',
  },
  {
    id: 'network',
    label: 'Network & certificates',
    kind: 'section',
    description:
      'The proxy every outbound call goes through, and the certificate authorities it trusts. Analyzers, connectors and the assistant all use it.',
    testable: true,
    testTarget: { label: 'Address to fetch', placeholder: 'https://example.com/' },
  },
  {
    id: 'assistant',
    label: 'Assistant',
    kind: 'section',
    description:
      'The chatbot and its inference server. The browser never calls the model: the backend does, through the network settings above.',
    testable: true,
  },
  {
    id: 'oidc',
    label: 'Single sign-on',
    kind: 'section',
    description: 'OpenID Connect. A field pinned by the deployment is shown read-only.',
    testable: true,
  },
  {
    id: 'ldap',
    label: 'Directory',
    kind: 'section',
    description: 'LDAPS or StartTLS authentication against a company directory.',
    testable: true,
    testTarget: { label: 'Account to look up (optional)', placeholder: 'jdoe' },
  },
  {
    id: 'smtp',
    label: 'E-mail',
    kind: 'section',
    description: 'The outgoing mail server the notifications use.',
    testable: true,
    testTarget: {
      label: 'Send a test message to',
      placeholder: 'you@example.com',
      required: true,
    },
  },
  {
    id: 'notifications',
    label: 'Notifications',
    kind: 'section',
    description: 'Who hears about a job that finished with a bad verdict.',
    testable: true,
  },
  {
    id: 'mcp',
    label: 'MCP servers',
    kind: 'section',
    description:
      'The two endpoints an AI agent drives XenoProxy through. Both are off until you turn them on, and neither grants a right the token’s account does not already have.',
  },
];

function ProbeOutcome({ result }: { result: ProbeResult }) {
  return (
    <div
      className={`mt-4 rounded-lg border p-3.5 text-sm ${
        result.ok
          ? 'border-success-border bg-success-soft'
          : 'border-danger-border bg-danger-soft'
      }`}
      role="status"
    >
      <p className="flex flex-wrap items-center gap-2 font-medium">
        {result.ok ? <Badge tone="success">Reached</Badge> : <Badge tone="danger">Failed</Badge>}
        {result.detail}
        <span className="text-xs text-muted">{result.elapsed_ms} ms</span>
      </p>
      {result.route ? <p className="mt-1 text-xs text-muted">Route: {result.route}</p> : null}
      {result.models?.length ? (
        <p className="mt-1 text-xs text-muted">Models: {result.models.join(', ')}</p>
      ) : null}
      {result.found ? (
        <pre className="mt-2 overflow-x-auto rounded bg-surface-sunken p-2 text-xs">
          {JSON.stringify(result.found, null, 2)}
        </pre>
      ) : null}
    </div>
  );
}

export function InstanceSettingsPage() {
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const toast = useToast();
  const fileInput = useRef<HTMLInputElement>(null);
  const [probe, setProbe] = useState<Record<string, ProbeResult>>({});

  const active = params.get('tab') ?? SECURITY_TAB.id;
  const tab = TABS.find((entry) => entry.id === active) ?? SECURITY_TAB;

  const query = useQuery({ queryKey: ['admin', 'settings'], queryFn: settingsApi.read });

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ['admin', 'settings'] });
    void queryClient.invalidateQueries({ queryKey: ['assistant'] });
  }

  function reportError(title: string) {
    return (error: unknown) =>
      toast.error(title, error instanceof ApiError ? error.message : 'Unexpected failure.');
  }

  const scalarMutation = useMutation({
    mutationFn: settingsApi.patchScalars,
    onSuccess: (result) => {
      toast.success(`${result.applied.length} setting(s) saved`);
      invalidate();
    },
    onError: reportError('The settings were refused'),
  });

  const sectionMutation = useMutation({
    mutationFn: (values: SectionValues) => settingsApi.saveSection(tab.id, values),
    onSuccess: () => {
      toast.success(`${tab.label} saved`);
      invalidate();
    },
    onError: reportError(`${tab.label} was refused`),
  });

  const testMutation = useMutation({
    mutationFn: ({ values, target }: { values: SectionValues; target: string }) =>
      settingsApi.testSection(tab.id, values, target || undefined),
    onSuccess: (result) => setProbe((previous) => ({ ...previous, [tab.id]: result })),
    onError: reportError('The test could not be run'),
  });

  const exportMutation = useMutation({
    mutationFn: settingsApi.exportConfiguration,
    onSuccess: (exported) => {
      const blob = new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'xenoproxy-configuration.json';
      link.click();
      URL.revokeObjectURL(url);
      toast.success('Configuration exported', 'It carries no credential.');
    },
    onError: reportError('The export failed'),
  });

  const importMutation = useMutation({
    mutationFn: settingsApi.importConfiguration,
    onSuccess: (result) => {
      toast.success(
        'Configuration imported',
        `${result.sections.length} section(s), ${result.settings.length} setting(s).`,
      );
      invalidate();
    },
    onError: reportError('The configuration was refused'),
  });

  function onFileChosen(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    void file.text().then((text) => {
      try {
        importMutation.mutate(JSON.parse(text));
      } catch {
        toast.error('The file is not valid JSON');
      }
    });
  }

  if (query.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (query.error || !query.data) {
    return (
      <ErrorBanner
        message={
          query.error instanceof ApiError
            ? query.error.message
            : 'The settings could not be loaded.'
        }
        onRetry={() => void query.refetch()}
      />
    );
  }

  const config = query.data;
  const managed = config.managed_by_environment[tab.id] ?? [];
  const probeResult = probe[tab.id];

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        breadcrumb={['Home', 'Admin', 'Settings']}
        title="Instance settings"
        description="What applies to the whole deployment. Credentials are sealed in the backend vault and are never returned to the browser."
        actions={
          <>
            <input
              ref={fileInput}
              type="file"
              accept="application/json"
              className="hidden"
              onChange={onFileChosen}
            />
            <Button
              loading={importMutation.isPending}
              onClick={() => fileInput.current?.click()}
              icon={<Upload className="h-4 w-4" aria-hidden />}
            >
              Import
            </Button>
            <Button
              loading={exportMutation.isPending}
              onClick={() => exportMutation.mutate()}
              icon={<Download className="h-4 w-4" aria-hidden />}
            >
              Export
            </Button>
          </>
        }
      />

      <div className="grid gap-5 md:grid-cols-[232px_1fr]">
        <nav
          aria-label="Settings sections"
          className="md:sticky md:top-[calc(var(--topbar-height)+1.25rem)] md:self-start"
        >
          <ul className="flex gap-1 overflow-x-auto pb-1 md:flex-col md:overflow-visible md:pb-0">
            {TABS.map((entry) => {
              const active = entry.id === tab.id;
              return (
                <li key={entry.id}>
                  <button
                    type="button"
                    aria-current={active ? 'page' : undefined}
                    onClick={() => {
                      const next = new URLSearchParams(params);
                      next.set('tab', entry.id);
                      setParams(next, { replace: true });
                    }}
                    className={`relative w-full shrink-0 whitespace-nowrap rounded-lg px-3 py-2 text-left text-sm transition-colors duration-fast ease-out focus-visible:shadow-focus focus-visible:outline-none ${
                      active
                        ? 'bg-primary-soft font-medium text-primary'
                        : 'text-muted hover:bg-surface-hover hover:text-content'
                    }`}
                  >
                    {/* The same active marker the main navigation uses, so the
                        two rails read as one system. */}
                    <span
                      className={`absolute left-0 top-1/2 hidden h-5 w-[3px] -translate-y-1/2 rounded-r-pill bg-primary transition-opacity duration-base ease-out md:block ${
                        active ? 'opacity-100' : 'opacity-0'
                      }`}
                      aria-hidden
                    />
                    {entry.label}
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        <Card title={tab.label} description={tab.description}>
          {tab.kind === 'scalar' ? (
            <ScalarSection
              specs={config.settings.filter((spec) => spec.section === tab.id)}
              onSave={(values) => scalarMutation.mutate(values)}
              saving={scalarMutation.isPending}
            />
          ) : (
            <SectionForm
              key={tab.id}
              name={tab.id}
              schema={config.section_schemas[tab.id] ?? { properties: {} }}
              stored={config.sections[tab.id] ?? {}}
              managed={managed}
              saving={sectionMutation.isPending}
              testing={testMutation.isPending}
              testTarget={tab.testTarget}
              hidden={tab.id === 'assistant' ? PROFILE_OWNED : undefined}
              onSave={(values) => sectionMutation.mutate(values)}
              onTest={
                tab.testable
                  ? (values, target) => testMutation.mutate({ values, target })
                  : undefined
              }
            >
              {tab.id === 'assistant' ? <AssistantProfiles /> : null}
              {tab.id === 'network' ? (
                <p className="mb-4 text-xs text-muted">
                  In force now: {config.outbound_route}
                </p>
              ) : null}
            </SectionForm>
          )}

          {probeResult ? <ProbeOutcome result={probeResult} /> : null}
        </Card>
      </div>
    </div>
  );
}