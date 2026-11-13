/** Playbook management.
 *
 * A playbook names the plugins of each phase. The three lists are separate
 * because the phases are: analyzers enrich, connectors publish the result,
 * pivots derive the next observable. Only the analyzer list is mandatory —
 * connectors and pivots act on an analysis, so there has to be one.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Plus, Save, Trash2, X } from 'lucide-react';
import { useState } from 'react';

import { PageHeader } from '@/app/AppShell';
import { Badge, Button, Card, ErrorBanner, Field, Input, Skeleton } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError } from '@/lib/api-client';
import type { ObservableType, Playbook, PluginType } from '@/lib/types';
import { adminApi, type PlaybookPayload } from '../api';

const OBSERVABLE_TYPES: ObservableType[] = ['ip', 'domain', 'url', 'hash', 'file', 'generic'];

const EMPTY: PlaybookPayload = {
  name: '',
  description: '',
  observable_types: [],
  analyzers: [],
  connectors: [],
  pivots: [],
  enabled: true,
};

/** The phase lists, in the order the orchestrator runs them. */
const PHASES: {
  key: 'analyzers' | 'connectors' | 'pivots';
  type: PluginType;
  legend: string;
  hint: string;
}[] = [
  {
    key: 'analyzers',
    type: 'analyzer',
    legend: 'Analyzers',
    hint: 'Run first, concurrently, and decide the verdict.',
  },
  {
    key: 'connectors',
    type: 'connector',
    legend: 'Connectors',
    hint: 'Run once a verdict exists and publish the finished job outside this instance.',
  },
  {
    key: 'pivots',
    type: 'pivot',
    legend: 'Pivots',
    hint: 'Run last and create a child job per observable they derive.',
  },
];

function PlaybookForm({
  initial,
  pluginNames,
  onCancel,
  onSubmit,
  submitting,
}: {
  initial: PlaybookPayload;
  pluginNames: Record<PluginType, string[]>;
  onCancel: () => void;
  onSubmit: (payload: PlaybookPayload) => void;
  submitting: boolean;
}) {
  const [draft, setDraft] = useState<PlaybookPayload>(initial);

  function toggleType(type: ObservableType) {
    setDraft((previous) => ({
      ...previous,
      observable_types: previous.observable_types.includes(type)
        ? previous.observable_types.filter((entry) => entry !== type)
        : [...previous.observable_types, type],
    }));
  }

  function togglePlugin(phase: 'analyzers' | 'connectors' | 'pivots', name: string) {
    setDraft((previous) => ({
      ...previous,
      [phase]: previous[phase].includes(name)
        ? previous[phase].filter((entry) => entry !== name)
        : [...previous[phase], name],
    }));
  }

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(draft);
      }}
      className="p-4"
    >
      <Field label="Name" htmlFor="playbook-name" required>
        <Input
          id="playbook-name"
          value={draft.name}
          maxLength={128}
          required
          onChange={(event) => setDraft((previous) => ({ ...previous, name: event.target.value }))}
        />
      </Field>
      <Field label="Description" htmlFor="playbook-description">
        <Input
          id="playbook-description"
          value={draft.description}
          maxLength={512}
          onChange={(event) =>
            setDraft((previous) => ({ ...previous, description: event.target.value }))
          }
        />
      </Field>

      <fieldset className="mb-4">
        <legend className="field-label">Observable types (empty means every type)</legend>
        <div className="flex flex-wrap gap-3">
          {OBSERVABLE_TYPES.map((type) => (
            <label key={type} className="flex items-center gap-1.5 text-sm">
              <input
                type="checkbox"
                className="h-4 w-4"
                checked={draft.observable_types.includes(type)}
                onChange={() => toggleType(type)}
              />
              {type}
            </label>
          ))}
        </div>
      </fieldset>

      {PHASES.map((phase) => (
        <fieldset key={phase.key} className="mb-4">
          <legend className="field-label">
            {phase.legend} ({draft[phase.key].length} selected)
          </legend>
          <p className="mb-2 text-xs text-muted">{phase.hint}</p>
          {pluginNames[phase.type].length === 0 ? (
            <p className="text-xs text-muted">
              No {phase.type} is registered on this instance.
            </p>
          ) : (
            <div className="grid gap-2 sm:grid-cols-3">
              {pluginNames[phase.type].map((name) => (
                <label key={name} className="flex items-center gap-1.5 text-sm">
                  <input
                    type="checkbox"
                    className="h-4 w-4"
                    checked={draft[phase.key].includes(name)}
                    onChange={() => togglePlugin(phase.key, name)}
                  />
                  {name}
                </label>
              ))}
            </div>
          )}
        </fieldset>
      ))}

      <label className="mb-4 flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          className="h-4 w-4"
          checked={draft.enabled}
          onChange={(event) => setDraft((previous) => ({ ...previous, enabled: event.target.checked }))}
        />
        Available to analysts
      </label>

      <div className="flex justify-end gap-2">
        <Button type="button" onClick={onCancel} icon={<X className="h-4 w-4" aria-hidden />}>
          Cancel
        </Button>
        <Button
          type="submit"
          variant="primary"
          loading={submitting}
          disabled={!draft.name.trim() || draft.analyzers.length === 0}
          icon={<Save className="h-4 w-4" aria-hidden />}
        >
          Save
        </Button>
      </div>
    </form>
  );
}

export function PlaybooksPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState<Playbook | 'new' | null>(null);

  const playbooksQuery = useQuery({ queryKey: ['playbooks'], queryFn: adminApi.playbooks });
  const pluginsQuery = useQuery({ queryKey: ['admin', 'plugins'], queryFn: () => adminApi.plugins() });

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ['playbooks'] });
  }

  const saveMutation = useMutation({
    mutationFn: (payload: PlaybookPayload) =>
      editing && editing !== 'new'
        ? adminApi.updatePlaybook(editing.id, payload)
        : adminApi.createPlaybook(payload),
    onSuccess: () => {
      toast.success('The playbook has been saved.');
      setEditing(null);
      invalidate();
    },
    onError: (error) => {
      toast.error(
        'The playbook could not be saved',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => adminApi.deletePlaybook(id),
    onSuccess: () => {
      toast.success('The playbook has been deleted.');
      invalidate();
    },
    onError: (error) => {
      toast.error(
        'The playbook could not be deleted',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const pluginNames: Record<PluginType, string[]> = {
    analyzer: [],
    connector: [],
    pivot: [],
  };
  for (const plugin of pluginsQuery.data ?? []) {
    pluginNames[plugin.plugin_type].push(plugin.name);
  }

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        breadcrumb={['Home', 'Admin', 'Playbooks']}
        title="Playbooks"
        description="Preset plugin pipelines offered to analysts per observable type: which analyzers run, what the result is published to, and where the investigation pivots next."
        actions={
          <Button
            variant="primary"
            onClick={() => setEditing('new')}
            icon={<Plus className="h-4 w-4" aria-hidden />}
          >
            New playbook
          </Button>
        }
      />

      {editing ? (
        <Card title={editing === 'new' ? 'New playbook' : `Edit ${editing.name}`} className="mb-4">
          <PlaybookForm
            initial={
              editing === 'new'
                ? EMPTY
                : {
                    name: editing.name,
                    description: editing.description,
                    observable_types: editing.observable_types,
                    analyzers: editing.analyzers,
                    connectors: editing.connectors ?? [],
                    pivots: editing.pivots ?? [],
                    enabled: editing.enabled,
                  }
            }
            pluginNames={pluginNames}
            onCancel={() => setEditing(null)}
            onSubmit={(payload) => saveMutation.mutate(payload)}
            submitting={saveMutation.isPending}
          />
        </Card>
      ) : null}

      {playbooksQuery.isLoading ? (
        <Skeleton className="h-40" />
      ) : playbooksQuery.error ? (
        <ErrorBanner
          message={
            playbooksQuery.error instanceof ApiError
              ? playbooksQuery.error.message
              : 'The playbooks could not be loaded.'
          }
          onRetry={() => void playbooksQuery.refetch()}
        />
      ) : (
        <div className="space-y-3">
          {(playbooksQuery.data ?? []).map((playbook) => (
            <Card
              key={playbook.id}
              title={
                <span className="flex flex-wrap items-center gap-2">
                  {playbook.name}
                  {playbook.is_builtin ? <Badge tone="info">Built-in</Badge> : null}
                  {(playbook.pivots ?? []).length > 0 ? (
                    <Badge tone="warning" title="Jobs run from this playbook may create further jobs">
                      Creates child jobs
                    </Badge>
                  ) : null}
                  {(playbook.connectors ?? []).length > 0 ? (
                    <Badge tone="info" title="Results from this playbook are published outside this instance">
                      Exports results
                    </Badge>
                  ) : null}
                  {playbook.enabled ? (
                    <Badge tone="success">Available</Badge>
                  ) : (
                    <Badge>Hidden</Badge>
                  )}
                </span>
              }
              description={playbook.description}
              actions={
                <>
                  <Button onClick={() => setEditing(playbook)}>Edit</Button>
                  {playbook.is_builtin ? null : (
                    <Button
                      variant="danger"
                      aria-label={`Delete the playbook ${playbook.name}`}
                      onClick={() => {
                        if (window.confirm(`Delete the playbook "${playbook.name}"?`)) {
                          deleteMutation.mutate(playbook.id);
                        }
                      }}
                      icon={<Trash2 className="h-4 w-4" aria-hidden />}
                    />
                  )}
                </>
              }
            >
              <p className="mb-2 text-xs text-muted">
                Types: {playbook.observable_types.join(', ') || 'every type'}
              </p>
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-1">
                  <span className="mr-1 text-xs text-muted">Analyzers:</span>
                  {playbook.analyzers.map((name) => (
                    <Badge key={name}>{name}</Badge>
                  ))}
                </div>
                {(playbook.connectors ?? []).length > 0 ? (
                  <div className="flex flex-wrap items-center gap-1">
                    <span className="mr-1 text-xs text-muted">Connectors:</span>
                    {playbook.connectors.map((name) => (
                      <Badge key={name} tone="info">
                        {name}
                      </Badge>
                    ))}
                  </div>
                ) : null}
                {(playbook.pivots ?? []).length > 0 ? (
                  <div className="flex flex-wrap items-center gap-1">
                    <span className="mr-1 text-xs text-muted">Pivots:</span>
                    {playbook.pivots.map((name) => (
                      <Badge key={name} tone="warning">
                        {name}
                      </Badge>
                    ))}
                  </div>
                ) : null}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
