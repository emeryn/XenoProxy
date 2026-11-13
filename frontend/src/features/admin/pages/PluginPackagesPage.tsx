/** Admin page for installed plugin packages: install from a zip, rescan the volume, remove.
 *
 * A package may contribute an analyzer, a connector or a pivot; its type comes
 * from the class it declares, which is why the row states it rather than
 * assuming an analyzer.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  CircleAlert,
  ExternalLink,
  Puzzle,
  RefreshCw,
  Trash2,
  Upload,
} from 'lucide-react';
import { useRef, useState } from 'react';

import { PageHeader } from '@/app/AppShell';
import { Badge, Button, Card, EmptyState, ErrorBanner, Skeleton } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError, api } from '@/lib/api-client';
import type { PluginState } from '@/lib/types';

function formatBytes(bytes: number): string {
  return `${Math.round(bytes / (1024 * 1024))} MiB`;
}

export function PluginPackagesPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const fileInput = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const query = useQuery({
    queryKey: ['admin', 'plugin-packages'],
    queryFn: () => api.get<PluginState>('/admin/plugin-packages'),
  });

  function refresh() {
    void queryClient.invalidateQueries({ queryKey: ['admin', 'plugin-packages'] });
    void queryClient.invalidateQueries({ queryKey: ['admin', 'plugins'] });
    void queryClient.invalidateQueries({ queryKey: ['plugins'] });
  }

  const installMutation = useMutation({
    mutationFn: async (file: File) => {
      const body = new FormData();
      body.append('archive', file);
      const response = await fetch('/api/v1/admin/plugin-packages', {
        method: 'POST',
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
          'Idempotency-Key': crypto.randomUUID(),
        },
        credentials: 'same-origin',
        body,
      });
      const text = await response.text();
      const payload = text ? JSON.parse(text) : null;
      if (!response.ok) {
        throw new ApiError(response.status, payload, 'The plugin could not be installed.');
      }
      return payload as PluginState;
    },
    onSuccess: () => {
      toast.success(
        'The plugin has been installed.',
        'Configure its credentials and enable it in Plugins & keys.',
      );
      refresh();
    },
    onError: (error) => {
      toast.error(
        'The plugin was rejected',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const reloadMutation = useMutation({
    mutationFn: () => api.post<PluginState>('/admin/plugin-packages/reload'),
    onSuccess: (state) => {
      toast.success(`Rescan complete: ${state.plugins.length} plugin(s) found.`);
      refresh();
    },
    onError: (error) => {
      toast.error(
        'The rescan failed',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (name: string) => api.delete<{ message: string }>(`/admin/plugin-packages/${name}`),
    onSuccess: (response) => {
      toast.success(response.message);
      refresh();
    },
    onError: (error) => {
      toast.error(
        'The plugin could not be removed',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  function submitFile(file: File | undefined) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.zip')) {
      toast.error('Only a .zip archive can be installed.');
      return;
    }
    installMutation.mutate(file);
  }

  const state = query.data;
  const uploadDisabled =
    !state?.enabled || !state?.upload_enabled || installMutation.isPending;

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        breadcrumb={['Home', 'Admin', 'Plugin packages']}
        title="Plugin packages"
        description="Add an analyzer, a connector or a pivot without rebuilding the image: upload a zip, or drop a folder into the plugins volume and rescan."
        actions={
          <Button
            loading={reloadMutation.isPending}
            onClick={() => reloadMutation.mutate()}
            icon={<RefreshCw className="h-4 w-4" aria-hidden />}
          >
            Rescan the volume
          </Button>
        }
      />

      <div className="mb-4 flex items-start gap-2 rounded-lg border border-warning-border bg-warning-soft p-3">
        <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
        <p className="text-xs">
          A plugin runs inside the backend with its privileges, so installing one is as
          consequential as installing a Python package. Read the code first and accept plugins
          only from a source you trust. Every installation is written to the audit trail with
          the archive digest.
        </p>
      </div>

      {query.isLoading ? (
        <Skeleton className="h-40" />
      ) : query.error ? (
        <ErrorBanner
          message={
            query.error instanceof ApiError
              ? query.error.message
              : 'The plugins could not be loaded.'
          }
          onRetry={() => void query.refetch()}
        />
      ) : (
        <>
          <Card
            title="Install from an archive"
            description={
              state?.enabled
                ? `Zip archive holding plugin.json, up to ${formatBytes(state.max_archive_bytes)}.`
                : 'Plugins are disabled on this instance.'
            }
            className="mb-4"
          >
            <div
              onDragOver={(event) => {
                event.preventDefault();
                if (!uploadDisabled) setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(event) => {
                event.preventDefault();
                setDragging(false);
                if (!uploadDisabled) submitFile(event.dataTransfer.files[0]);
              }}
              className={`flex flex-col items-center gap-3 rounded-lg border border-dashed p-6 text-center transition-colors ${
                dragging ? 'border-primary bg-surface-sunken' : 'border-border'
              } ${uploadDisabled ? 'opacity-60' : ''}`}
            >
              <Upload className="h-6 w-6 text-muted" aria-hidden />
              <p className="text-sm">Drop a plugin archive here, or choose a file.</p>
              <input
                ref={fileInput}
                type="file"
                accept=".zip,application/zip"
                className="sr-only"
                onChange={(event) => {
                  submitFile(event.target.files?.[0]);
                  event.target.value = '';
                }}
              />
              <Button
                variant="primary"
                disabled={uploadDisabled}
                loading={installMutation.isPending}
                onClick={() => fileInput.current?.click()}
              >
                Choose an archive
              </Button>
              {state?.directory ? (
                <p className="text-xs text-muted">
                  Plugins directory in the container: <code>{state.directory}</code>
                </p>
              ) : null}
            </div>
          </Card>

          <Card title={`Installed plugins (${state?.plugins.length ?? 0})`}>
            {!state || state.plugins.length === 0 ? (
              <EmptyState
                title="No plugin installed"
                description="Upload an archive above, or copy a plugin folder into the plugins volume and rescan."
              />
            ) : (
              <ul className="divide-y divide-border">
                {state.plugins.map((plugin) => (
                  <li key={plugin.name} className="py-3">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                          <Puzzle className="h-4 w-4 text-primary" aria-hidden />
                          {plugin.manifest?.label ?? plugin.name}
                          <code className="text-xs text-muted">{plugin.name}</code>
                          {plugin.manifest?.version ? (
                            <Badge>v{plugin.manifest.version}</Badge>
                          ) : null}
                          {plugin.loaded ? (
                            <Badge tone="success">Loaded</Badge>
                          ) : (
                            <Badge tone="danger">Not loaded</Badge>
                          )}
                        </p>
                        {plugin.manifest?.description ? (
                          <p className="mt-1 text-xs text-muted">{plugin.manifest.description}</p>
                        ) : null}
                        {plugin.plugin ? (
                          <p className="mt-1 text-xs text-muted">
                            Registered as a {plugin.plugin.plugin_type}
                            {plugin.plugin.supported_types.length > 0
                              ? ` · supports: ${plugin.plugin.supported_types.join(', ')}`
                              : ' · applies to every observable type'}
                            {plugin.plugin.secrets.length > 0
                              ? ` · credentials: ${plugin.plugin.secrets
                                  .map((secret) => secret.name)
                                  .join(', ')}`
                              : ' · no credential needed'}
                          </p>
                        ) : null}
                        {plugin.manifest?.author ? (
                          <p className="mt-1 text-xs text-muted">
                            By {plugin.manifest.author}
                            {plugin.manifest.homepage ? (
                              <>
                                {' · '}
                                <a
                                  href={plugin.manifest.homepage}
                                  target="_blank"
                                  rel="noreferrer noopener"
                                  className="inline-flex items-center gap-1 text-primary hover:underline"
                                >
                                  Homepage
                                  <ExternalLink className="h-3 w-3" aria-hidden />
                                </a>
                              </>
                            ) : null}
                          </p>
                        ) : null}
                        {plugin.error ? (
                          <p className="mt-2 rounded-lg border border-danger-border bg-danger-soft p-2 text-xs text-danger">
                            {plugin.error}
                          </p>
                        ) : null}
                      </div>
                      <Button
                        variant="danger"
                        aria-label={`Remove the plugin ${plugin.name}`}
                        loading={deleteMutation.isPending}
                        onClick={() => {
                          if (
                            window.confirm(
                              `Remove the plugin "${plugin.name}"? Its stored credentials are kept.`,
                            )
                          ) {
                            deleteMutation.mutate(plugin.name);
                          }
                        }}
                        icon={<Trash2 className="h-4 w-4" aria-hidden />}
                      />
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-4 text-xs text-muted">
              A new plugin is picked up immediately. Replacing one that is already loaded needs a
              backend restart, because the previous module stays imported.
            </p>
          </Card>
        </>
      )}
    </div>
  );
}
