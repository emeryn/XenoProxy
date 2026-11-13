/** Admin page where plugin credentials are configured and plugins are enabled.
 *
 * The filter defaults to analyzers because that is the list an operator opens
 * this page for. Connectors and pivots are one click away and marked, so it is
 * always obvious whether a row publishes outside the instance or creates jobs.
 */

import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';

import { PageHeader } from '@/app/AppShell';
import { Badge, Card, ErrorBanner, Input, Select, Skeleton } from '@/components/ui';
import { ApiError } from '@/lib/api-client';
import type { PluginType } from '@/lib/types';
import { PluginCard } from '../components/PluginCard';
import { adminApi } from '../api';

const TYPE_LABELS: Record<PluginType, string> = {
  analyzer: 'Analyzers',
  connector: 'Connectors and exporters',
  pivot: 'Pivots',
};

export function PluginCatalogPage() {
  const [params, setParams] = useSearchParams();
  const search = params.get('search') ?? '';
  const state = params.get('state') ?? '';
  const pluginType = params.get('type') ?? '';

  const query = useQuery({ queryKey: ['admin', 'plugins'], queryFn: () => adminApi.plugins() });

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  const filtered = useMemo(() => {
    const all = query.data ?? [];
    return all.filter((plugin) => {
      if (search) {
        const term = search.toLowerCase();
        const haystack = `${plugin.name} ${plugin.label} ${plugin.description}`.toLowerCase();
        if (!haystack.includes(term)) return false;
      }
      if (pluginType && plugin.plugin_type !== pluginType) return false;
      if (state === 'enabled' && !plugin.enabled) return false;
      if (state === 'disabled' && plugin.enabled) return false;
      if (state === 'needs_key' && plugin.missing_secrets.length === 0) return false;
      if (state === 'unhealthy' && plugin.health_ok !== false) return false;
      return true;
    });
  }, [query.data, search, state, pluginType]);

  const counts = useMemo(() => {
    const all = query.data ?? [];
    return {
      total: all.length,
      enabled: all.filter((plugin) => plugin.enabled).length,
      needsKey: all.filter((plugin) => plugin.missing_secrets.length > 0).length,
      byType: {
        analyzer: all.filter((plugin) => plugin.plugin_type === 'analyzer').length,
        connector: all.filter((plugin) => plugin.plugin_type === 'connector').length,
        pivot: all.filter((plugin) => plugin.plugin_type === 'pivot').length,
      },
    };
  }, [query.data]);

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        breadcrumb={['Home', 'Admin', 'Plugins & keys']}
        title="Plugins and API keys"
        description="Analyzers enrich an observable, connectors publish a finished job, pivots derive the next observable. Credentials are sealed in the backend vault: they are never returned to the browser, logged or included in API errors."
        actions={
          <>
            <Badge tone="success">{counts.enabled} enabled</Badge>
            <Badge tone="warning">{counts.needsKey} need a key</Badge>
            <Badge>{counts.total} total</Badge>
          </>
        }
      />

      <Card className="mb-4">
        <div className="grid gap-3 p-4 sm:grid-cols-3">
          <div>
            <label className="field-label" htmlFor="plugin-search">
              Search
            </label>
            <Input
              id="plugin-search"
              defaultValue={search}
              placeholder="shodan, hash, opencti…"
              onChange={(event) => setParam('search', event.target.value.trim())}
            />
          </div>
          <div>
            <label className="field-label" htmlFor="plugin-state">
              State
            </label>
            <Select
              id="plugin-state"
              value={state}
              onChange={(event) => setParam('state', event.target.value)}
            >
              <option value="">All states</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
              <option value="needs_key">Missing a credential</option>
              <option value="unhealthy">Last health probe failed</option>
            </Select>
          </div>
          <div>
            <label className="field-label" htmlFor="plugin-type">
              Type
            </label>
            <Select
              id="plugin-type"
              value={pluginType}
              onChange={(event) => setParam('type', event.target.value)}
            >
              <option value="">All types</option>
              <option value="analyzer">{TYPE_LABELS.analyzer} ({counts.byType.analyzer})</option>
              <option value="connector">
                {TYPE_LABELS.connector} ({counts.byType.connector})
              </option>
              <option value="pivot">{TYPE_LABELS.pivot} ({counts.byType.pivot})</option>
            </Select>
          </div>
        </div>
      </Card>

      {query.isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, index) => (
            <Skeleton key={index} className="h-24" />
          ))}
        </div>
      ) : query.error ? (
        <ErrorBanner
          message={
            query.error instanceof ApiError
              ? query.error.message
              : 'The plugins could not be loaded.'
          }
          requestId={query.error instanceof ApiError ? query.error.requestId : undefined}
          onRetry={() => void query.refetch()}
        />
      ) : (
        <div className="space-y-3">
          {filtered.map((plugin) => (
            <PluginCard key={plugin.name} plugin={plugin} />
          ))}
          {filtered.length === 0 ? (
            <Card>
              <p className="text-sm text-muted">No plugin matches these filters.</p>
            </Card>
          ) : null}
        </div>
      )}
    </div>
  );
}
