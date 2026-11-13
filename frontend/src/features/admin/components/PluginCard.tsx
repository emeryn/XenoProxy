/**
 * One plugin's configuration: credentials, activation, timeout, cache and options.
 *
 * Credentials are write-only. The API returns the last four characters so the
 * administrator can tell which key is in place, and nothing more.
 *
 * The header states what the plugin does to a job rather than only naming it:
 * an operator enabling a connector is allowing data out of the instance, and
 * one enabling a pivot is allowing jobs to create further jobs. Both deserve to
 * be said out loud on the row that turns them on.
 */

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { BookOpen, ExternalLink, HeartPulse, KeyRound, Link2, Save, Trash2 } from 'lucide-react';
import { useState } from 'react';

import { Badge, Button, Field, Input, Select } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError } from '@/lib/api-client';
import { formatDateTime } from '@/lib/format';
import type { Plugin, PluginType, ProviderInfo } from '@/lib/types';
import { adminApi } from '../api';

const TYPE_TONE: Record<PluginType, 'neutral' | 'info' | 'warning'> = {
  analyzer: 'neutral',
  connector: 'info',
  pivot: 'warning',
};

const TYPE_EXPLANATION: Record<PluginType, string> = {
  analyzer: 'Runs during the analysis phase and reports on the observable.',
  connector:
    'Runs after the analysis and publishes the finished job to an external platform. Enabling it lets job data leave this instance.',
  pivot:
    'Runs after the connectors and derives the next observable from the finished job. Enabling it lets a job create further jobs.',
};

function invalidatePluginQueries(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: ['admin', 'plugins'] });
  void queryClient.invalidateQueries({ queryKey: ['plugins'] });
}

/**
 * What this plugin talks to, and what turning it on requires.
 *
 * Shown above the credential fields rather than behind a documentation link,
 * because the three questions it answers — which service, where do I get a key,
 * what does the free tier allow — are the ones that otherwise leave the plugin
 * half configured while somebody reads a web page.
 */
function ProviderBlock({ provider, documentationUrl }: { provider: ProviderInfo; documentationUrl: string }) {
  if (!provider?.name) return null;

  const facts: { label: string; value: string }[] = [
    {
      label: provider.self_hosted ? 'Address you provide' : 'Endpoint called',
      value: provider.api_base_url,
    },
    { label: 'Free tier', value: provider.free_tier },
    { label: 'Published limits', value: provider.rate_limit },
    { label: 'Worth knowing', value: provider.notes },
  ].filter((fact) => fact.value);

  return (
    <section className="mb-4 rounded-lg border border-border bg-surface-sunken p-3">
      <h4 className="flex flex-wrap items-center gap-2 text-sm font-medium">
        <BookOpen className="h-3.5 w-3.5 text-muted" aria-hidden />
        {provider.name}
        {provider.self_hosted ? <Badge tone="info">You host it</Badge> : null}
      </h4>

      <dl className="mt-2 grid gap-2">
        {facts.map((fact) => (
          <div key={fact.label}>
            <dt className="text-xs font-medium text-faint">{fact.label}</dt>
            <dd className="mt-0.5 break-words text-xs">
              {fact.label === 'Endpoint called' ? (
                <code className="rounded bg-surface px-1.5 py-0.5">{fact.value}</code>
              ) : (
                fact.value
              )}
            </dd>
          </div>
        ))}
      </dl>

      <p className="mt-3 flex flex-wrap gap-3 text-xs">
        {provider.credential_url ? (
          provider.credential_url.startsWith('http') ? (
            <a
              href={provider.credential_url}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              <KeyRound className="h-3 w-3" aria-hidden />
              Get a credential
              <ExternalLink className="h-3 w-3" aria-hidden />
            </a>
          ) : (
            <span className="inline-flex items-center gap-1 text-muted">
              <KeyRound className="h-3 w-3" aria-hidden />
              {provider.credential_url}
            </span>
          )
        ) : null}
        {provider.url ? (
          <a
            href={provider.url}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-1 text-primary hover:underline"
          >
            <Link2 className="h-3 w-3" aria-hidden />
            The service
            <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        ) : null}
        {documentationUrl ? (
          <a
            href={documentationUrl}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-1 text-primary hover:underline"
          >
            <BookOpen className="h-3 w-3" aria-hidden />
            API documentation
            <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        ) : null}
      </p>
    </section>
  );
}

function SecretRow({ plugin, secretName }: { plugin: Plugin; secretName: string }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [value, setValue] = useState('');
  const hint = plugin.secret_hints[secretName];
  const spec = plugin.secrets.find((entry) => entry.name === secretName);

  const saveMutation = useMutation({
    mutationFn: () => adminApi.setSecret(plugin.name, secretName, value),
    onSuccess: (response) => {
      setValue('');
      toast.success(
        `${spec?.label ?? secretName} saved`,
        response.details?.hint ? `Ends with ${response.details.hint}` : undefined,
      );
      invalidatePluginQueries(queryClient);
    },
    onError: (error) => {
      toast.error(
        'The credential was refused',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => adminApi.deleteSecret(plugin.name, secretName),
    onSuccess: () => {
      toast.success(`${spec?.label ?? secretName} deleted`);
      invalidatePluginQueries(queryClient);
    },
    onError: (error) => {
      toast.error(
        'The credential could not be deleted',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  return (
    <div className="mb-3 rounded-lg border border-border p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-2 text-sm font-medium">
          <KeyRound className="h-3.5 w-3.5 text-muted" aria-hidden />
          {spec?.label ?? secretName}
          {spec?.required ? <Badge tone="warning">Required</Badge> : <Badge>Optional</Badge>}
          {spec?.user_overridable ? (
            <Badge tone="info" title="An analyst may replace this with their own, in Settings">
              Analysts may override
            </Badge>
          ) : null}
        </span>
        {hint ? (
          <Badge tone="success" title="Only the last four characters are ever returned">
            Configured ••••{hint}
          </Badge>
        ) : (
          <Badge tone="neutral">Not configured</Badge>
        )}
      </div>

      {spec?.help_text ? <p className="mb-2 text-xs text-muted">{spec.help_text}</p> : null}

      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-[220px] flex-1">
          <label className="sr-only" htmlFor={`${plugin.name}-${secretName}`}>
            {spec?.label ?? secretName}
          </label>
          <Input
            id={`${plugin.name}-${secretName}`}
            type="password"
            autoComplete="off"
            spellCheck={false}
            placeholder={
              hint
                ? 'Enter a new value to replace it'
                : spec?.placeholder || 'Paste the credential'
            }
            value={value}
            onChange={(event) => setValue(event.target.value)}
            maxLength={2048}
          />
        </div>
        <Button
          variant="primary"
          disabled={value.trim().length < 8}
          loading={saveMutation.isPending}
          onClick={() => saveMutation.mutate()}
          icon={<Save className="h-4 w-4" aria-hidden />}
        >
          Save
        </Button>
        {hint ? (
          <Button
            variant="danger"
            loading={deleteMutation.isPending}
            onClick={() => {
              if (
                window.confirm(
                  `Delete the ${spec?.label ?? secretName} of ${plugin.label}? The plugin will be disabled if this credential is required.`,
                )
              ) {
                deleteMutation.mutate();
              }
            }}
            icon={<Trash2 className="h-4 w-4" aria-hidden />}
            aria-label={`Delete the ${spec?.label ?? secretName} of ${plugin.label}`}
          />
        ) : null}
      </div>
    </div>
  );
}

export function PluginCard({ plugin }: { plugin: Plugin }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [timeout_, setTimeout_] = useState(String(plugin.timeout_seconds));
  const [cacheTtl, setCacheTtl] = useState(String(plugin.cache_ttl_seconds));
  const [options, setOptions] = useState<Record<string, unknown>>(plugin.options ?? {});
  const [expanded, setExpanded] = useState(false);

  const patchMutation = useMutation({
    mutationFn: (patch: Parameters<typeof adminApi.patchPlugin>[1]) =>
      adminApi.patchPlugin(plugin.name, patch),
    onSuccess: () => {
      toast.success(`${plugin.label} updated`);
      invalidatePluginQueries(queryClient);
    },
    onError: (error) => {
      toast.error(
        `${plugin.label} could not be updated`,
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const healthMutation = useMutation({
    mutationFn: () => adminApi.healthcheck(plugin.name),
    onSuccess: (result) => {
      if (result.healthy) toast.success(`${plugin.label} is reachable`, result.detail);
      else toast.error(`${plugin.label} is not reachable`, result.detail);
      invalidatePluginQueries(queryClient);
    },
    onError: (error) => {
      toast.error(
        'The health probe failed',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const optionEntries = Object.entries(plugin.options_schema ?? {});
  // A connector is not cacheable and a pivot's decision is specific to one
  // parent job, so the cache field only means something for an analyzer.
  const showsCache = plugin.plugin_type === 'analyzer';

  return (
    <article className="card">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border p-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold">{plugin.label}</h3>
            <Badge tone={TYPE_TONE[plugin.plugin_type]} title={TYPE_EXPLANATION[plugin.plugin_type]}>
              {plugin.plugin_type}
            </Badge>
            {plugin.free_tier ? <Badge tone="success">Free tier</Badge> : null}
            {plugin.is_custom ? (
              <Badge tone="primary" title="Provided by an installed plugin package">
                custom v{plugin.plugin_version}
              </Badge>
            ) : null}
            {plugin.enabled ? (
              <Badge tone="success">Enabled</Badge>
            ) : (
              <Badge tone="neutral">Disabled</Badge>
            )}
            {plugin.missing_secrets.length > 0 ? (
              <Badge tone="warning">Missing: {plugin.missing_secrets.join(', ')}</Badge>
            ) : null}
            {plugin.health_ok === false ? (
              <Badge tone="danger" title={plugin.health_detail ?? undefined}>
                Unreachable
              </Badge>
            ) : null}
          </div>

          <p className="mt-1 text-xs text-muted">{plugin.description}</p>
          <p className="mt-1 text-xs text-muted">{TYPE_EXPLANATION[plugin.plugin_type]}</p>

          <p className="mt-1 text-xs text-muted">
            {plugin.supported_types.length > 0
              ? `Supports: ${plugin.supported_types.join(', ')}`
              : 'Applies to every observable type'}
            {` · Up to TLP:${plugin.max_tlp.toUpperCase()}`}
            {plugin.run_on_verdicts && plugin.run_on_verdicts.length > 0
              ? ` · Only on: ${plugin.run_on_verdicts.join(', ')}`
              : null}
            {plugin.child_playbook ? ` · Children run “${plugin.child_playbook}”` : null}
            {plugin.provider?.name ? ` · ${plugin.provider.name}` : null}
          </p>

          {plugin.health_checked_at ? (
            <p className="mt-1 text-xs text-muted">
              Last probe {formatDateTime(plugin.health_checked_at)}
              {plugin.health_detail ? `: ${plugin.health_detail}` : null}
            </p>
          ) : null}
          {plugin.updated_by ? (
            <p className="mt-1 text-xs text-muted">
              Last change by {plugin.updated_by} on {formatDateTime(plugin.updated_at)}
            </p>
          ) : null}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="h-4 w-4"
              checked={plugin.enabled}
              disabled={patchMutation.isPending || plugin.missing_secrets.length > 0}
              onChange={(event) => patchMutation.mutate({ enabled: event.target.checked })}
            />
            Enabled
          </label>
          <Button
            variant="ghost"
            loading={healthMutation.isPending}
            onClick={() => healthMutation.mutate()}
            icon={<HeartPulse className="h-4 w-4" aria-hidden />}
            aria-label={`Probe whether ${plugin.label} is reachable`}
          >
            Probe
          </Button>
          <Button variant="ghost" onClick={() => setExpanded((previous) => !previous)}>
            {expanded ? 'Hide settings' : 'Settings'}
          </Button>
        </div>
      </header>

      {expanded ? (
        <div className="p-4">
          <ProviderBlock provider={plugin.provider} documentationUrl={plugin.documentation_url} />

          {plugin.secrets.length > 0 ? (
            <>
              <h4 className="field-label">Credentials</h4>
              {plugin.secrets.map((spec) => (
                <SecretRow key={spec.name} plugin={plugin} secretName={spec.name} />
              ))}
            </>
          ) : (
            <p className="mb-4 text-xs text-muted">
              This plugin needs no credential; enabling it is enough.
            </p>
          )}

          <h4 className="field-label mt-4">Limits</h4>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Timeout (seconds)" htmlFor={`${plugin.name}-timeout`}>
              <Input
                id={`${plugin.name}-timeout`}
                type="number"
                min={5}
                max={900}
                value={timeout_}
                onChange={(event) => setTimeout_(event.target.value)}
              />
            </Field>
            {showsCache ? (
              <Field
                label="Cache lifetime (seconds)"
                htmlFor={`${plugin.name}-cache`}
                hint="0 disables the cache for this source and spends a quota on every job."
              >
                <Input
                  id={`${plugin.name}-cache`}
                  type="number"
                  min={0}
                  max={2592000}
                  value={cacheTtl}
                  onChange={(event) => setCacheTtl(event.target.value)}
                />
              </Field>
            ) : null}
          </div>

          {optionEntries.length > 0 ? (
            <>
              <h4 className="field-label mt-2">Options</h4>
              {optionEntries.map(([key, spec]) => {
                const current = options[key] ?? spec.default;
                const inputId = `${plugin.name}-option-${key}`;
                const label = spec.user_overridable
                  ? `${spec.label ?? key} (analysts may override)`
                  : (spec.label ?? key);
                if (spec.type === 'boolean') {
                  return (
                    <label key={key} className="mb-3 flex items-start gap-2">
                      <input
                        id={inputId}
                        type="checkbox"
                        className="mt-0.5 h-4 w-4"
                        checked={Boolean(current)}
                        onChange={(event) =>
                          setOptions((previous) => ({ ...previous, [key]: event.target.checked }))
                        }
                      />
                      <span className="text-sm">{label}</span>
                    </label>
                  );
                }
                if (spec.enum) {
                  return (
                    <Field key={key} label={label} htmlFor={inputId}>
                      <Select
                        id={inputId}
                        value={String(current ?? '')}
                        onChange={(event) =>
                          setOptions((previous) => ({ ...previous, [key]: event.target.value }))
                        }
                      >
                        {spec.enum.map((choice) => (
                          <option key={choice} value={choice}>
                            {choice}
                          </option>
                        ))}
                      </Select>
                    </Field>
                  );
                }
                return (
                  <Field key={key} label={label} htmlFor={inputId}>
                    <Input
                      id={inputId}
                      type={spec.type === 'integer' ? 'number' : 'text'}
                      value={String(current ?? '')}
                      onChange={(event) =>
                        setOptions((previous) => ({
                          ...previous,
                          [key]:
                            spec.type === 'integer'
                              ? Number(event.target.value)
                              : event.target.value,
                        }))
                      }
                    />
                  </Field>
                );
              })}
            </>
          ) : null}

          <div className="mt-2 flex justify-end">
            <Button
              variant="primary"
              loading={patchMutation.isPending}
              onClick={() =>
                patchMutation.mutate({
                  timeout_seconds: Number(timeout_),
                  ...(showsCache ? { cache_ttl_seconds: Number(cacheTtl) } : {}),
                  options,
                })
              }
              icon={<Save className="h-4 w-4" aria-hidden />}
            >
              Save settings
            </Button>
          </div>
        </div>
      ) : null}
    </article>
  );
}
