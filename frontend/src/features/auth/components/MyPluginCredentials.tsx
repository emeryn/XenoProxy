/**
 * The analyst's own plugin credentials and options.
 *
 * Only what a plugin marks as personal appears here. A shared team subscription
 * stays with the administrator, and nothing that would point a plugin at a
 * different endpoint is offered — that would turn this page into a way around
 * the instance's outbound policy.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Save, Trash2 } from 'lucide-react';
import { useState } from 'react';

import { Badge, Button, Card, ErrorBanner, Input, Skeleton } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError, api } from '@/lib/api-client';
import type { MyPluginConfig } from '@/lib/types';

const QUERY_KEY = ['me', 'plugin-config'];

function CredentialRow({
  pluginName,
  pluginLabel,
  secretName,
  hint,
}: {
  pluginName: string;
  pluginLabel: string;
  secretName: string;
  hint: string | undefined;
}) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [value, setValue] = useState('');
  const inputId = `me-${pluginName}-${secretName}`;

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: QUERY_KEY });
  }

  const saveMutation = useMutation({
    mutationFn: () =>
      api.put<{ message: string; details: { hint?: string } }>(
        `/me/plugin-config/${pluginName}/secrets/${secretName}`,
        { value },
      ),
    onSuccess: (response) => {
      setValue('');
      toast.success(
        `Your ${pluginLabel} credential is saved`,
        response.details?.hint ? `Ends with ${response.details.hint}` : undefined,
      );
      invalidate();
    },
    onError: (error) => {
      toast.error(
        'The credential was refused',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () =>
      api.delete<{ message: string }>(`/me/plugin-config/${pluginName}/secrets/${secretName}`),
    onSuccess: (response) => {
      toast.success('Your credential is deleted', response.message);
      invalidate();
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
          {pluginLabel}
          <code className="rounded bg-surface-sunken px-1.5 py-0.5 text-xs">{secretName}</code>
        </span>
        {hint ? (
          <Badge tone="success" title="Only the last four characters are ever returned">
            Yours ••••{hint}
          </Badge>
        ) : (
          <Badge tone="neutral">Using the team credential</Badge>
        )}
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-[220px] flex-1">
          <label className="sr-only" htmlFor={inputId}>
            Your {pluginLabel} {secretName}
          </label>
          <Input
            id={inputId}
            type="password"
            autoComplete="off"
            spellCheck={false}
            placeholder={hint ? 'Enter a new value to replace it' : 'Paste your own credential'}
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
                  `Delete your own ${pluginLabel} credential? Your jobs will use the team's again.`,
                )
              ) {
                deleteMutation.mutate();
              }
            }}
            icon={<Trash2 className="h-4 w-4" aria-hidden />}
            aria-label={`Delete your own ${pluginLabel} credential`}
          />
        ) : null}
      </div>
    </div>
  );
}

export function MyPluginCredentials() {
  const query = useQuery({
    queryKey: QUERY_KEY,
    queryFn: () => api.get<MyPluginConfig>('/me/plugin-config'),
  });

  const entries = Object.entries(query.data?.overridable ?? {}).filter(
    ([, info]) => info.secrets.length > 0,
  );

  return (
    <Card
      title="My provider accounts"
      description="Use your own account with a provider instead of the team's shared one. It applies to your jobs only, and every other source keeps using the shared credential."
      className="mb-4"
    >
      {query.isLoading ? (
        <Skeleton className="h-24" />
      ) : query.error ? (
        <ErrorBanner
          message={
            query.error instanceof ApiError
              ? query.error.message
              : 'Your provider accounts could not be loaded.'
          }
          onRetry={() => void query.refetch()}
        />
      ) : entries.length === 0 ? (
        <p className="text-sm text-muted">
          No source on this instance allows a personal account. Credentials that point a plugin at
          a service, such as a webhook or a platform URL, are always set by an administrator.
        </p>
      ) : (
        entries.map(([pluginName, info]) =>
          info.secrets.map((secretName) => (
            <CredentialRow
              key={`${pluginName}-${secretName}`}
              pluginName={pluginName}
              pluginLabel={info.label}
              secretName={secretName}
              hint={query.data?.secret_hints?.[pluginName]?.[secretName]}
            />
          )),
        )
      )}
    </Card>
  );
}
