/** Personal settings: password, own provider accounts, and API tokens. */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, KeyRound, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';

import { PageHeader } from '@/app/AppShell';
import { useAuth } from '@/app/auth-context';
import { Badge, Button, Card, ErrorBanner, Field, Input, Skeleton } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError, api } from '@/lib/api-client';
import { formatDateTime, formatRelative } from '@/lib/format';
import type { ApiKey, ApiKeyCreated } from '@/lib/types';
import { MfaPanel } from '../components/MfaPanel';
import { MyPluginCredentials } from '../components/MyPluginCredentials';

export function SettingsPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const toast = useToast();

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [keyName, setKeyName] = useState('');
  const [createdToken, setCreatedToken] = useState<string | null>(null);

  const keysQuery = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => api.get<ApiKey[]>('/auth/api-keys'),
  });

  const passwordMutation = useMutation({
    mutationFn: () =>
      api.post<{ message: string }>('/auth/password', {
        current_password: currentPassword,
        new_password: newPassword,
      }),
    onSuccess: (response) => {
      toast.success(response.message);
      setCurrentPassword('');
      setNewPassword('');
      void queryClient.invalidateQueries({ queryKey: ['auth', 'me'] });
    },
    onError: (error) => {
      toast.error(
        'The password was not changed',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const createKeyMutation = useMutation({
    mutationFn: () =>
      api.post<ApiKeyCreated>('/auth/api-keys', { name: keyName, days_valid: 365 }),
    onSuccess: (key) => {
      setCreatedToken(key.token);
      setKeyName('');
      void queryClient.invalidateQueries({ queryKey: ['api-keys'] });
    },
    onError: (error) => {
      toast.error(
        'The token could not be created',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const revokeKeyMutation = useMutation({
    mutationFn: (id: string) => api.delete<{ message: string }>(`/auth/api-keys/${id}`),
    onSuccess: () => {
      toast.success('The token has been revoked.');
      void queryClient.invalidateQueries({ queryKey: ['api-keys'] });
    },
    onError: (error) => {
      toast.error(
        'The token could not be revoked',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        breadcrumb={['Home', 'My access']}
        title="My access"
        description="Your password and the personal tokens that let scripts or n8n call XenoProxy as you."
      />

      {user?.must_change_password ? (
        <div className="mb-4">
          <ErrorBanner message="The initial password must be changed before you can submit scans." />
        </div>
      ) : null}

      <Card title="Password" className="mb-4">
        {user?.auth_source === 'local' ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              passwordMutation.mutate();
            }}
          >
            <Field label="Current password" htmlFor="current-password" required>
              <Input
                id="current-password"
                type="password"
                autoComplete="current-password"
                required
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
              />
            </Field>
            <Field
              label="New password"
              htmlFor="new-password"
              required
              hint="At least 12 characters. Passphrases are preferred to complex short passwords."
            >
              <Input
                id="new-password"
                type="password"
                autoComplete="new-password"
                required
                minLength={12}
                maxLength={128}
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
              />
            </Field>
            <Button
              type="submit"
              variant="primary"
              loading={passwordMutation.isPending}
              disabled={newPassword.length < 12 || currentPassword.length === 0}
            >
              Change the password
            </Button>
          </form>
        ) : (
          <p className="text-sm text-muted">
            This account is managed by the identity provider, so its password is changed there.
          </p>
        )}
      </Card>

      <MfaPanel />

      <MyPluginCredentials />

      <Card
        title="API tokens"
        description="Use the token as an Authorization: Bearer header. It carries your own permissions."
        className="mb-4"
      >
        {createdToken ? (
          <div className="mb-4 rounded-lg border border-warning-border bg-warning-soft p-3">
            <p className="text-sm font-medium">Copy this token now; it is shown only once.</p>
            <div className="mt-2 flex items-center gap-2">
              <code className="min-w-0 flex-1 overflow-x-auto rounded bg-surface-sunken p-2 font-mono text-xs">
                {createdToken}
              </code>
              <Button
                onClick={() => {
                  void navigator.clipboard.writeText(createdToken);
                  toast.success('Token copied to the clipboard.');
                }}
                icon={<Copy className="h-4 w-4" aria-hidden />}
              >
                Copy
              </Button>
            </div>
            <Button variant="ghost" className="mt-2" onClick={() => setCreatedToken(null)}>
              I have stored it
            </Button>
          </div>
        ) : null}

        <form
          className="mb-4 flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            createKeyMutation.mutate();
          }}
        >
          <div className="min-w-[220px] flex-1">
            <label className="field-label" htmlFor="key-name">
              Token name
            </label>
            <Input
              id="key-name"
              value={keyName}
              maxLength={128}
              placeholder="n8n enrichment workflow"
              onChange={(event) => setKeyName(event.target.value)}
            />
          </div>
          <Button
            type="submit"
            variant="primary"
            disabled={!keyName.trim()}
            loading={createKeyMutation.isPending}
            icon={<Plus className="h-4 w-4" aria-hidden />}
          >
            Create
          </Button>
        </form>

        {keysQuery.isLoading ? (
          <Skeleton className="h-20" />
        ) : (keysQuery.data ?? []).length === 0 ? (
          <p className="text-sm text-muted">No token yet.</p>
        ) : (
          <ul className="divide-y divide-border">
            {(keysQuery.data ?? []).map((key) => (
              <li key={key.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                <div>
                  <p className="flex items-center gap-2 text-sm font-medium">
                    <KeyRound className="h-3.5 w-3.5 text-muted" aria-hidden />
                    {key.name}
                    {key.revoked ? <Badge tone="danger">Revoked</Badge> : null}
                  </p>
                  <p className="mt-0.5 text-xs text-muted">
                    {key.prefix}… · created {formatDateTime(key.created_at)} · last used{' '}
                    {formatRelative(key.last_used_at)}
                  </p>
                </div>
                {key.revoked ? null : (
                  <Button
                    variant="danger"
                    aria-label={`Revoke the token ${key.name}`}
                    loading={revokeKeyMutation.isPending}
                    onClick={() => {
                      if (window.confirm(`Revoke the token "${key.name}"?`)) {
                        revokeKeyMutation.mutate(key.id);
                      }
                    }}
                    icon={<Trash2 className="h-4 w-4" aria-hidden />}
                  />
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
