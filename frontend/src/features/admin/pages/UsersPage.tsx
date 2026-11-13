/**
 * Accounts: create, edit, move between groups, reset, remove.
 *
 * A created account's password is shown **once**, because that is all the
 * backend ever returns: it is stored hashed and there is no second chance to
 * read it. The panel therefore insists on it rather than tucking it into a
 * toast that disappears after four seconds.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, Copy, KeyRound, Plus, ShieldOff, Trash2, UserPlus } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { PageHeader } from '@/app/AppShell';
import { useAuth } from '@/app/auth-context';
import { Badge, Button, Card, ErrorBanner, Field, Input, Select, Skeleton } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError } from '@/lib/api-client';
import { formatDateTime, formatRelative } from '@/lib/format';
import type { GroupRecord, Role, UserCreated, UserDetail } from '@/lib/types';
import { adminApi, type UserPayload } from '../api';

const ROLES: Role[] = ['analyst', 'admin'];

function CredentialOnce({
  account,
  onDismiss,
}: {
  account: UserCreated;
  onDismiss: () => void;
}) {
  const toast = useToast();
  return (
    <Card className="mb-4">
      <div className="rounded-lg border border-warning-border bg-warning-soft p-3">
        <p className="text-sm font-medium">
          The password of <strong>{account.username}</strong>
        </p>
        <p className="mt-1 text-xs text-muted">
          Shown once: it is stored hashed and cannot be displayed again. Hand it over through a
          channel you trust, not by e-mail alongside the username.
        </p>
        <p className="mt-2 break-all font-mono text-sm">{account.initial_password}</p>
        <div className="mt-3 flex gap-2">
          <Button
            onClick={() =>
              void navigator.clipboard
                .writeText(account.initial_password)
                .then(() => toast.success('Password copied'))
                .catch(() => toast.error('Could not copy', 'Select it and copy it by hand.'))
            }
            icon={<Copy className="h-4 w-4" aria-hidden />}
          >
            Copy
          </Button>
          <Button
            variant="primary"
            onClick={onDismiss}
            icon={<Check className="h-4 w-4" aria-hidden />}
          >
            I handed it over
          </Button>
        </div>
      </div>
    </Card>
  );
}

function CreateForm({
  groups,
  onCancel,
  onSubmit,
  submitting,
}: {
  groups: GroupRecord[];
  onCancel: () => void;
  onSubmit: (payload: UserPayload) => void;
  submitting: boolean;
}) {
  const defaults = useMemo(() => groups.filter((group) => group.is_default), [groups]);
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Role>('analyst');
  const [chosen, setChosen] = useState<string[]>(() => defaults.map((group) => group.id));
  const [password, setPassword] = useState('');

  return (
    <Card
      title="New account"
      description="A local account. Identities from single sign-on or the directory are created on their first sign-in instead."
      className="mb-4"
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit({
            username: username.trim(),
            display_name: displayName.trim() || null,
            email: email.trim() || null,
            role,
            group_ids: chosen,
            password: password.trim() || null,
          });
        }}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            label="Username"
            htmlFor="new-username"
            required
            hint="Letters, digits and . _ @ + -"
          >
            <Input
              id="new-username"
              autoFocus
              required
              maxLength={128}
              pattern="[A-Za-z0-9._@+\-]+"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
          </Field>
          <Field label="Display name" htmlFor="new-display">
            <Input
              id="new-display"
              maxLength={256}
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          </Field>
          <Field label="E-mail" htmlFor="new-email">
            <Input
              id="new-email"
              type="email"
              maxLength={320}
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </Field>
          <Field label="Role" htmlFor="new-role">
            <Select
              id="new-role"
              value={role}
              onChange={(event) => setRole(event.target.value as Role)}
            >
              {ROLES.map((entry) => (
                <option key={entry} value={entry}>
                  {entry}
                </option>
              ))}
            </Select>
          </Field>
        </div>

        <Field
          label="Password"
          htmlFor="new-password"
          hint="Leave it empty and a strong one is generated and shown once. At least 12 characters otherwise."
        >
          <Input
            id="new-password"
            type="password"
            autoComplete="new-password"
            minLength={12}
            maxLength={128}
            placeholder="Generated if left empty"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </Field>

        <fieldset className="mb-4">
          <legend className="field-label">Groups ({chosen.length} selected)</legend>
          <p className="mb-2 text-xs text-muted">
            Membership decides which jobs the account sees from AMBER upwards, and can demand
            two-factor.
          </p>
          {groups.length === 0 ? (
            <p className="text-xs text-muted">No group exists yet.</p>
          ) : (
            <div className="grid gap-2 sm:grid-cols-3">
              {groups.map((group) => (
                <label key={group.id} className="flex items-center gap-1.5 text-sm">
                  <input
                    type="checkbox"
                    className="h-4 w-4"
                    checked={chosen.includes(group.id)}
                    onChange={() =>
                      setChosen((current) =>
                        current.includes(group.id)
                          ? current.filter((entry) => entry !== group.id)
                          : [...current, group.id],
                      )
                    }
                  />
                  {group.name}
                  {group.grants_admin ? <Badge tone="warning">admin</Badge> : null}
                </label>
              ))}
            </div>
          )}
        </fieldset>

        <div className="flex justify-end gap-2">
          <Button type="button" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            loading={submitting}
            disabled={!username.trim()}
            icon={<UserPlus className="h-4 w-4" aria-hidden />}
          >
            Create
          </Button>
        </div>
      </form>
    </Card>
  );
}

function GroupPicker({
  account,
  groups,
  onSave,
  saving,
}: {
  account: UserDetail;
  groups: GroupRecord[];
  onSave: (groupIds: string[]) => void;
  saving: boolean;
}) {
  const [chosen, setChosen] = useState<string[]>(account.group_ids);
  const dirty =
    chosen.length !== account.group_ids.length ||
    chosen.some((id) => !account.group_ids.includes(id));

  return (
    <div className="mt-2 rounded-lg border border-border p-3">
      <p className="field-label">Groups</p>
      <div className="grid gap-2 sm:grid-cols-3">
        {groups.map((group) => (
          <label key={group.id} className="flex items-center gap-1.5 text-sm">
            <input
              type="checkbox"
              className="h-4 w-4"
              checked={chosen.includes(group.id)}
              onChange={() =>
                setChosen((current) =>
                  current.includes(group.id)
                    ? current.filter((entry) => entry !== group.id)
                    : [...current, group.id],
                )
              }
            />
            {group.name}
          </label>
        ))}
      </div>
      <div className="mt-3 flex justify-end">
        <Button
          variant="primary"
          loading={saving}
          disabled={!dirty}
          onClick={() => onSave(chosen)}
        >
          Save the membership
        </Button>
      </div>
    </div>
  );
}

export function UsersPage() {
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const toast = useToast();
  const { user: current } = useAuth();

  const creating = params.get('new') === '1';
  const expanded = params.get('open') ?? '';
  const [created, setCreated] = useState<UserCreated | null>(null);

  const usersQuery = useQuery({ queryKey: ['admin', 'users'], queryFn: adminApi.users });
  const groupsQuery = useQuery({ queryKey: ['admin', 'groups'], queryFn: adminApi.groups });

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
    void queryClient.invalidateQueries({ queryKey: ['admin', 'groups'] });
  }

  function reportError(title: string) {
    return (error: unknown) =>
      toast.error(title, error instanceof ApiError ? error.message : 'Unexpected failure.');
  }

  const createMutation = useMutation({
    mutationFn: adminApi.createUser,
    onSuccess: (account) => {
      setCreated(account);
      setParam('new', '');
      toast.success(`${account.username} created`);
      invalidate();
    },
    onError: reportError('The account could not be created'),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Parameters<typeof adminApi.updateUser>[1] }) =>
      adminApi.updateUser(id, patch),
    onSuccess: () => {
      toast.success('Account updated');
      invalidate();
    },
    onError: reportError('The account could not be updated'),
  });

  const groupsMutation = useMutation({
    mutationFn: ({ id, groupIds }: { id: string; groupIds: string[] }) =>
      adminApi.setUserGroups(id, groupIds),
    onSuccess: () => {
      toast.success('Membership saved');
      invalidate();
    },
    onError: reportError('The membership could not be saved'),
  });

  const resetMutation = useMutation({
    mutationFn: (id: string) => adminApi.resetUserPassword(id),
    onSuccess: (account) => {
      setCreated(account);
      toast.success(`The password of ${account.username} was reset`);
      invalidate();
    },
    onError: reportError('The password could not be reset'),
  });

  const clearMfaMutation = useMutation({
    mutationFn: (id: string) => adminApi.clearUserMfa(id),
    onSuccess: (response) => {
      toast.success('Two-factor cleared', response.message);
      invalidate();
    },
    onError: reportError('The enrolment could not be cleared'),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => adminApi.deleteUser(id),
    onSuccess: () => {
      toast.success('Account deleted');
      invalidate();
    },
    onError: reportError('The account could not be deleted'),
  });

  const groups = groupsQuery.data ?? [];
  const users = usersQuery.data ?? [];
  const admins = users.filter((entry) => entry.role === 'admin' && entry.is_active).length;

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        breadcrumb={['Home', 'Admin', 'Users']}
        title="Accounts"
        description="Local accounts are created here. An identity from single sign-on or the directory is created on its first sign-in, and its role and groups come from the mapping."
        actions={
          <>
            <Badge>{users.length} account(s)</Badge>
            <Button
              variant="primary"
              onClick={() => setParam('new', creating ? '' : '1')}
              icon={<Plus className="h-4 w-4" aria-hidden />}
            >
              New account
            </Button>
          </>
        }
      />

      {created ? <CredentialOnce account={created} onDismiss={() => setCreated(null)} /> : null}

      {creating ? (
        <CreateForm
          groups={groups}
          onCancel={() => setParam('new', '')}
          onSubmit={(payload) => createMutation.mutate(payload)}
          submitting={createMutation.isPending}
        />
      ) : null}

      {usersQuery.isLoading ? (
        <Skeleton className="h-64" />
      ) : usersQuery.error ? (
        <ErrorBanner
          message={
            usersQuery.error instanceof ApiError
              ? usersQuery.error.message
              : 'The accounts could not be loaded.'
          }
          onRetry={() => void usersQuery.refetch()}
        />
      ) : (
        <div className="space-y-2">
          {users.map((account) => {
            const isSelf = account.id === current?.id;
            const open = expanded === account.id;
            // Removing the last administrator locks everybody out of the admin
            // area, so the control is disabled rather than left to fail.
            const lastAdmin = account.role === 'admin' && account.is_active && admins <= 1;

            return (
              <Card
                key={account.id}
                title={
                  <span className="flex flex-wrap items-center gap-2">
                    {account.username}
                    <Badge tone={account.role === 'admin' ? 'warning' : 'neutral'}>
                      {account.role}
                    </Badge>
                    <Badge tone="info">{account.auth_source}</Badge>
                    {account.is_active ? null : <Badge tone="danger">Disabled</Badge>}
                    {account.mfa_enabled ? <Badge tone="success">2FA</Badge> : null}
                    {account.must_change_password ? (
                      <Badge tone="warning">Password change due</Badge>
                    ) : null}
                    {isSelf ? <Badge tone="primary">You</Badge> : null}
                  </span>
                }
                description={
                  [
                    account.display_name,
                    account.email,
                    account.groups.length ? `Groups: ${account.groups.join(', ')}` : 'No group',
                    account.last_login_at
                      ? `Last sign-in ${formatRelative(account.last_login_at)}`
                      : 'Never signed in',
                  ]
                    .filter(Boolean)
                    .join(' · ') || undefined
                }
                actions={
                  <Button onClick={() => setParam('open', open ? '' : account.id)}>
                    {open ? 'Close' : 'Manage'}
                  </Button>
                }
              >
                {open ? (
                  <div className="space-y-3">
                    <div className="grid gap-3 sm:grid-cols-2">
                      <Field label="Role" htmlFor={`role-${account.id}`}>
                        <Select
                          id={`role-${account.id}`}
                          value={account.role}
                          disabled={lastAdmin || updateMutation.isPending}
                          onChange={(event) =>
                            updateMutation.mutate({
                              id: account.id,
                              patch: { role: event.target.value as Role },
                            })
                          }
                        >
                          {ROLES.map((entry) => (
                            <option key={entry} value={entry}>
                              {entry}
                            </option>
                          ))}
                        </Select>
                      </Field>
                      <Field label="State" htmlFor={`active-${account.id}`}>
                        <label className="flex items-center gap-2 text-sm">
                          <input
                            id={`active-${account.id}`}
                            type="checkbox"
                            className="h-4 w-4"
                            checked={account.is_active}
                            disabled={isSelf || lastAdmin || updateMutation.isPending}
                            onChange={(event) =>
                              updateMutation.mutate({
                                id: account.id,
                                patch: { is_active: event.target.checked },
                              })
                            }
                          />
                          {account.is_active ? 'Active' : 'Disabled'}
                        </label>
                      </Field>
                    </div>

                    {lastAdmin ? (
                      <p className="text-xs text-muted">
                        This is the only active administrator, so its role and state are locked:
                        changing either would leave the instance without one.
                      </p>
                    ) : null}

                    {account.auth_source === 'local' ? (
                      <GroupPicker
                        account={account}
                        groups={groups}
                        saving={groupsMutation.isPending}
                        onSave={(groupIds) => groupsMutation.mutate({ id: account.id, groupIds })}
                      />
                    ) : (
                      <p className="text-xs text-muted">
                        This identity comes from {account.auth_source}: its groups and role are
                        recomputed from the provider on every sign-in, so they are not edited
                        here. Map them in Admin, Groups.
                      </p>
                    )}

                    <div className="flex flex-wrap gap-2">
                      {account.auth_source === 'local' ? (
                        <Button
                          loading={resetMutation.isPending}
                          onClick={() => {
                            if (window.confirm(`Reset the password of ${account.username}?`)) {
                              resetMutation.mutate(account.id);
                            }
                          }}
                          icon={<KeyRound className="h-4 w-4" aria-hidden />}
                        >
                          Reset the password
                        </Button>
                      ) : null}
                      {account.mfa_enabled ? (
                        <Button
                          loading={clearMfaMutation.isPending}
                          onClick={() => {
                            if (
                              window.confirm(
                                `Clear the authenticator of ${account.username}? They will enrol a new one at their next sign-in.`,
                              )
                            ) {
                              clearMfaMutation.mutate(account.id);
                            }
                          }}
                          icon={<ShieldOff className="h-4 w-4" aria-hidden />}
                        >
                          Clear two-factor
                        </Button>
                      ) : null}
                      <Button
                        variant="danger"
                        disabled={isSelf || lastAdmin}
                        loading={deleteMutation.isPending}
                        onClick={() => {
                          if (
                            window.confirm(
                              `Delete ${account.username}? Their jobs stay in the history, attributed to their name.`,
                            )
                          ) {
                            deleteMutation.mutate(account.id);
                          }
                        }}
                        icon={<Trash2 className="h-4 w-4" aria-hidden />}
                      >
                        Delete
                      </Button>
                    </div>

                    <p className="text-xs text-muted">
                      Created {formatDateTime(account.created_at)}
                    </p>
                  </div>
                ) : null}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
