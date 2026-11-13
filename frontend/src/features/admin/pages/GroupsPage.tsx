/**
 * Groups: membership, the two-factor demand, and the directory mapping.
 *
 * A group is also where an identity provider's groups land. The mapping is
 * worth trying before trusting it — a wrong one that grants administration is
 * not something to discover by watching who gets in — so the page can resolve
 * a set of provider group names without anybody signing in.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Cloud, HardDrive, Plus, Trash2, Users } from 'lucide-react';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { PageHeader } from '@/app/AppShell';
import { Badge, Button, Card, ErrorBanner, Field, Input, Skeleton } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError } from '@/lib/api-client';
import { formatRelative } from '@/lib/format';
import type { GroupRecord } from '@/lib/types';
import { adminApi, type GroupPayload } from '../api';

const EMPTY: GroupPayload = {
  name: '',
  description: '',
  is_default: false,
  require_mfa: false,
  external_names: [],
  grants_admin: false,
};

function GroupForm({
  initial,
  onCancel,
  onSubmit,
  submitting,
}: {
  initial: GroupPayload;
  onCancel: () => void;
  onSubmit: (payload: GroupPayload) => void;
  submitting: boolean;
}) {
  const [draft, setDraft] = useState<GroupPayload>(initial);
  const [names, setNames] = useState(initial.external_names.join('\n'));

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({
          ...draft,
          external_names: names
            .split('\n')
            .map((entry) => entry.trim())
            .filter(Boolean),
        });
      }}
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" htmlFor="group-name" required>
          <Input
            id="group-name"
            autoFocus
            required
            maxLength={128}
            value={draft.name}
            onChange={(event) => setDraft({ ...draft, name: event.target.value })}
          />
        </Field>
        <Field label="Description" htmlFor="group-description">
          <Input
            id="group-description"
            maxLength={512}
            value={draft.description}
            onChange={(event) => setDraft({ ...draft, description: event.target.value })}
          />
        </Field>
      </div>

      <Field
        label="Names in the identity provider or the directory"
        htmlFor="group-external"
        hint="One per line. A full distinguished name works: only its first component is compared, and the comparison ignores case. The group's own name is always accepted, so the obvious case needs nothing here."
      >
        <textarea
          id="group-external"
          rows={4}
          className="input font-mono text-xs"
          placeholder={'soc_analysts\ncn=soc-leads,ou=groups,dc=example,dc=com'}
          value={names}
          onChange={(event) => setNames(event.target.value)}
        />
      </Field>

      <div className="mb-4 grid gap-2">
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4"
            checked={draft.is_default}
            onChange={(event) => setDraft({ ...draft, is_default: event.target.checked })}
          />
          <span>
            Default group
            <span className="mt-0.5 block text-xs text-muted">
              New accounts join it, and so does a sign-in whose provider groups matched nothing.
            </span>
          </span>
        </label>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4"
            checked={draft.require_mfa}
            onChange={(event) => setDraft({ ...draft, require_mfa: event.target.checked })}
          />
          <span>
            Members must use two-factor authentication
            <span className="mt-0.5 block text-xs text-muted">
              On top of the instance-wide requirements.
            </span>
          </span>
        </label>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4"
            checked={draft.grants_admin}
            onChange={(event) => setDraft({ ...draft, grants_admin: event.target.checked })}
          />
          <span>
            Membership grants the administrator role
            <span className="mt-0.5 block text-xs text-warning">
              Anyone the provider puts in a mapped group becomes an administrator at their next
              sign-in.
            </span>
          </span>
        </label>
      </div>

      <div className="flex justify-end gap-2">
        <Button type="button" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" loading={submitting} disabled={!draft.name.trim()}>
          Save
        </Button>
      </div>
    </form>
  );
}

/**
 * Where a group's membership comes from.
 *
 * Nothing creates a group from a directory: every row is local, and a sign-in
 * matches the names a provider reports against the mappings a group carries.
 * So a group is only "from OIDC" once a sign-in has actually arrived through
 * it, which is what the backend stamps. A group carrying mappings that have
 * never matched is shown as waiting rather than as synchronised, because
 * claiming otherwise would hide a mapping that does not work.
 */
function SourceTag({ group }: { group: GroupRecord }) {
  if (group.matched_source && group.matched_source !== 'local') {
    return (
      <Badge tone="primary" title={`Last sign-in through this group: ${formatRelative(group.matched_at ?? '')}`}>
        <Cloud className="h-3 w-3" aria-hidden />
        {group.matched_source.toUpperCase()}
      </Badge>
    );
  }
  if ((group.external_names ?? []).length > 0) {
    return (
      <Badge tone="neutral" title="Mapped to directory names, but no sign-in has matched it yet">
        <Cloud className="h-3 w-3" aria-hidden />
        Mapped, never matched
      </Badge>
    );
  }
  return (
    <Badge tone="neutral">
      <HardDrive className="h-3 w-3" aria-hidden />
      Local
    </Badge>
  );
}

export function GroupsPage() {
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const toast = useToast();

  const editing = params.get('edit') ?? '';
  const creating = params.get('new') === '1';

  const query = useQuery({ queryKey: ['admin', 'groups'], queryFn: adminApi.groups });

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: ['admin', 'groups'] });
    void queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
  }

  function reportError(title: string) {
    return (error: unknown) =>
      toast.error(title, error instanceof ApiError ? error.message : 'Unexpected failure.');
  }

  const saveMutation = useMutation({
    mutationFn: (payload: GroupPayload) =>
      editing ? adminApi.updateGroup(editing, payload) : adminApi.createGroup(payload),
    onSuccess: (group) => {
      toast.success(`${group.name} saved`);
      setParam('edit', '');
      setParam('new', '');
      invalidate();
    },
    onError: reportError('The group was refused'),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => adminApi.deleteGroup(id),
    onSuccess: () => {
      toast.success('Group deleted');
      invalidate();
    },
    onError: reportError('The group could not be deleted'),
  });

  const groups = query.data ?? [];
  const target = groups.find((group) => group.id === editing);

  function payloadOf(group: GroupRecord): GroupPayload {
    return {
      name: group.name,
      description: group.description,
      is_default: group.is_default,
      require_mfa: group.require_mfa,
      external_names: group.external_names ?? [],
      grants_admin: group.grants_admin,
    };
  }

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        breadcrumb={['Home', 'Admin', 'Groups']}
        title="Groups"
        description="Membership decides who sees a job from TLP:AMBER upwards. A group is also where the groups of an identity provider or a directory are mapped."
        actions={
          <>
            <Badge>{groups.length} group(s)</Badge>
            <Button
              variant="primary"
              onClick={() => {
                setParam('edit', '');
                setParam('new', creating ? '' : '1');
              }}
              icon={<Plus className="h-4 w-4" aria-hidden />}
            >
              New group
            </Button>
          </>
        }
      />

      {creating || target ? (
        <Card title={target ? `Edit ${target.name}` : 'New group'} className="mb-4">
          <GroupForm
            key={target?.id ?? 'new'}
            initial={target ? payloadOf(target) : EMPTY}
            submitting={saveMutation.isPending}
            onCancel={() => {
              setParam('edit', '');
              setParam('new', '');
            }}
            onSubmit={(payload) => saveMutation.mutate(payload)}
          />
        </Card>
      ) : null}

      {query.isLoading ? (
        <Skeleton className="h-48" />
      ) : query.error ? (
        <ErrorBanner
          message={
            query.error instanceof ApiError ? query.error.message : 'The groups could not be loaded.'
          }
          onRetry={() => void query.refetch()}
        />
      ) : (
        <div className="space-y-2">
          {groups.map((group) => (
            <Card
              key={group.id}
              title={
                <span className="flex flex-wrap items-center gap-2">
                  {group.name}
                  <SourceTag group={group} />
                  {group.is_default ? <Badge tone="info">Default</Badge> : null}
                  {group.grants_admin ? <Badge tone="warning">Grants admin</Badge> : null}
                  {group.require_mfa ? <Badge tone="success">2FA required</Badge> : null}
                </span>
              }
              description={group.description || undefined}
              actions={
                <>
                  <Button
                    onClick={() => {
                      setParam('new', '');
                      setParam('edit', group.id);
                    }}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="danger"
                    aria-label={`Delete the group ${group.name}`}
                    loading={deleteMutation.isPending}
                    onClick={() => {
                      if (
                        window.confirm(
                          `Delete the group "${group.name}"? Its ${group.member_count} member(s) keep their accounts.`,
                        )
                      ) {
                        deleteMutation.mutate(group.id);
                      }
                    }}
                    icon={<Trash2 className="h-4 w-4" aria-hidden />}
                  />
                </>
              }
            >
              <p className="flex flex-wrap items-center gap-2 text-xs text-muted">
                <Users className="h-3.5 w-3.5" aria-hidden />
                {group.member_count} member(s)
                {group.members.length > 0 ? `: ${group.members.slice(0, 12).join(', ')}` : ''}
              </p>
              {(group.external_names ?? []).length > 0 ? (
                <p className="mt-2 flex flex-wrap items-center gap-1 text-xs text-muted">
                  Mapped from:
                  {group.external_names.map((name) => (
                    <code key={name} className="rounded bg-surface-sunken px-1.5 py-0.5">
                      {name}
                    </code>
                  ))}
                </p>
              ) : null}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
