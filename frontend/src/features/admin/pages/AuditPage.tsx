/** Audit trail with hash-chain verification. */

import { useMutation, useQuery } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';

import { PageHeader } from '@/app/AppShell';
import { Badge, Button, Card, ErrorBanner, Input, TableSkeleton } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError } from '@/lib/api-client';
import { formatDateTime } from '@/lib/format';
import { adminApi } from '../api';

export function AuditPage() {
  const [params, setParams] = useSearchParams();
  const toast = useToast();
  const page = Number(params.get('page') ?? '1');
  const action = params.get('action') ?? '';

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== 'page') next.delete('page');
    setParams(next, { replace: true });
  }

  const query = useQuery({
    queryKey: ['admin', 'audit', page, action],
    queryFn: () => adminApi.audit(page, 50, action || undefined),
  });

  const verifyMutation = useMutation({
    mutationFn: adminApi.verifyAudit,
    onSuccess: (result) => {
      if (result.details.valid) {
        toast.success(result.message, `${result.details.checked} entries checked.`);
      } else {
        toast.error(result.message, 'The trail has been altered; investigate immediately.');
      }
    },
    onError: (error) => {
      toast.error(
        'The verification failed',
        error instanceof ApiError ? error.message : 'Unexpected failure.',
      );
    },
  });

  const totalPages = query.data ? Math.max(1, Math.ceil(query.data.total / 50)) : 1;

  return (
    <div>
      <PageHeader
        breadcrumb={['Home', 'Admin', 'Audit']}
        title="Audit trail"
        description="Append-only record of sign-ins, credential changes, configuration changes and exports. Each entry is chained to the previous one."
        actions={
          <Button
            variant="primary"
            loading={verifyMutation.isPending}
            onClick={() => verifyMutation.mutate()}
            icon={<ShieldCheck className="h-4 w-4" aria-hidden />}
          >
            Verify the chain
          </Button>
        }
      />

      <Card className="mb-4">
        <div className="p-4 sm:max-w-xs">
          <label className="field-label" htmlFor="audit-action">
            Action
          </label>
          <Input
            id="audit-action"
            defaultValue={action}
            placeholder="analyzer.secret_set"
            onBlur={(event) => setParam('action', event.currentTarget.value.trim())}
          />
        </div>
      </Card>

      <Card>
        {query.isLoading ? (
          <TableSkeleton rows={8} columns={6} />
        ) : query.error ? (
          <div className="p-4">
            <ErrorBanner
              message={
                query.error instanceof ApiError
                  ? query.error.message
                  : 'The audit trail could not be loaded.'
              }
              onRetry={() => void query.refetch()}
            />
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">Audit events</caption>
                <thead>
                  <tr className="border-b border-border text-xs font-medium text-faint">
                    <th scope="col" className="table-cell">
                      #
                    </th>
                    <th scope="col" className="table-cell">
                      When
                    </th>
                    <th scope="col" className="table-cell">
                      Action
                    </th>
                    <th scope="col" className="table-cell">
                      Actor
                    </th>
                    <th scope="col" className="table-cell">
                      Target
                    </th>
                    <th scope="col" className="table-cell">
                      Source IP
                    </th>
                    <th scope="col" className="table-cell">
                      Outcome
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {(query.data?.items ?? []).map((event) => (
                    <tr key={event.seq}>
                      <td className="table-cell font-mono text-xs text-muted">{event.seq}</td>
                      <td className="table-cell text-xs">{formatDateTime(event.occurred_at)}</td>
                      <td className="table-cell font-mono text-xs">{event.action}</td>
                      <td className="table-cell text-xs">{event.actor}</td>
                      <td className="table-cell font-mono text-xs text-muted">
                        {event.target ?? '—'}
                      </td>
                      <td className="table-cell font-mono text-xs text-muted">
                        {event.ip_address ?? '—'}
                      </td>
                      <td className="table-cell">
                        <Badge tone={event.outcome === 'success' ? 'success' : 'danger'}>
                          {event.outcome}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between gap-3 border-t border-border p-3">
              <p className="text-xs text-muted">
                {query.data?.total ?? 0} event(s) — page {page} of {totalPages}
              </p>
              <div className="flex gap-2">
                <Button disabled={page <= 1} onClick={() => setParam('page', String(page - 1))}>
                  Previous
                </Button>
                <Button
                  disabled={page >= totalPages}
                  onClick={() => setParam('page', String(page + 1))}
                >
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
