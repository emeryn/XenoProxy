/**
 * Enrolling, replacing and turning off an authenticator.
 *
 * The secret is shown once, as text and as an `otpauth://` link. No QR code:
 * drawing one needs a library, and the application bundles everything it
 * serves, so a dependency added for a convenience is a dependency to audit and
 * to keep patched. Every authenticator accepts a typed secret, and the link
 * works on the device that is already holding the page.
 *
 * The recovery codes are shown once too, for the same reason the secret is:
 * they are stored hashed and cannot be displayed again.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, Copy, ShieldCheck, ShieldOff } from 'lucide-react';
import { useState } from 'react';

import { useAuth } from '@/app/auth-context';
import { Badge, Button, Card, Field, Input, Skeleton } from '@/components/ui';
import { useToast } from '@/components/ui/Toast';
import { ApiError, api } from '@/lib/api-client';
import { formatDateTime } from '@/lib/format';
import type { MfaEnrolment, MfaStatus } from '@/lib/types';

export function MfaPanel() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { refresh } = useAuth();

  const [enrolment, setEnrolment] = useState<MfaEnrolment | null>(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');

  const statusQuery = useQuery({
    queryKey: ['auth', 'mfa'],
    queryFn: () => api.get<MfaStatus>('/auth/mfa'),
  });

  function reportError(title: string) {
    return (error: unknown) =>
      toast.error(title, error instanceof ApiError ? error.message : 'Unexpected failure.');
  }

  async function settled() {
    await queryClient.invalidateQueries({ queryKey: ['auth', 'mfa'] });
    await refresh();
  }

  const beginMutation = useMutation({
    mutationFn: () => api.post<MfaEnrolment>('/auth/mfa/enrol'),
    onSuccess: (result) => {
      setEnrolment(result);
      setCode('');
    },
    onError: reportError('Enrolment could not be started'),
  });

  const confirmMutation = useMutation({
    mutationFn: () => api.post<{ codes: string[] }>('/auth/mfa/confirm', { code: code.trim() }),
    onSuccess: async (result) => {
      setEnrolment(null);
      setCode('');
      setCodes(result.codes);
      toast.success('Two-factor authentication is on');
      await settled();
    },
    onError: (error) => {
      setCode('');
      reportError('The code was refused')(error);
    },
  });

  const regenerateMutation = useMutation({
    mutationFn: () => api.post<{ codes: string[] }>('/auth/mfa/recovery-codes'),
    onSuccess: async (result) => {
      setCodes(result.codes);
      toast.success('New recovery codes issued', 'The previous ones no longer work.');
      await settled();
    },
    onError: reportError('The codes could not be replaced'),
  });

  const disableMutation = useMutation({
    mutationFn: () =>
      api.post<{ message: string }>('/auth/mfa/disable', {
        password: disablePassword,
        code: disableCode.trim(),
      }),
    onSuccess: async () => {
      setDisablePassword('');
      setDisableCode('');
      toast.success('Two-factor authentication is off');
      await settled();
    },
    onError: reportError('Two-factor could not be turned off'),
  });

  function copy(text: string, what: string) {
    void navigator.clipboard
      .writeText(text)
      .then(() => toast.success(`${what} copied`))
      .catch(() => toast.error(`${what} could not be copied`, 'Select it and copy it by hand.'));
  }

  if (statusQuery.isLoading) {
    return (
      <Card title="Two-factor authentication" className="mb-4">
        <Skeleton className="h-24" />
      </Card>
    );
  }

  const status = statusQuery.data;

  return (
    <Card
      title="Two-factor authentication"
      description="A code from an authenticator application, on top of your password."
      className="mb-4"
      actions={
        status?.enabled ? (
          <Badge tone="success">
            <ShieldCheck className="h-3 w-3" aria-hidden />
            On
          </Badge>
        ) : status?.required ? (
          <Badge tone="warning">Required</Badge>
        ) : (
          <Badge tone="neutral">
            <ShieldOff className="h-3 w-3" aria-hidden />
            Off
          </Badge>
        )
      }
    >
      {status?.required && !status.enabled ? (
        <p className="mb-4 rounded-lg border border-warning-border bg-warning-soft p-3 text-sm">
          {status.requirement_reason ??
            'This instance requires two-factor authentication for your account.'}{' '}
          Enrol an authenticator to keep using the platform.
        </p>
      ) : null}

      {codes ? (
        <div className="mb-4 rounded-lg border border-warning-border bg-warning-soft p-3">
          <p className="text-sm font-medium">Your recovery codes</p>
          <p className="mt-1 text-xs text-muted">
            Each works once, in place of a code from the authenticator. They are stored hashed and
            cannot be shown again: save them somewhere safe now.
          </p>
          <ul className="mt-2 grid gap-1 font-mono text-xs sm:grid-cols-2">
            {codes.map((entry) => (
              <li key={entry}>{entry}</li>
            ))}
          </ul>
          <div className="mt-3 flex gap-2">
            <Button
              onClick={() => copy(codes.join('\n'), 'Recovery codes')}
              icon={<Copy className="h-4 w-4" aria-hidden />}
            >
              Copy
            </Button>
            <Button
              variant="primary"
              onClick={() => setCodes(null)}
              icon={<Check className="h-4 w-4" aria-hidden />}
            >
              I saved them
            </Button>
          </div>
        </div>
      ) : null}

      {enrolment ? (
        <div className="rounded-lg border border-border p-3">
          <p className="text-sm font-medium">Add this secret to your authenticator</p>
          <p className="mt-1 break-all font-mono text-sm">{enrolment.secret}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button
              onClick={() => copy(enrolment.secret, 'Secret')}
              icon={<Copy className="h-4 w-4" aria-hidden />}
            >
              Copy the secret
            </Button>
            <a
              href={enrolment.otpauth_uri}
              className="rounded-lg border border-border px-3 py-1.5 text-sm hover:bg-surface-sunken"
            >
              Open in an authenticator on this device
            </a>
          </div>

          <div className="mt-4">
            <Field label="Then enter the code it shows" htmlFor="mfa-enrol-code" required>
              <Input
                id="mfa-enrol-code"
                autoComplete="one-time-code"
                inputMode="numeric"
                maxLength={16}
                className="font-mono tracking-widest"
                value={code}
                onChange={(event) => setCode(event.target.value)}
              />
            </Field>
          </div>
          <div className="flex gap-2">
            <Button
              variant="primary"
              loading={confirmMutation.isPending}
              disabled={code.trim().length < 6}
              onClick={() => confirmMutation.mutate()}
            >
              Confirm
            </Button>
            <Button onClick={() => setEnrolment(null)}>Cancel</Button>
          </div>
        </div>
      ) : status?.enabled ? (
        <>
          <p className="text-sm text-muted">
            Enrolled {formatDateTime(status.confirmed_at)} ·{' '}
            {status.recovery_codes_remaining} recovery code(s) left.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button
              loading={regenerateMutation.isPending}
              onClick={() => {
                if (window.confirm('Replace your recovery codes? The current ones stop working.')) {
                  regenerateMutation.mutate();
                }
              }}
            >
              Replace the recovery codes
            </Button>
          </div>

          {status.required ? (
            <p className="mt-4 text-xs text-muted">
              Two-factor is required for your account on this instance, so it cannot be turned
              off here.
            </p>
          ) : (
            <details className="mt-4">
              <summary className="cursor-pointer text-xs text-muted">
                Turn two-factor off
              </summary>
              <p className="mt-2 text-xs text-muted">
                Both your password and a current code are required, so losing either one cannot
                be used to remove the second factor.
              </p>
              <Field label="Password" htmlFor="mfa-off-password" required>
                <Input
                  id="mfa-off-password"
                  type="password"
                  autoComplete="current-password"
                  value={disablePassword}
                  onChange={(event) => setDisablePassword(event.target.value)}
                />
              </Field>
              <Field label="Authentication code" htmlFor="mfa-off-code" required>
                <Input
                  id="mfa-off-code"
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  maxLength={16}
                  className="font-mono tracking-widest"
                  value={disableCode}
                  onChange={(event) => setDisableCode(event.target.value)}
                />
              </Field>
              <Button
                variant="danger"
                loading={disableMutation.isPending}
                disabled={!disablePassword || disableCode.trim().length < 6}
                onClick={() => disableMutation.mutate()}
              >
                Turn it off
              </Button>
            </details>
          )}
        </>
      ) : (
        <Button
          variant="primary"
          loading={beginMutation.isPending}
          onClick={() => beginMutation.mutate()}
          icon={<ShieldCheck className="h-4 w-4" aria-hidden />}
        >
          Enrol an authenticator
        </Button>
      )}
    </Card>
  );
}
