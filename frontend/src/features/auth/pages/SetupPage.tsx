/**
 * What an account has to finish before it can use the platform.
 *
 * The backend refuses almost every call while a password change or an
 * authenticator enrolment is outstanding, so landing such an account in the
 * normal interface would show a shell whose every panel fails. This page is
 * that gate: it offers exactly the steps that are owed, and nothing else.
 */

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { KeyRound } from 'lucide-react';
import { useState } from 'react';

import { useAuth } from '@/app/auth-context';
import { Button, Card, ErrorBanner, Field, Input } from '@/components/ui';
import { LogoLockup } from '@/components/ui/Logo';
import { useToast } from '@/components/ui/Toast';
import { ApiError, api } from '@/lib/api-client';
import { MfaPanel } from '../components/MfaPanel';

function PasswordStep() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      api.post<{ message: string }>('/auth/password', {
        current_password: currentPassword,
        new_password: newPassword,
      }),
    onSuccess: (response) => {
      toast.success(response.message);
      void queryClient.invalidateQueries({ queryKey: ['auth', 'me'] });
    },
    onError: (caught) =>
      setError(caught instanceof ApiError ? caught.message : 'The password was refused.'),
  });

  const mismatch = Boolean(confirmation) && confirmation !== newPassword;

  return (
    <Card
      title="Choose a password"
      description="This account was given a password it did not choose, so it has to be replaced before anything else."
      className="mb-4"
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setError(null);
          mutation.mutate();
        }}
      >
        <Field label="Current password" htmlFor="setup-current" required>
          <Input
            id="setup-current"
            type="password"
            autoComplete="current-password"
            autoFocus
            required
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
          />
        </Field>
        <Field
          label="New password"
          htmlFor="setup-new"
          required
          hint="At least 12 characters. A long passphrase beats a short complicated one."
        >
          <Input
            id="setup-new"
            type="password"
            autoComplete="new-password"
            required
            minLength={12}
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
          />
        </Field>
        <Field
          label="New password again"
          htmlFor="setup-confirm"
          required
          error={mismatch ? 'The two entries do not match.' : undefined}
        >
          <Input
            id="setup-confirm"
            type="password"
            autoComplete="new-password"
            required
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
          />
        </Field>

        {error ? (
          <div className="mb-4">
            <ErrorBanner message={error} />
          </div>
        ) : null}

        <Button
          type="submit"
          variant="primary"
          loading={mutation.isPending}
          disabled={mismatch || newPassword.length < 12 || !currentPassword}
          icon={<KeyRound className="h-4 w-4" aria-hidden />}
        >
          Set the password
        </Button>
      </form>
    </Card>
  );
}

export function SetupPage() {
  const { user, signOut } = useAuth();
  const needsPassword = Boolean(user?.must_change_password);
  // One thing at a time: the password is replaced first, then the authenticator.
  const needsMfa = !needsPassword && Boolean(user?.mfa_required) && !user?.mfa_enabled;

  return (
    <div className="flex min-h-screen items-start justify-center p-4 pt-10">
      <div className="w-full max-w-xl">
        <div className="mb-7 flex flex-col items-center gap-2 text-center">
          <LogoLockup size={40} />
          <p className="text-sm">
            Welcome, <strong>{user?.username}</strong>. Two steps and you are in.
          </p>
        </div>

        {needsPassword ? <PasswordStep /> : null}
        {needsMfa ? <MfaPanel /> : null}

        <p className="text-center">
          <Button onClick={() => void signOut()}>Sign out</Button>
        </p>
      </div>
    </div>
  );
}
