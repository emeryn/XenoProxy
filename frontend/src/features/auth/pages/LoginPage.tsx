/**
 * Sign-in page, in two steps.
 *
 * The password step opens a session only when the account has no
 * authenticator. Otherwise it answers a challenge token and no session, and the
 * code from the authenticator is what completes the sign-in. The two steps are
 * one page because they are one action: the password is never asked twice.
 */

import { Database, GitBranch, Radar, ShieldCheck } from 'lucide-react';
import { useState } from 'react';

import { useAuth } from '@/app/auth-context';
import { Button, ErrorBanner, Field, Input } from '@/components/ui';
import { LogoLockup, LogoMark } from '@/components/ui/Logo';
import { ApiError } from '@/lib/api-client';

interface Failure {
  message: string;
  requestId: string;
}

function describe(caught: unknown, fallback: string): Failure {
  return {
    message: caught instanceof ApiError ? caught.message : fallback,
    requestId: caught instanceof ApiError ? caught.requestId : '-',
  };
}

// What the product does, in the words an analyst would use. It is on the
// sign-in page because that is the one screen a new team member reads.
const CAPABILITIES = [
  {
    icon: <Radar className="h-4 w-4" aria-hidden />,
    title: 'Queried in parallel',
    body: 'One observable, queried across your reputation, exposure and sandbox providers in parallel.',
  },
  {
    icon: <Database className="h-4 w-4" aria-hidden />,
    title: 'Quota kept',
    body: 'A shared cache means the team never spends the same paid lookup twice.',
  },
  {
    icon: <GitBranch className="h-4 w-4" aria-hidden />,
    title: 'Pivots and playbooks',
    body: 'Follow a bad verdict to the hosting address, or run a preset pipeline in one click.',
  },
];

export function LoginPage() {
  const { signIn, completeMfa, methods } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState<Failure | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onPassword(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await signIn(username, password);
      if (result.mfa_required && result.challenge_token) {
        setChallenge(result.challenge_token);
        // The password is not kept: the second step authenticates with the
        // challenge token, so there is nothing left to hold on to.
        setPassword('');
      }
    } catch (caught) {
      setError(describe(caught, 'Sign-in failed. Try again.'));
    } finally {
      setSubmitting(false);
    }
  }

  async function onCode(event: React.FormEvent) {
    event.preventDefault();
    if (!challenge) return;
    setError(null);
    setSubmitting(true);
    try {
      const result = await completeMfa(challenge, code.trim());
      if (!result.user) {
        setCode('');
        setError({ message: 'The code was accepted but no session was opened.', requestId: '-' });
      }
    } catch (caught) {
      setCode('');
      setError(describe(caught, 'The code was refused. Try the next one.'));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-[1.1fr_1fr]">
      {/* The brand panel is hidden on a narrow window: on a phone the form is
          the only thing worth the screen. */}
      <aside className="relative hidden flex-col justify-between overflow-hidden border-r border-border bg-surface p-10 lg:flex">
        <div
          className="pointer-events-none absolute inset-0 opacity-70"
          style={{
            backgroundImage:
              'radial-gradient(700px 420px at 15% 10%, var(--color-primary-soft), transparent 70%), radial-gradient(600px 500px at 90% 90%, var(--color-info-soft), transparent 70%)',
          }}
          aria-hidden
        />
        <div className="relative">
          <LogoLockup size={40} />
          <p className="mt-10 max-w-md text-3xl font-semibold leading-tight">
            The <span className="text-gradient">secure gateway</span> to global threat
            intelligence.
          </p>
          <p className="mt-3 max-w-md text-sm text-muted">
            XenoProxy holds the API keys, runs the sources, and keeps the team's history in one place.
          </p>
        </div>

        <ul className="relative mt-10 space-y-5">
          {CAPABILITIES.map((item) => (
            <li key={item.title} className="flex gap-3.5">
              <span className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-primary-border bg-primary-soft text-primary">
                {item.icon}
              </span>
              <span>
                <span className="block text-sm font-medium">{item.title}</span>
                <span className="mt-0.5 block max-w-sm text-xs leading-relaxed text-muted">
                  {item.body}
                </span>
              </span>
            </li>
          ))}
        </ul>

        <p className="relative text-xs text-faint">XenoProxy v0.1.0 — self-hosted, no telemetry.</p>
      </aside>

      <main className="flex items-center justify-center p-5">
        <div className="w-full max-w-sm">
          <div className="mb-7 flex flex-col items-center gap-2 text-center lg:hidden">
            <LogoLockup size={40} />
            <p className="text-xs text-muted">OSINT and threat-intelligence orchestration</p>
          </div>

          {challenge ? (
            <form onSubmit={onCode} className="card animate-fade-rise p-6">
              <div className="mb-5 flex items-center gap-3">
                <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-primary-soft text-primary">
                  <ShieldCheck className="h-5 w-5" aria-hidden />
                </span>
                <div>
                  <h1 className="text-lg font-semibold">Two-factor check</h1>
                  <p className="text-xs text-muted">
                    The code from your authenticator for <strong>{username}</strong>.
                  </p>
                </div>
              </div>

              <Field
                label="Authentication code"
                htmlFor="mfa-code"
                required
                hint="A recovery code works here too, if you no longer have the authenticator."
              >
                <Input
                  id="mfa-code"
                  name="code"
                  // `one-time-code` is what makes a phone offer the code it just
                  // received, and a password manager fill it.
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  autoFocus
                  required
                  maxLength={32}
                  className="h-12 text-center font-mono text-lg tracking-[0.35em]"
                  value={code}
                  onChange={(event) => setCode(event.target.value)}
                />
              </Field>

              {error ? (
                <div className="mb-4">
                  <ErrorBanner message={error.message} requestId={error.requestId} />
                </div>
              ) : null}

              <Button
                type="submit"
                variant="primary"
                size="lg"
                className="w-full"
                loading={submitting}
                disabled={code.trim().length < 6}
              >
                Verify
              </Button>
              <Button
                type="button"
                variant="ghost"
                className="mt-2 w-full"
                onClick={() => {
                  setChallenge(null);
                  setCode('');
                  setError(null);
                }}
              >
                Start over
              </Button>
            </form>
          ) : (
            <form onSubmit={onPassword} className="card p-6">
              <div className="mb-5 flex items-center gap-3 lg:mb-6">
                <LogoMark size={32} className="lg:hidden" />
                <div>
                  <h1 className="text-lg font-semibold">Sign in</h1>
                  <p className="text-xs text-muted">Use your XenoProxy or directory account.</p>
                </div>
              </div>

              <Field label="Username" htmlFor="username" required>
                <Input
                  id="username"
                  name="username"
                  autoComplete="username"
                  autoFocus
                  required
                  maxLength={128}
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                />
              </Field>
              <Field label="Password" htmlFor="password" required>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  maxLength={128}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </Field>

              {error ? (
                <div className="mb-4">
                  <ErrorBanner message={error.message} requestId={error.requestId} />
                </div>
              ) : null}

              <Button
                type="submit"
                variant="primary"
                size="lg"
                className="w-full"
                loading={submitting}
              >
                Sign in
              </Button>

              {methods?.oidc_enabled ? (
                <>
                  <div className="my-4 flex items-center gap-3">
                    <span className="h-px flex-1 bg-border" aria-hidden />
                    <span className="text-xs text-faint">or</span>
                    <span className="h-px flex-1 bg-border" aria-hidden />
                  </div>
                  <a
                    href="/api/v1/auth/oidc/start"
                    className="flex h-11 items-center justify-center gap-2 rounded-lg border border-border bg-surface-raised text-sm font-medium shadow-sm transition-colors duration-fast ease-out hover:border-border-strong hover:bg-surface-overlay"
                  >
                    <ShieldCheck className="h-4 w-4 text-primary" aria-hidden />
                    Sign in with single sign-on
                  </a>
                </>
              ) : null}
              {methods?.proxy_enabled ? (
                <p className="mt-3 text-xs text-muted">
                  This instance also accepts identities delegated by the reverse proxy.
                </p>
              ) : null}
            </form>
          )}

          <details className="mt-5 text-center">
            <summary className="cursor-pointer text-xs text-faint transition-colors duration-fast ease-out hover:text-muted">
              First sign-in on a new instance?
            </summary>
            <p className="mt-2 text-left text-xs leading-relaxed text-muted">
              Read the first administrator's password with{' '}
              <code className="rounded bg-surface-sunken px-1.5 py-0.5 font-mono">
                docker compose run --rm api admin-password
              </code>
              . If it is refused, reapply it with{' '}
              <code className="rounded bg-surface-sunken px-1.5 py-0.5 font-mono">
                docker compose run --rm api reset-admin
              </code>
              .
            </p>
          </details>
        </div>
      </main>
    </div>
  );
}
