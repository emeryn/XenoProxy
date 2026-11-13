/** Catches render failures so a broken page never shows a blank screen. */

import { Component, type ErrorInfo, type ReactNode } from 'react';

import { Button } from '@/components/ui';

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('Unhandled render error', error, info.componentStack);
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="card max-w-lg p-6">
          <h1 className="text-lg font-semibold">This page could not be displayed</h1>
          <p className="mt-2 text-sm text-muted">
            The interface hit an unexpected error. Reloading usually resolves it; if it persists,
            report the message below to your administrator.
          </p>
          <pre className="mt-3 overflow-auto rounded bg-surface-sunken p-3 text-xs">
            {error.message}
          </pre>
          <Button variant="primary" className="mt-4" onClick={() => window.location.reload()}>
            Reload the page
          </Button>
        </div>
      </div>
    );
  }
}
