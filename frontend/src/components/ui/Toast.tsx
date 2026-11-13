/** Toast notifications: success auto-dismisses, errors stay until dismissed. */

import { CircleAlert, CircleCheck, Info, X } from 'lucide-react';
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

type ToastTone = 'success' | 'error' | 'info';

interface Toast {
  id: number;
  tone: ToastTone;
  message: string;
  detail?: string;
}

interface ToastApi {
  success: (message: string, detail?: string) => void;
  error: (message: string, detail?: string) => void;
  info: (message: string, detail?: string) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const TONE_CLASS: Record<ToastTone, string> = {
  success: 'border-success-border',
  error: 'border-danger-border',
  info: 'border-info-border',
};

const TONE_MARK: Record<ToastTone, string> = {
  success: 'bg-success-soft text-success',
  error: 'bg-danger-soft text-danger',
  info: 'bg-info-soft text-info',
};

const TONE_ICON: Record<ToastTone, ReactNode> = {
  success: <CircleCheck className="h-4 w-4" aria-hidden />,
  error: <CircleAlert className="h-4 w-4" aria-hidden />,
  info: <Info className="h-4 w-4" aria-hidden />,
};

let nextId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (tone: ToastTone, message: string, detail?: string) => {
      const id = nextId++;
      setToasts((current) => [...current, { id, tone, message, ...(detail ? { detail } : {}) }]);
      if (tone !== 'error') {
        window.setTimeout(() => dismiss(id), 4000);
      }
    },
    [dismiss],
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (message, detail) => push('success', message, detail),
      error: (message, detail) => push('error', message, detail),
      info: (message, detail) => push('info', message, detail),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2"
        role="status"
        aria-live="polite"
      >
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto flex animate-fade-rise items-start gap-3 rounded-lg border bg-surface-overlay p-3.5 shadow-lg ${TONE_CLASS[toast.tone]}`}
          >
            <span
              className={`mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md ${TONE_MARK[toast.tone]}`}
            >
              {TONE_ICON[toast.tone]}
            </span>
            <div className="flex-1">
              <p className="text-sm font-medium">{toast.message}</p>
              {toast.detail ? <p className="mt-1 text-xs text-muted">{toast.detail}</p> : null}
            </div>
            <button
              type="button"
              onClick={() => dismiss(toast.id)}
              aria-label="Dismiss notification"
              className="rounded-md p-1 text-muted transition-colors duration-fast ease-out hover:bg-surface-hover hover:text-content"
            >
              <X className="h-3.5 w-3.5" aria-hidden />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used inside a ToastProvider');
  }
  return context;
}
