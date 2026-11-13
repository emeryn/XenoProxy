/** Shared design-system primitives. Styling comes from tokens, never literals. */

import { Check, Loader2 } from 'lucide-react';
import {
  forwardRef,
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';

import { cn } from '@/lib/cn';

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'subtle';
type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  icon?: ReactNode;
  /** A right-hand slot, for a chevron or a keyboard hint. */
  trailing?: ReactNode;
}

// The primary button carries the product's gradient, which is the one place in
// the interface where the brand is allowed to be loud. Everything else is a
// surface with a hairline, so a page never has two competing call to actions.
const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary: cn(
    'border-transparent text-primary-content shadow-sm',
    'bg-gradient-to-br from-accent-from to-accent-to',
    'hover:brightness-110 active:brightness-95',
  ),
  secondary: cn(
    'border-border bg-surface-raised text-content shadow-sm',
    'hover:border-border-strong hover:bg-surface-overlay',
  ),
  subtle: 'border-transparent bg-primary-soft text-primary hover:bg-primary-border',
  ghost: 'border-transparent bg-transparent text-muted hover:bg-surface-hover hover:text-content',
  danger: cn(
    'border-danger-border bg-danger-soft text-danger',
    'hover:border-danger hover:bg-danger hover:text-surface',
  ),
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: 'h-8 gap-1.5 rounded-md px-2.5 text-xs',
  md: 'h-9 gap-2 rounded-md px-3.5 text-sm',
  lg: 'h-11 gap-2 rounded-lg px-5 text-base',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'secondary',
    size = 'md',
    loading = false,
    icon,
    trailing,
    className,
    children,
    disabled,
    ...rest
  },
  ref,
) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={cn(
        'inline-flex shrink-0 select-none items-center justify-center border font-medium',
        'transition-[background-color,border-color,color,filter,transform,box-shadow]',
        'duration-fast ease-out active:scale-[0.98]',
        'focus-visible:shadow-focus focus-visible:outline-none',
        'disabled:pointer-events-none disabled:opacity-45',
        BUTTON_SIZES[size],
        BUTTON_VARIANTS[variant],
        className,
      )}
      {...rest}
    >
      {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : icon}
      {children}
      {trailing}
    </button>
  );
});

// A field is a surface that lights up on focus. The ring replaces a border
// colour change, which on a hairline is too small a signal to notice.
const CONTROL = cn(
  'w-full rounded-md border border-border bg-surface-sunken text-content',
  'transition-[border-color,box-shadow,background-color] duration-fast ease-out',
  'placeholder:text-faint',
  'hover:border-border-strong',
  'focus:border-primary focus:bg-surface focus:shadow-accent focus:outline-none',
  'disabled:cursor-not-allowed disabled:opacity-55',
);

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...rest }, ref) {
    return <input ref={ref} className={cn(CONTROL, 'h-9 px-3 text-sm', className)} {...rest} />;
  },
);

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  function Select({ className, children, ...rest }, ref) {
    return (
      <select
        ref={ref}
        className={cn(
          CONTROL,
          // The native arrow is replaced by one drawn in the current text
          // colour, so the control matches the theme instead of the platform.
          'h-9 cursor-pointer appearance-none bg-no-repeat py-0 pl-3 pr-9 text-sm',
          className,
        )}
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%238d9bb0' stroke-width='1.6' stroke-linecap='round'%3E%3Cpath d='M4 6.5 8 10.5l4-4'/%3E%3C/svg%3E\")",
          backgroundPosition: 'right 10px center',
          backgroundSize: '16px 16px',
        }}
        {...rest}
      >
        {children}
      </select>
    );
  },
);

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  function Textarea({ className, ...rest }, ref) {
    return <textarea ref={ref} className={cn(CONTROL, 'p-3 font-mono text-sm', className)} {...rest} />;
  },
);

export function Field({
  label,
  hint,
  error,
  htmlFor,
  required,
  children,
  className,
}: {
  label: string;
  hint?: string;
  error?: string;
  htmlFor?: string;
  required?: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('mb-4', className)}>
      <label className="field-label" htmlFor={htmlFor}>
        {label}
        {required ? <span className="ml-1 text-danger">*</span> : null}
      </label>
      {children}
      {hint && !error ? <p className="mt-1.5 text-xs text-faint">{hint}</p> : null}
      {error ? (
        <p className="mt-1.5 text-xs font-medium text-danger" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

/** A switch reads as a state; a checkbox reads as a choice being made. */
export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled,
  id,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: ReactNode;
  description?: ReactNode;
  disabled?: boolean;
  id?: string;
}) {
  const generated = useId();
  const controlId = id ?? generated;
  return (
    <div className="flex items-start gap-3">
      <button
        id={controlId}
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative mt-0.5 h-5 w-9 shrink-0 rounded-pill border transition-colors duration-base ease-out',
          'focus-visible:shadow-focus focus-visible:outline-none',
          'disabled:cursor-not-allowed disabled:opacity-50',
          checked ? 'border-transparent bg-primary' : 'border-border bg-surface-sunken',
        )}
      >
        <span
          className={cn(
            'absolute top-1/2 h-3.5 w-3.5 -translate-y-1/2 rounded-pill transition-[left] duration-base ease-spring',
            checked ? 'left-[18px] bg-primary-content' : 'left-[3px] bg-muted',
          )}
          aria-hidden
        />
      </button>
      <label htmlFor={controlId} className="cursor-pointer select-none">
        <span className="block text-sm font-medium leading-5">{label}</span>
        {description ? <span className="mt-0.5 block text-xs text-muted">{description}</span> : null}
      </label>
    </div>
  );
}

type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'primary';

// A filled tint, not an outline: a dozen outlined chips on one row turn into
// noise, while tinted ones stay scannable by colour alone.
const TONES: Record<Tone, string> = {
  neutral: 'border-border bg-surface-raised text-muted',
  success: 'border-success-border bg-success-soft text-success',
  warning: 'border-warning-border bg-warning-soft text-warning',
  danger: 'border-danger-border bg-danger-soft text-danger',
  info: 'border-info-border bg-info-soft text-info',
  primary: 'border-primary-border bg-primary-soft text-primary',
};

export function Badge({
  tone = 'neutral',
  children,
  className,
  title,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-pill border px-2 py-0.5',
        'text-xs font-medium',
        TONES[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

/** A dot carries a status in the width of a table cell, where a chip cannot. */
export function StatusDot({ tone = 'neutral', pulse }: { tone?: Tone; pulse?: boolean }) {
  const colour: Record<Tone, string> = {
    neutral: 'bg-faint',
    success: 'bg-success',
    warning: 'bg-warning',
    danger: 'bg-danger',
    info: 'bg-info',
    primary: 'bg-primary',
  };
  return (
    <span className="relative inline-flex h-2 w-2 shrink-0" aria-hidden>
      {pulse ? (
        <span className={cn('absolute inset-0 animate-ping rounded-pill opacity-70', colour[tone])} />
      ) : null}
      <span className={cn('relative h-2 w-2 rounded-pill', colour[tone])} />
    </span>
  );
}

export function Card({
  title,
  description,
  actions,
  icon,
  children,
  className,
  bodyClassName,
  interactive,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  icon?: ReactNode;
  children?: ReactNode;
  className?: string;
  bodyClassName?: string;
  interactive?: boolean;
}) {
  return (
    <section className={cn('card', interactive && 'card-interactive', className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-4 border-b border-border-subtle px-4 py-3">
          <div className="flex min-w-0 items-start gap-3">
            {icon ? (
              <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-md bg-primary-soft text-primary">
                {icon}
              </span>
            ) : null}
            <div className="min-w-0">
              {title ? <h2 className="truncate text-sm font-semibold">{title}</h2> : null}
              {description ? <p className="mt-0.5 text-xs text-muted">{description}</p> : null}
            </div>
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
        </header>
      )}
      {children ? <div className={cn('p-4', bodyClassName)}>{children}</div> : null}
    </section>
  );
}

/** A figure, large enough to be read from across a desk. */
export function Stat({
  label,
  value,
  hint,
  icon,
  tone = 'neutral',
  onClick,
}: {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  tone?: Tone;
  onClick?: () => void;
}) {
  const accent: Record<Tone, string> = {
    neutral: 'text-muted',
    success: 'text-success',
    warning: 'text-warning',
    danger: 'text-danger',
    info: 'text-info',
    primary: 'text-primary',
  };
  const body = (
    <>
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-medium uppercase tracking-wide text-faint">{label}</p>
        {icon ? <span className={cn('shrink-0', accent[tone])}>{icon}</span> : null}
      </div>
      <p className={cn('mt-2 text-2xl font-semibold tabular', accent[tone])}>{value}</p>
      {hint ? <p className="mt-1 text-xs text-muted">{hint}</p> : null}
    </>
  );

  if (!onClick) return <div className="card p-4">{body}</div>;
  return (
    <button type="button" onClick={onClick} className="card card-interactive p-4 text-left">
      {body}
    </button>
  );
}

/** Two to five mutually exclusive views; more than that belongs in a Select. */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  label,
  className,
}: {
  value: T;
  onChange: (next: T) => void;
  options: { value: T; label: ReactNode; icon?: ReactNode }[];
  label: string;
  className?: string;
}) {
  return (
    <div
      role="tablist"
      aria-label={label}
      className={cn(
        'inline-flex items-center gap-0.5 rounded-lg border border-border bg-surface-sunken p-0.5',
        className,
      )}
    >
      {options.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(option.value)}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium',
              'transition-colors duration-fast ease-out focus-visible:shadow-focus focus-visible:outline-none',
              active
                ? 'bg-surface-raised text-content shadow-sm'
                : 'text-muted hover:text-content',
            )}
          >
            {option.icon}
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

/** A menu anchored to its trigger, closing on outside click and on Escape. */
export function Menu({
  trigger,
  children,
  align = 'end',
  className,
}: {
  trigger: (props: { open: boolean; toggle: () => void }) => ReactNode;
  children: (props: { close: () => void }) => ReactNode;
  align?: 'start' | 'end';
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return undefined;
    function onPointerDown(event: MouseEvent) {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false);
    }
    window.document.addEventListener('mousedown', onPointerDown);
    window.document.addEventListener('keydown', onKeyDown);
    return () => {
      window.document.removeEventListener('mousedown', onPointerDown);
      window.document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  return (
    <div ref={container} className="relative">
      {trigger({ open, toggle: () => setOpen((previous) => !previous) })}
      {open ? (
        <div
          role="menu"
          className={cn(
            'absolute top-[calc(100%+6px)] z-50 min-w-52 animate-fade-rise rounded-lg border border-border',
            'bg-surface-overlay p-1 shadow-lg',
            align === 'end' ? 'right-0' : 'left-0',
            className,
          )}
        >
          {children({ close: () => setOpen(false) })}
        </div>
      ) : null}
    </div>
  );
}

export function MenuItem({
  icon,
  children,
  onClick,
  tone = 'neutral',
}: {
  icon?: ReactNode;
  children: ReactNode;
  onClick?: () => void;
  tone?: 'neutral' | 'danger';
}) {
  return (
    <button
      type="button"
      role="menuitem"
      onClick={onClick}
      className={cn(
        'flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm',
        'transition-colors duration-fast ease-out focus-visible:shadow-focus focus-visible:outline-none',
        tone === 'danger'
          ? 'text-danger hover:bg-danger-soft'
          : 'text-content hover:bg-surface-hover',
      )}
    >
      {icon ? <span className="shrink-0 text-muted">{icon}</span> : null}
      {children}
    </button>
  );
}

/**
 * A selectable surface: the whole tile is the control.
 *
 * It replaces a native checkbox next to a label. A native control cannot be
 * styled consistently across platforms, and at this size the hit area is the
 * label anyway, so the tile carries the state and the mark only reports it.
 */
export function SelectTile({
  selected,
  onToggle,
  title,
  description,
  badges,
  footer,
  multiple = true,
  disabled,
  className,
}: {
  selected: boolean;
  onToggle: () => void;
  title: ReactNode;
  description?: ReactNode;
  badges?: ReactNode;
  footer?: ReactNode;
  /** Checkbox semantics by default; a radio when only one may be chosen. */
  multiple?: boolean;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <button
      type="button"
      role={multiple ? 'checkbox' : 'radio'}
      aria-checked={selected}
      disabled={disabled}
      onClick={onToggle}
      className={cn(
        'group relative flex w-full gap-3 rounded-lg border p-3 text-left',
        'transition-[border-color,background-color,box-shadow] duration-fast ease-out',
        'focus-visible:shadow-focus focus-visible:outline-none',
        'disabled:cursor-not-allowed disabled:opacity-50',
        selected
          ? 'border-primary-border bg-primary-soft shadow-accent'
          : 'border-border bg-surface-raised hover:border-border-strong hover:bg-surface-overlay',
        className,
      )}
    >
      <span
        className={cn(
          'mt-0.5 grid h-4 w-4 shrink-0 place-items-center border transition-colors duration-fast ease-out',
          multiple ? 'rounded-sm' : 'rounded-pill',
          selected
            ? 'border-primary bg-primary text-primary-content'
            : 'border-border-strong bg-surface-sunken',
        )}
        aria-hidden
      >
        {selected ? (
          multiple ? (
            <Check className="h-3 w-3" strokeWidth={3} />
          ) : (
            <span className="h-1.5 w-1.5 rounded-pill bg-primary-content" />
          )
        ) : null}
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className={cn('text-sm font-medium', selected && 'text-primary')}>{title}</span>
          {badges}
        </span>
        {description ? (
          <span className="mt-1 block text-xs leading-relaxed text-muted">{description}</span>
        ) : null}
        {footer ? <span className="mt-1.5 block text-xs text-faint">{footer}</span> : null}
      </span>
    </button>
  );
}

export function EmptyState({
  title,
  description,
  action,
  icon,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      {icon ? (
        <span className="grid h-12 w-12 place-items-center rounded-xl border border-border bg-surface-sunken text-faint">
          {icon}
        </span>
      ) : null}
      <p className="text-base font-medium">{title}</p>
      {description ? <p className="max-w-md text-sm text-muted">{description}</p> : null}
      {action ? <div className="mt-1">{action}</div> : null}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('skeleton h-4 w-full', className)} aria-hidden />;
}

export function TableSkeleton({ rows = 5, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <div className="p-4" aria-busy="true" aria-live="polite">
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className="mb-3 flex gap-4">
          {Array.from({ length: columns }).map((__, columnIndex) => (
            <Skeleton key={columnIndex} className="flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

export function ErrorBanner({
  message,
  requestId,
  onRetry,
}: {
  message: string;
  requestId?: string;
  onRetry?: () => void;
}) {
  return (
    <div
      className="flex items-start justify-between gap-4 rounded-lg border border-danger-border bg-danger-soft p-3.5"
      role="alert"
    >
      <div>
        <p className="text-sm font-medium text-danger">{message}</p>
        {requestId && requestId !== '-' ? (
          <p className="mt-1 font-mono text-xs text-muted">Reference for support: {requestId}</p>
        ) : null}
      </div>
      {onRetry ? (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}
