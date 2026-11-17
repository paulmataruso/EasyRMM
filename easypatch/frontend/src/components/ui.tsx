import {
  forwardRef,
  useId,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';
import { AlertTriangle, ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Inbox, Info, Loader2, OctagonAlert, RefreshCw } from 'lucide-react';
import { errorMessage, ApiError } from '../api/client';

export function cx(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(' ');
}

// ---------------------------------------------------------------------------------------------
// Buttons
// ---------------------------------------------------------------------------------------------

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-ghost';
type ButtonSize = 'sm' | 'md';

const variantClasses: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-accent-fg hover:bg-accent-hover border border-transparent shadow-xs',
  secondary: 'bg-surface text-fg border border-line hover:bg-hover shadow-xs',
  ghost: 'bg-transparent text-fg border border-transparent hover:bg-hover',
  danger: 'bg-danger text-white border border-transparent hover:opacity-90 shadow-xs dark:text-[#1a0606]',
  'danger-ghost': 'bg-transparent text-danger border border-transparent hover:bg-danger-soft',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', loading = false, icon, className, children, disabled, type = 'button', ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cx(
        'inline-flex items-center justify-center gap-1.5 rounded-md font-medium whitespace-nowrap transition-colors disabled:cursor-not-allowed disabled:opacity-55',
        size === 'sm' ? 'h-7 px-2.5 text-xs' : 'h-8.5 px-3.5 text-sm',
        variantClasses[variant],
        className,
      )}
      {...rest}
    >
      {loading ? <Loader2 className="size-4 animate-spin" aria-hidden /> : icon}
      {children}
    </button>
  );
});

export function IconButton({
  label,
  children,
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cx('inline-flex size-8 items-center justify-center rounded-md text-muted hover:bg-hover hover:text-fg', className)}
      {...rest}
    >
      {children}
    </button>
  );
}

// ---------------------------------------------------------------------------------------------
// Layout primitives
// ---------------------------------------------------------------------------------------------

export function Card({ children, className, title, actions, padded = true }: {
  children: ReactNode;
  className?: string;
  title?: ReactNode;
  actions?: ReactNode;
  padded?: boolean;
}) {
  return (
    <section className={cx('rounded-lg border border-line bg-surface shadow-xs', className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2.5">
          {title && <h2 className="text-sm font-semibold text-fg">{title}</h2>}
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={padded ? 'p-4' : undefined}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions, breadcrumb }: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  breadcrumb?: ReactNode;
}) {
  return (
    <div className="mb-5">
      {breadcrumb && <div className="mb-1 text-xs text-muted">{breadcrumb}</div>}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="truncate text-xl font-semibold text-fg">{title}</h1>
          {subtitle && <div className="mt-0.5 text-sm text-muted">{subtitle}</div>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </div>
  );
}

export function Toolbar({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx('mb-3 flex flex-wrap items-end gap-2', className)}>{children}</div>;
}

// ---------------------------------------------------------------------------------------------
// Badges
// ---------------------------------------------------------------------------------------------

export type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'neutral' | 'accent';

const toneClasses: Record<Tone, string> = {
  ok: 'bg-ok-soft text-ok',
  warn: 'bg-warn-soft text-warn',
  danger: 'bg-danger-soft text-danger',
  info: 'bg-info-soft text-info',
  neutral: 'bg-neutral-soft text-muted',
  accent: 'bg-accent-soft text-accent',
};

export function Badge({ tone = 'neutral', children, className, title, icon }: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
  title?: string;
  icon?: ReactNode;
}) {
  return (
    <span
      title={title}
      className={cx(
        'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap',
        toneClasses[tone],
        className,
      )}
    >
      {icon}
      {children}
    </span>
  );
}

export function Dot({ tone }: { tone: Tone }) {
  const color: Record<Tone, string> = {
    ok: 'bg-ok',
    warn: 'bg-warn',
    danger: 'bg-danger',
    info: 'bg-info',
    neutral: 'bg-subtle',
    accent: 'bg-accent',
  };
  return <span aria-hidden className={cx('inline-block size-2 shrink-0 rounded-full', color[tone])} />;
}

// ---------------------------------------------------------------------------------------------
// States
// ---------------------------------------------------------------------------------------------

export function Spinner({ label = 'Loading…', className }: { label?: string; className?: string }) {
  return (
    <div role="status" className={cx('flex items-center justify-center gap-2 py-10 text-sm text-muted', className)}>
      <Loader2 className="size-4 animate-spin" aria-hidden />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ title, children, icon, action }: { title: string; children?: ReactNode; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center">
      <div className="text-subtle">{icon ?? <Inbox className="size-8" aria-hidden />}</div>
      <p className="font-medium text-fg">{title}</p>
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, compact = false }: { error: unknown; onRetry?: () => void; compact?: boolean }) {
  const notFound = error instanceof ApiError && error.status === 404;
  const correlation = error instanceof ApiError ? error.correlationId : null;
  return (
    <div className={cx('flex flex-col items-center justify-center gap-2 px-4 text-center', compact ? 'py-4' : 'py-10')} role="alert">
      <OctagonAlert className="size-7 text-danger" aria-hidden />
      <p className="font-medium text-fg">{notFound ? 'Not found' : 'Could not load this data'}</p>
      <p className="max-w-md text-sm text-muted">{errorMessage(error)}</p>
      {correlation && <p className="text-xs text-subtle">Reference: <code>{correlation}</code></p>}
      {onRetry && !notFound && (
        <Button size="sm" onClick={onRetry} icon={<RefreshCw className="size-3.5" aria-hidden />}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Alert({ tone = 'info', title, children, className }: { tone?: 'info' | 'warn' | 'danger' | 'ok'; title?: ReactNode; children?: ReactNode; className?: string }) {
  const styles = {
    info: 'border-info/40 bg-info-soft',
    warn: 'border-warn/40 bg-warn-soft',
    danger: 'border-danger/40 bg-danger-soft',
    ok: 'border-ok/40 bg-ok-soft',
  }[tone];
  const iconColor = { info: 'text-info', warn: 'text-warn', danger: 'text-danger', ok: 'text-ok' }[tone];
  const Icon = tone === 'info' || tone === 'ok' ? Info : AlertTriangle;
  return (
    <div className={cx('flex gap-2.5 rounded-md border px-3 py-2.5 text-sm', styles, className)} role={tone === 'danger' ? 'alert' : undefined}>
      <Icon className={cx('mt-0.5 size-4 shrink-0', iconColor)} aria-hidden />
      <div className="min-w-0 text-fg">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className={cx(title ? 'mt-0.5' : '', 'text-fg/90')}>{children}</div>}
      </div>
    </div>
  );
}

export function InlineError({ error }: { error: unknown }) {
  if (!error) return null;
  const correlation = error instanceof ApiError ? error.correlationId : null;
  return (
    <Alert tone="danger">
      {errorMessage(error)}
      {correlation && <span className="ml-1 text-xs text-muted">(ref {correlation})</span>}
    </Alert>
  );
}

// ---------------------------------------------------------------------------------------------
// Form fields
// ---------------------------------------------------------------------------------------------

export function Field({ label, hint, error, children, htmlFor, className, required }: {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
  htmlFor?: string;
  className?: string;
  required?: boolean;
}) {
  return (
    <div className={cx('flex flex-col gap-1', className)}>
      <label htmlFor={htmlFor} className="text-xs font-medium text-muted">
        {label}
        {required && <span className="ml-0.5 text-danger" aria-hidden>*</span>}
      </label>
      {children}
      {error ? <p className="text-xs text-danger">{error}</p> : hint ? <p className="text-xs text-subtle">{hint}</p> : null}
    </div>
  );
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...rest }, ref) {
  return <input ref={ref} className={cx('input', className)} {...rest} />;
});

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea({ className, ...rest }, ref) {
  return <textarea ref={ref} className={cx('input min-h-20', className)} {...rest} />;
});

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, children, ...rest }, ref) {
  return (
    <select ref={ref} className={cx('input pr-8', className)} {...rest}>
      {children}
    </select>
  );
});

/** Labelled input with generated id. */
export function TextField({ label, hint, error, required, className, ...rest }: InputHTMLAttributes<HTMLInputElement> & {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
}) {
  const id = useId();
  return (
    <Field label={label} hint={hint} error={error} htmlFor={id} className={className} required={required}>
      <Input id={id} required={required} aria-invalid={error ? true : undefined} {...rest} />
    </Field>
  );
}

export function SelectField({ label, hint, error, className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement> & {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
}) {
  const id = useId();
  return (
    <Field label={label} hint={hint} error={error} htmlFor={id} className={className} required={rest.required}>
      <Select id={id} {...rest}>
        {children}
      </Select>
    </Field>
  );
}

export function Checkbox({ label, hint, className, ...rest }: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode; hint?: ReactNode }) {
  const id = useId();
  return (
    <div className={cx('flex items-start gap-2', className)}>
      <input id={id} type="checkbox" className="mt-0.5 size-4 shrink-0 rounded border-line" {...rest} />
      <label htmlFor={id} className="text-sm text-fg">
        {label}
        {hint && <span className="block text-xs text-muted">{hint}</span>}
      </label>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Tabs (URL-agnostic; parents decide where the active tab lives)
// ---------------------------------------------------------------------------------------------

export interface TabDef {
  id: string;
  label: ReactNode;
  count?: number | null;
  hidden?: boolean;
}

export function Tabs({ tabs, active, onChange, className }: { tabs: TabDef[]; active: string; onChange: (id: string) => void; className?: string }) {
  const visible = tabs.filter((t) => !t.hidden);
  return (
    <div role="tablist" aria-orientation="horizontal" className={cx('mb-4 flex gap-1 overflow-x-auto border-b border-line', className)}
      onKeyDown={(e) => {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        const index = visible.findIndex((t) => t.id === active);
        const next = visible[(index + (e.key === 'ArrowRight' ? 1 : visible.length - 1)) % visible.length];
        onChange(next.id);
        requestAnimationFrame(() => document.getElementById(`tab-${next.id}`)?.focus());
      }}
    >
      {visible.map((tab) => {
        const selected = tab.id === active;
        return (
          <button
            key={tab.id}
            id={`tab-${tab.id}`}
            role="tab"
            type="button"
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.id)}
            className={cx(
              '-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm font-medium whitespace-nowrap transition-colors',
              selected ? 'border-accent text-fg' : 'border-transparent text-muted hover:text-fg',
            )}
          >
            {tab.label}
            {tab.count !== undefined && tab.count !== null && (
              <span className={cx('rounded-full px-1.5 text-xs', selected ? 'bg-accent-soft text-accent' : 'bg-neutral-soft text-muted')}>
                {tab.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------------------------

export function TableWrap({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx('overflow-x-auto rounded-lg border border-line bg-surface', className)}>{children}</div>;
}

export interface SortState {
  sort: string | null;
  dir: 'asc' | 'desc';
}

export function SortHeader({ field, label, state, onSort, className }: {
  field: string;
  label: ReactNode;
  state: SortState;
  onSort: (field: string) => void;
  className?: string;
}) {
  const active = state.sort === field;
  return (
    <th className={className} aria-sort={active ? (state.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="inline-flex items-center gap-1 uppercase hover:text-fg" onClick={() => onSort(field)}>
        {label}
        {active ? (
          state.dir === 'asc' ? <ChevronUp className="size-3.5" aria-hidden /> : <ChevronDown className="size-3.5" aria-hidden />
        ) : (
          <ChevronDown className="size-3.5 opacity-25" aria-hidden />
        )}
      </button>
    </th>
  );
}

export function Pagination({ page, pageSize, totalCount, onPage }: { page: number; pageSize: number; totalCount: number; onPage: (page: number) => void }) {
  if (totalCount === 0 || pageSize === 0) return null;
  const pages = Math.max(1, Math.ceil(totalCount / pageSize));
  const from = (page - 1) * pageSize + 1;
  const to = Math.min(totalCount, page * pageSize);
  return (
    <nav className="mt-3 flex items-center justify-between gap-2 text-sm text-muted" aria-label="Pagination">
      <span>
        {from.toLocaleString()}–{to.toLocaleString()} of {totalCount.toLocaleString()}
      </span>
      <div className="flex items-center gap-1">
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)} icon={<ChevronLeft className="size-4" aria-hidden />}>
          Previous
        </Button>
        <span className="px-2">
          Page {page} of {pages}
        </span>
        <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          Next
          <ChevronRight className="size-4" aria-hidden />
        </Button>
      </div>
    </nav>
  );
}

// ---------------------------------------------------------------------------------------------
// Data display
// ---------------------------------------------------------------------------------------------

export function KeyValueList({ items, className }: { items: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={cx('grid grid-cols-1 gap-x-6 gap-y-2.5 sm:grid-cols-[minmax(9rem,max-content)_1fr]', className)}>
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-xs font-medium text-muted sm:pt-0.5">{k}</dt>
          <dd className="min-w-0 text-sm break-words text-fg">{v ?? '—'}</dd>
        </div>
      ))}
    </dl>
  );
}

export function StatTile({ label, value, tone, hint, icon, to }: {
  label: string;
  value: ReactNode;
  tone?: Tone;
  hint?: ReactNode;
  icon?: ReactNode;
  to?: ReactNode;
}) {
  const valueColor = tone
    ? { ok: 'text-ok', warn: 'text-warn', danger: 'text-danger', info: 'text-info', neutral: 'text-fg', accent: 'text-accent' }[tone]
    : 'text-fg';
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-line bg-surface px-4 py-3 shadow-xs">
      <div className="flex items-center justify-between gap-2 text-xs font-medium text-muted">
        <span>{label}</span>
        {icon && <span className="text-subtle">{icon}</span>}
      </div>
      <div className={cx('text-2xl font-semibold tabular-nums', valueColor)}>{value}</div>
      {hint && <div className="text-xs text-muted">{hint}</div>}
      {to}
    </div>
  );
}

export function ProgressBar({ value, tone = 'accent', label }: { value: number | null | undefined; tone?: Tone; label?: string }) {
  const pct = Math.max(0, Math.min(100, value ?? 0));
  const color = { ok: 'bg-ok', warn: 'bg-warn', danger: 'bg-danger', info: 'bg-info', neutral: 'bg-subtle', accent: 'bg-accent' }[tone];
  return (
    <div
      role="progressbar"
      aria-label={label ?? 'Progress'}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value ?? undefined}
      className="h-2 w-full overflow-hidden rounded-full bg-neutral-soft"
    >
      <div className={cx('h-full rounded-full transition-[width]', color)} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cx('rounded bg-neutral-soft px-1.5 py-0.5 font-mono text-xs break-all text-fg', className)}>{children}</code>;
}

// ---------------------------------------------------------------------------------------------
// Links styled as buttons (avoids nesting <button> inside <a>)
// ---------------------------------------------------------------------------------------------

export function buttonClasses(variant: ButtonVariant = 'secondary', size: ButtonSize = 'md'): string {
  return cx(
    'inline-flex items-center justify-center gap-1.5 rounded-md font-medium whitespace-nowrap transition-colors',
    size === 'sm' ? 'h-7 px-2.5 text-xs' : 'h-8.5 px-3.5 text-sm',
    variantClasses[variant],
  );
}
