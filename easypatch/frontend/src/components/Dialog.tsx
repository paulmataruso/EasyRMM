import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { X } from 'lucide-react';
import { Button, cx, InlineError, Input } from './ui';

/** Modal built on the native <dialog> element (focus trapping, Escape and top-layer come from the browser). */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = 'md',
  dismissible = true,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  /** When false, Escape and the close button are disabled (e.g. while showing one-time secrets until acknowledged). */
  dismissible?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const opener = useRef<Element | null>(null);
  const titleId = useId();
  const descId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      opener.current = document.activeElement;
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
      if (opener.current instanceof HTMLElement) opener.current.focus();
    }
  }, [open]);

  useEffect(() => {
    const dialog = ref.current;
    return () => {
      if (dialog?.open) dialog.close();
    };
  }, []);

  const widths = { sm: 'max-w-md', md: 'max-w-xl', lg: 'max-w-3xl', xl: 'max-w-5xl' }[size];

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      aria-describedby={description ? descId : undefined}
      onCancel={(e) => {
        e.preventDefault();
        if (dismissible) onClose();
      }}
      onMouseDown={(e) => {
        // Click on the backdrop (the dialog element itself, outside the panel) closes.
        if (dismissible && e.target === ref.current) onClose();
      }}
      className={cx(
        'm-auto w-[calc(100%-2rem)] rounded-xl border border-line bg-surface p-0 text-fg shadow-2xl',
        'max-h-[calc(100dvh-2rem)]',
        widths,
      )}
    >
      {open && (
        <div className="flex max-h-[calc(100dvh-2rem)] flex-col">
          <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-3.5">
            <div className="min-w-0">
              <h2 id={titleId} className="text-base font-semibold">
                {title}
              </h2>
              {description && (
                <p id={descId} className="mt-0.5 text-sm text-muted">
                  {description}
                </p>
              )}
            </div>
            {dismissible && (
              <button type="button" onClick={onClose} aria-label="Close" className="rounded-md p-1 text-muted hover:bg-hover hover:text-fg">
                <X className="size-4" aria-hidden />
              </button>
            )}
          </header>
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
          {footer && <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-line px-5 py-3">{footer}</footer>}
        </div>
      )}
    </dialog>
  );
}

/** Confirmation dialog. With `confirmText`, the user must type it (used for destructive actions). */
export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  children,
  confirmLabel = 'Confirm',
  tone = 'primary',
  loading = false,
  error,
  confirmText,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: ReactNode;
  children?: ReactNode;
  confirmLabel?: string;
  tone?: 'primary' | 'danger';
  loading?: boolean;
  error?: unknown;
  confirmText?: string;
}) {
  const [typed, setTyped] = useState('');
  const inputId = useId();
  useEffect(() => {
    if (open) setTyped('');
  }, [open]);
  const blocked = confirmText !== undefined && typed.trim() !== confirmText;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!blocked && !loading) onConfirm();
  }

  return (
    <Dialog open={open} onClose={onClose} title={title} size="sm">
      <form onSubmit={submit} className="flex flex-col gap-3">
        {children && <div className="text-sm text-fg">{children}</div>}
        {confirmText !== undefined && (
          <div className="flex flex-col gap-1">
            <label htmlFor={inputId} className="text-xs text-muted">
              Type <strong className="font-mono text-fg">{confirmText}</strong> to confirm
            </label>
            <Input id={inputId} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" autoFocus />
          </div>
        )}
        <InlineError error={error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button type="submit" variant={tone === 'danger' ? 'danger' : 'primary'} loading={loading} disabled={blocked}>
            {confirmLabel}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
