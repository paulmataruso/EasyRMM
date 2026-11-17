import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { CheckCircle2, Info, OctagonAlert, X } from 'lucide-react';
import { cx } from './ui';

type ToastTone = 'success' | 'error' | 'info';

interface ToastItem {
  id: number;
  tone: ToastTone;
  message: ReactNode;
}

interface ToastApi {
  success: (message: ReactNode) => void;
  error: (message: ReactNode) => void;
  info: (message: ReactNode) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => setItems((list) => list.filter((t) => t.id !== id)), []);

  const push = useCallback(
    (tone: ToastTone, message: ReactNode) => {
      const id = nextId.current++;
      setItems((list) => [...list.slice(-4), { id, tone, message }]);
      window.setTimeout(() => dismiss(id), tone === 'error' ? 9000 : 5000);
    },
    [dismiss],
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (m) => push('success', m),
      error: (m) => push('error', m),
      info: (m) => push('info', m),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2" aria-live="polite" aria-relevant="additions">
        {items.map((t) => {
          const Icon = t.tone === 'success' ? CheckCircle2 : t.tone === 'error' ? OctagonAlert : Info;
          return (
            <div
              key={t.id}
              role={t.tone === 'error' ? 'alert' : 'status'}
              className="toast-enter pointer-events-auto flex items-start gap-2.5 rounded-lg border border-line bg-surface px-3.5 py-3 text-sm text-fg shadow-lg"
            >
              <Icon
                className={cx('mt-0.5 size-4 shrink-0', t.tone === 'success' ? 'text-ok' : t.tone === 'error' ? 'text-danger' : 'text-info')}
                aria-hidden
              />
              <div className="min-w-0 flex-1 break-words">{t.message}</div>
              <button type="button" onClick={() => dismiss(t.id)} aria-label="Dismiss" className="rounded p-0.5 text-muted hover:text-fg">
                <X className="size-3.5" aria-hidden />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>');
  return ctx;
}
