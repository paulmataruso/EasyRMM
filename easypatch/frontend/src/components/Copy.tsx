import { useState, type ReactNode } from 'react';
import { Check, Copy, Download, ShieldAlert } from 'lucide-react';
import { Button, cx } from './ui';

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for non-secure contexts.
    try {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.className = 'fixed -left-[9999px]';
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(area);
      return ok;
    } catch {
      return false;
    }
  }
}

export function CopyButton({ text, label = 'Copy', size = 'sm', className }: { text: string; label?: string; size?: 'sm' | 'md'; className?: string }) {
  const [copied, setCopied] = useState<boolean | null>(null);
  return (
    <Button
      size={size}
      className={className}
      onClick={async () => {
        const ok = await copyText(text);
        setCopied(ok);
        window.setTimeout(() => setCopied(null), 1800);
      }}
      icon={copied ? <Check className="size-3.5 text-ok" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      aria-live="polite"
    >
      {copied === true ? 'Copied' : copied === false ? 'Copy failed' : label}
    </Button>
  );
}

export function downloadText(fileName: string, text: string, mime = 'text/plain'): void {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function DownloadButton({ fileName, text, label = 'Download', mime }: { fileName: string; text: string; label?: string; mime?: string }) {
  return (
    <Button size="sm" onClick={() => downloadText(fileName, text, mime)} icon={<Download className="size-3.5" aria-hidden />}>
      {label}
    </Button>
  );
}

/** A copyable code block. */
export function CodeBlock({ code, className, wrap = true, maxHeight }: { code: string; className?: string; wrap?: boolean; maxHeight?: string }) {
  return (
    <div className={cx('group relative rounded-md border border-line bg-raised', className)}>
      <pre
        className={cx('overflow-auto px-3 py-2.5 pr-20 font-mono text-xs leading-relaxed text-fg', wrap ? 'break-all whitespace-pre-wrap' : 'whitespace-pre')}
        style={maxHeight ? { maxHeight } : undefined}
      >
        {code}
      </pre>
      <div className="absolute top-1.5 right-1.5">
        <CopyButton text={code} />
      </div>
    </div>
  );
}

/** Banner shown above one-time secrets (enrollment tokens, recovery codes). */
export function OneTimeNotice({ children }: { children?: ReactNode }) {
  return (
    <div className="flex gap-2.5 rounded-md border border-warn/40 bg-warn-soft px-3 py-2.5 text-sm" role="note">
      <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
      <div>
        <p className="font-medium text-fg">Copy this now. You will not see it again.</p>
        <p className="text-fg/85">
          {children ?? 'EasyPatch stores only a hash. If it is lost, create a new one and revoke the old one.'}
        </p>
      </div>
    </div>
  );
}
