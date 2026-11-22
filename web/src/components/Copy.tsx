import { useEffect, useState, type ReactNode } from "react";
import { Check, Copy, Download, ShieldAlert } from "lucide-react";
import { Button, cx } from "./ui";

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for non-secure contexts.
    try {
      const area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.className = "fixed -left-[9999px]";
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(area);
      return ok;
    } catch {
      return false;
    }
  }
}

export function CopyButton({ text, label = "Copy", size = "sm", className }: { text: string; label?: string; size?: "sm" | "md"; className?: string }) {
  const [copied, setCopied] = useState<boolean | null>(null);
  // The label goes back after a moment, on a timer the button clears when it unmounts.
  useEffect(() => {
    if (copied === null) return;
    const timer = window.setTimeout(() => setCopied(null), 1800);
    return () => window.clearTimeout(timer);
  }, [copied]);
  return (
    <Button
      size={size}
      className={className}
      onClick={async () => setCopied(await copyText(text))}
      icon={copied ? <Check className="size-3.5 text-ok" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      aria-live="polite"
    >
      {copied === true ? "Copied" : copied === false ? "Copy failed" : label}
    </Button>
  );
}

export function downloadText(fileName: string, text: string): void {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function DownloadButton({ fileName, text, label = "Download" }: { fileName: string; text: string; label?: string }) {
  return (
    <Button size="sm" onClick={() => downloadText(fileName, text)} icon={<Download className="size-3.5" aria-hidden />}>
      {label}
    </Button>
  );
}

/** A copyable code block. */
export function CodeBlock({ code, className }: { code: string; className?: string }) {
  return (
    <div className={cx("relative rounded-md border border-line bg-raised", className)}>
      <pre className="overflow-auto px-3 py-2.5 pr-20 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap text-fg">{code}</pre>
      <div className="absolute top-1.5 right-1.5">
        <CopyButton text={code} />
      </div>
    </div>
  );
}

/** Banner shown above one-time secrets (recovery codes, password links). */
export function OneTimeNotice({ title = "Copy this now. You will not see it again.", children }: { title?: string; children?: ReactNode }) {
  return (
    <div className="flex gap-2.5 rounded-md border border-warn/40 bg-warn-soft px-3 py-2.5 text-sm" role="note">
      <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
      <div>
        <p className="font-medium text-fg">{title}</p>
        {children && <p className="text-fg/85">{children}</p>}
      </div>
    </div>
  );
}
