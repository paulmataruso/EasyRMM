// The parts an alert's card is made of, shared by EasyRMM's alerts (AlertDetail.tsx) and patching alerts
// (patching/PatchAlertCard.tsx).
import { useId, type ReactNode } from "react";
import { CodeBlock } from "../../components/Copy";
import { formatDateTime, formatRelative } from "../../lib/format";

/** A link inside a card. */
export const linkClass = "font-medium break-words text-accent hover:underline";

/** A value the card cannot show, in words. */
export const muted = (text: string) => <span className="text-muted">{text}</span>;

/** One section of a card, labelled by its heading. */
export function Section({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="flex min-w-0 flex-col gap-2">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <h3 id={id} className="text-sm font-semibold">
          {title}
        </h3>
        {actions}
      </div>
      {children}
    </section>
  );
}

/** A moment, with how long ago. */
export function When({ at }: { at: string }) {
  return (
    <>
      <time dateTime={at}>{formatDateTime(at)}</time> <span className="text-muted">({formatRelative(at)})</span>
    </>
  );
}

/** The record as the API returns it, folded, to copy. */
export function RawDetails({ value }: { value: unknown }) {
  return (
    <details className="rounded-lg border border-line">
      <summary className="cursor-pointer px-3 py-2 text-sm font-medium select-none">Raw details (JSON)</summary>
      <div className="border-t border-line p-3">
        <CodeBlock code={JSON.stringify(value, null, 2)} />
      </div>
    </details>
  );
}
