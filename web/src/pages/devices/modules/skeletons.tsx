import type { ReactNode } from "react";
import { Card, Skeleton, TableWrap } from "../../../components/ui";

// What a module's tab shows while its first result loads: the page's own layout with bars where the data goes, so the
// page does not jump when the result arrives (ADR-0073 section 5, as amended). Never an empty state.

const WIDTHS = ["w-24", "w-40", "w-32", "w-48", "w-28"];

/** A card of label and value rows, as a KeyValueList lays them out. */
export function SkeletonKeyValue({ title, rows = 5 }: { title?: string; rows?: number }) {
  return (
    <Card title={title}>
      <div className="flex flex-col gap-3">
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className="flex items-center justify-between gap-6">
            <Skeleton className="w-36" />
            <Skeleton className={WIDTHS[i % WIDTHS.length]} />
          </div>
        ))}
      </div>
    </Card>
  );
}

/** A table's bars without a card around them, for a card that already exists (a list inside a panel). */
export function SkeletonGrid({ columns = 3, rows = 4 }: { columns?: number; rows?: number }) {
  return (
    <div role="status" aria-busy="true" aria-label="Loading the list">
      <TableWrap>
        <table className="table-base" aria-hidden>
          <thead>
            <tr>
              {Array.from({ length: columns }, (_, c) => (
                <th key={c}>
                  <Skeleton className="h-3 w-16" />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: rows }, (_, r) => (
              <tr key={r}>
                {Array.from({ length: columns }, (_, c) => (
                  <td key={c}>
                    <Skeleton className={WIDTHS[(r + c) % WIDTHS.length]} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </div>
  );
}

/** A card holding a table: a header row and body rows. */
export function SkeletonTable({ title, columns = 3, rows = 4, toolbar = false }: { title?: string; columns?: number; rows?: number; toolbar?: boolean }) {
  return (
    <Card title={title} padded={false}>
      {toolbar && (
        <div className="flex gap-2 border-b border-line px-4 py-3">
          <Skeleton className="h-8 w-56" />
          <Skeleton className="h-8 w-24" />
        </div>
      )}
      <TableWrap className="rounded-none border-0">
        <table className="table-base" aria-hidden>
          <thead>
            <tr>
              {Array.from({ length: columns }, (_, c) => (
                <th key={c}>
                  <Skeleton className="h-3 w-16" />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: rows }, (_, r) => (
              <tr key={r}>
                {Array.from({ length: columns }, (_, c) => (
                  <td key={c}>
                    <Skeleton className={WIDTHS[(r + c) % WIDTHS.length]} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Card>
  );
}

/** A row of stat tiles. */
export function SkeletonTiles({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="flex flex-col gap-2 rounded-lg border border-line bg-surface p-3 shadow-xs">
          <Skeleton className="h-3 w-20" />
          <Skeleton className="h-6 w-12" />
        </div>
      ))}
    </div>
  );
}

/** A segmented control's bar. */
export function SkeletonSegmented() {
  return <Skeleton className="h-8.5 w-64 rounded-md" />;
}

/** A card with a line of text and a bar or two. */
export function SkeletonCard({ title, lines = 2 }: { title?: string; lines?: number }) {
  return (
    <Card title={title}>
      <div className="flex flex-col gap-2">
        {Array.from({ length: lines }, (_, i) => (
          <Skeleton key={i} className={i === lines - 1 ? "w-2/3" : "w-full"} />
        ))}
      </div>
    </Card>
  );
}

/** The skeleton's frame: announced as loading to a screen reader. */
export function Loading({ name, children }: { name: string; children: ReactNode }) {
  return (
    <div role="status" aria-busy="true" aria-label={`Loading ${name}`} className="flex flex-col gap-4">
      {children}
    </div>
  );
}
