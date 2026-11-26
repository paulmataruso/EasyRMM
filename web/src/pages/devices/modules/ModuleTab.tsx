import { Link } from "react-router";
import { Loader2 } from "lucide-react";
import type { ReactNode } from "react";
import type { Device } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { Alert, EmptyState } from "../../../components/ui";
import { formatDateTime, formatRelative } from "../../../lib/format";
import { Loading } from "./skeletons";

/**
 * The frame every module's tab uses (ADR-0073, section 7): the module's name, when what is shown was read and, when the
 * module cannot answer, why. There is no read button: a tab shows its last result when it opens, reads again by itself
 * when that is old and keeps it fresh while it stays open. A module supplies its panels as children and, for the
 * time before the first result, a skeleton of its real layout.
 */
export function ModuleTab({
  name,
  asOf,
  refreshing = false,
  loading = false,
  skeleton,
  offline = false,
  unavailable,
  children,
}: {
  name: string;
  /** When the data shown was read; null before the first result. */
  asOf: string | null;
  /** A new read is on its way: what is shown is the last result. */
  refreshing?: boolean;
  /** No result yet, stored or new: the skeleton is shown in place of the panels. */
  loading?: boolean;
  skeleton?: ReactNode;
  /** The computer is not checking in; what is shown is its last result. */
  offline?: boolean;
  /** Why the module cannot be read now (an offline device, a missing Windows feature). */
  unavailable?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <section aria-label={name} className="flex flex-col gap-4">
      <header className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <h2 className="text-base font-semibold text-fg">{name}</h2>
        <span className="text-xs text-muted">
          {asOf ? (
            <>
              As of <span title={formatDateTime(asOf)}>{formatRelative(asOf)}</span>
            </>
          ) : loading ? (
            "Reading…"
          ) : (
            "Not read yet"
          )}
        </span>
        {refreshing && !loading && (
          <span className="inline-flex items-center gap-1 text-xs text-muted" role="status">
            <Loader2 className="size-3 animate-spin" aria-hidden /> Updating
          </span>
        )}
      </header>
      {offline && <Alert tone="warn">This computer is not checking in. What is shown is its last result, from the time above.</Alert>}
      {unavailable && <Alert tone="warn">{unavailable}</Alert>}
      {loading && skeleton ? <Loading name={name}>{skeleton}</Loading> : children}
    </section>
  );
}

/**
 * What a module's URL shows while the module is off for the device's site. Someone who may change the toggle gets a
 * link to it (the site's card, where an override can be set; otherwise the organization's).
 */
export function ModuleOff({ device, label }: { device: Device; label: string }) {
  const { canAt } = useAuth();
  const scope = { organizationId: device.organizationId, siteId: device.siteId };
  const toggle = canAt("site.manage", scope)
    ? `/sites/${device.siteId}?tab=windows-modules`
    : canAt("org.manage", { organizationId: device.organizationId })
      ? `/organizations/${device.organizationId}?tab=windows-modules`
      : null;
  return (
    <EmptyState title={`${label} is off for this site`}>
      <p>
        A module that is off sends no job to this computer and raises no alert.
        {toggle ? (
          <>
            {" "}
            <Link to={toggle} className="text-accent underline">
              Open the Windows modules settings
            </Link>{" "}
            to turn it on.
          </>
        ) : (
          " An administrator of the site or the organization can turn it on."
        )}
      </p>
    </EmptyState>
  );
}
