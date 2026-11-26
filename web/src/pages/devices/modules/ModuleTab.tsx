import { Link } from "react-router";
import { RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import type { Device } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { Alert, Button, EmptyState } from "../../../components/ui";
import { formatDateTime, formatRelative } from "../../../lib/format";

/**
 * The frame every module's tab uses (ADR-0073, section 7): the module's name, when what is shown was read, a refresh
 * button and, when the module cannot answer, why. A module supplies its panels as children.
 */
export function ModuleTab({
  name,
  asOf,
  onRefresh,
  refreshing = false,
  canRefresh = true,
  unavailable,
  children,
}: {
  name: string;
  /** When the data shown was read; null before the first read. */
  asOf: string | null;
  onRefresh: () => void;
  refreshing?: boolean;
  canRefresh?: boolean;
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
              Read <span title={formatDateTime(asOf)}>{formatRelative(asOf)}</span>
            </>
          ) : (
            "Not read yet"
          )}
        </span>
        {canRefresh && (
          <Button
            size="sm"
            icon={<RefreshCw className="size-3.5" aria-hidden />}
            onClick={onRefresh}
            loading={refreshing}
            className="ml-auto"
          >
            {asOf ? "Refresh" : "Read now"}
          </Button>
        )}
      </header>
      {unavailable && <Alert tone="warn">{unavailable}</Alert>}
      {children}
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
