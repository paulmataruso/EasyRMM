import { useId } from "react";
import { api, ApiError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { EasyPatchOrganizationLink } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Card, ErrorState, InlineError, Spinner } from "../../components/ui";
import { plural } from "../../lib/format";

/**
 * An organization's page → Patching: whether EasyRMM installs and enrolls the EasyPatch agent on the organization's
 * devices that have none (ADR-0031). It was a row of Settings → Patching engine; it is per organization (ADR-0072).
 */
export function AgentInstallCard({ organizationId }: { organizationId: string }) {
  const toast = useToast();
  const id = useId();
  const path = `/patching/organizations/${organizationId}/agent-install`;
  const link = useApi<EasyPatchOrganizationLink>(path, undefined, { refetchInterval: 60_000 });
  const set = useApiMutation((on: boolean) => api.patch(`/settings/easypatch/organizations/${organizationId}`, { autoInstall: on }), {
    invalidate: [path, "/patching", "/audit"],
    onSuccess: (_, on) =>
      toast.success(
        on
          ? "EasyRMM installs the EasyPatch agent on devices in this organization that have none, within a few minutes."
          : "EasyRMM no longer installs the EasyPatch agent in this organization by itself.",
      ),
  });
  return (
    <Card title="EasyPatch agent">
      {link.isPending ? (
        <Spinner />
      ) : link.isError ? (
        link.error instanceof ApiError && link.error.status === 404 ? (
          <p className="text-sm text-muted">The organization is being created in the patching engine. This shows in a few minutes.</p>
        ) : (
          <ErrorState error={link.error} onRetry={() => void link.refetch()} />
        )
      ) : (
        <div className="flex flex-col gap-3 text-sm">
          <label htmlFor={id} className="flex items-start gap-2.5">
            <input
              id={id}
              type="checkbox"
              className="mt-0.5 size-4 accent-accent"
              checked={link.data.autoInstall}
              disabled={set.isPending}
              onChange={(e) => set.mutate(e.target.checked)}
            />
            <span>
              Install automatically
              <span className="block text-xs text-muted">
                EasyRMM&apos;s agent installs and enrolls the EasyPatch agent on this organization&apos;s Windows and Linux devices that have none. To keep one
                device unpatched, stop patching on its Patches tab.
              </span>
            </span>
          </label>
          <p className="text-muted">
            {plural(link.data.devices.linked, "device")} patched
            {link.data.devices.unlinked > 0 && <span className="text-warn">, {link.data.devices.unlinked.toLocaleString()} not linked</span>}
            {link.data.devices.pending > 0 && <>, {link.data.devices.pending.toLocaleString()} being checked</>}.
          </p>
          <InlineError error={set.error} />
        </div>
      )}
    </Card>
  );
}
