import { Link, useLocation } from "react-router";
import { useApi } from "../api/hooks";
import type { Device, Organization, ProductSwitch as SwitchState, Site } from "../api/types";
import { formatDateTime, formatRelative } from "../lib/format";
import { easyPatchHref } from "../pages/patching/patchText";
import { switchTarget } from "./productSwitch";

const segment = "flex-1 rounded px-2 py-1 text-center text-sm transition-colors";

/**
 * EasyRMM | EasyPatch, under the logo (integration plan, 6.1). EasyPatch opens on the page of what this page shows,
 * in the same tab, through EasyRMM's /go/to-easypatch; Back returns. Shown to people with EasyPatch access by
 * organization-wide roles, once EasyPatch is set up. When EasyPatch was not answering, a dot says so; the link still
 * works, in case it has recovered.
 */
export function ProductSwitch() {
  const location = useLocation();
  const state = useApi<SwitchState>("/patching/switch", undefined, { staleTime: 60_000, refetchInterval: 5 * 60_000 });
  const shown = state.data?.show === true;
  const target = switchTarget(location.pathname, location.search);
  // Names come from the page's own query, which has the same key.
  const device = useApi<Device>(shown && target.device ? `/devices/${target.device}` : null);
  const org = useApi<Organization>(shown && target.organization ? `/organizations/${target.organization}` : null);
  const site = useApi<Site>(shown && target.site ? `/sites/${target.site}` : null);
  if (!shown) return null;

  const name = target.device ? device.data?.name : target.organization ? org.data?.name : target.site ? site.data?.organizationName : undefined;
  let label = "Open EasyPatch";
  if (name) label = `Open ${name} in EasyPatch`;
  else if (target.device) label = "Open this device in EasyPatch";
  else if (target.job) label = "Open this job in EasyPatch";
  const failing = state.data?.answering === false;
  const warning = failing
    ? `EasyPatch was not answering ${state.data?.failingSince ? formatRelative(state.data.failingSince) : "when last asked"}; it may have recovered.`
    : "";

  return (
    <nav aria-label="Products" className="px-3 pb-3">
      <div className="flex gap-0.5 rounded-md bg-white/5 p-0.5 ring-1 ring-white/10">
        <Link to="/" aria-current="true" className={`${segment} bg-sidebar-active font-medium text-white`}>
          EasyRMM
        </Link>
        <a
          href={easyPatchHref(target)}
          aria-label={warning ? `${label}. ${warning}` : label}
          title={warning ? `${label}\n${warning}${state.data?.failingSince ? ` (${formatDateTime(state.data.failingSince)})` : ""}` : label}
          className={`${segment} relative text-sidebar-fg/75 hover:bg-sidebar-active/60 hover:text-white`}
        >
          EasyPatch
          {failing && <span className="absolute top-1 right-1 size-1.5 rounded-full bg-warn" aria-hidden />}
        </a>
      </div>
    </nav>
  );
}
