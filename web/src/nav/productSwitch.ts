import { PATCH_VIEW_TAB, type EasyPatchTarget } from "../pages/patching/patchText";

/** Device pages that are not a device. */
const DEVICE_PAGES = new Set(["add", "approvals"]);

/**
 * What EasyPatch shows of the page someone is on (integration plan, 6.2), for the product switch to keep their place:
 * a device opens its endpoint, on the tab matching its Patches view; an organization or site opens the
 * organization; a patch job or an update opens it; Patching's device and job lists open EasyPatch's; anything else,
 * including Patching's overview and update list, its home.
 */
export function switchTarget(pathname: string, search: string): EasyPatchTarget {
  const q = new URLSearchParams(search);
  const [section, id, ...rest] = pathname.split("/").filter(Boolean);
  switch (section) {
    case "devices": {
      if (!id || DEVICE_PAGES.has(id)) return { list: "endpoints" };
      const t: EasyPatchTarget = { device: id };
      if (rest.length === 0 && q.get("tab") === "patches") t.tab = PATCH_VIEW_TAB[q.get("patches") ?? "available"];
      return t;
    }
    case "organizations":
      return id ? { organization: id } : {};
    case "sites":
      return id ? { site: id } : {};
    case "patching": {
      if (id === "updates" && rest[0]) return { update: rest[0] };
      const job = q.get("job");
      if (job) return { job };
      const tab = q.get("tab");
      return tab === "jobs" ? { list: "jobs" } : tab === "devices" ? { list: "endpoints" } : {};
    }
    default:
      return {};
  }
}
