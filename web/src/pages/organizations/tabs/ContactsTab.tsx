import type { Organization, Site } from "../../../api/types";
import { useApi, useList } from "../../../api/hooks";
import { useUrlState } from "../../../lib/urlState";
import { ContactsPanel } from "../Contacts";
import type { LevelTabProps } from "../levelTabs";

/** The organization's contacts, and those of the sites the viewer may manage (ADR-0072). */
export function ContactsTab({ id }: LevelTabProps) {
  const url = useUrlState();
  const org = useApi<Organization>(`/organizations/${id}`);
  const sites = useList<Site>(`/organizations/${id}/sites`);
  if (!org.data) return null;
  const o = org.data;
  return (
    <ContactsPanel
      organizationId={o.id}
      levels={[
        ...(o.canManageDocumentation
          ? [{ id: null, name: "The organization" }]
          : []),
        ...sites.items
          .filter((s) => s.canManageDocumentation)
          .map((s) => ({ id: s.id, name: s.name })),
      ]}
      after={url.get("after")}
      onPage={(after) => url.set({ after })}
    />
  );
}
