import { Navigate } from "react-router";
import { useAuth } from "../../auth/AuthContext";
import { PageHeader, Tabs } from "../../components/ui";
import { useUrlState } from "../../lib/urlState";
import { settingsParts } from "../../nav/SectionNav";
import { AgentUpdatesTab } from "./AgentUpdatesTab";
import { AuditForwardingTab } from "./AuditForwardingTab";
import { AuditTab } from "./AuditTab";
import { EasyPatchTab } from "./EasyPatchTab";
import { NotificationsTab } from "./NotificationsTab";
import { PatchingTab } from "./PatchingTab";
import { RemoteAccessTab } from "./RemoteAccessTab";
import { SingleSignOnTab } from "./SingleSignOnTab";
import { UsersTab } from "./UsersTab";

const SUBTITLES: Record<string, string> = {
  users: "People who can sign in to EasyRMM, and the roles that decide what they can do where.",
  audit: "Everything people, agents and the platform did, in a tamper-evident log.",
  remote: "The MeshCentral service behind remote desktop, terminal and files.",
  "agent-updates": "Keep every EasyRMM agent on the build this server ships, a few devices at a time.",
  notifications: "The mail server EasyRMM sends invitations, password resets and the patching engine's email through, and how much mail it sends.",
  forwarding: "A copy of every audit record, sent as it is written to your syslog server or SIEM.",
  easypatch: "The patching engine in this deployment, the organizations where EasyRMM installs its agent automatically, and devices it cannot match.",
  patching:
    "The default patch policy and tags, each organization's monthly report schedule, and the patching engine's own settings, OS lifecycle dates, agent packages, alert rules, notifications and audit log.",
  sso: "Identity providers people can sign in through with OpenID Connect, instead of their EasyRMM password.",
};

/**
 * Settings' parts. On wide screens the sidebar lists them (ADR-0021); on narrow ones the sidebar is out of sight, so
 * the page shows them as tabs.
 */
export function SettingsPage() {
  const url = useUrlState();
  const { can } = useAuth();
  const parts = settingsParts(can);
  const first = parts[0];
  if (!first) return <Navigate to="/" replace />;
  const requested = url.get("tab");
  const part = parts.find((p) => p.id === requested) ?? first;

  return (
    <>
      <PageHeader breadcrumb="Settings" title={part.label} subtitle={SUBTITLES[part.id]} />
      <Tabs
        className="lg:hidden"
        active={part.id}
        onChange={(t) => url.set({ tab: t === first.id ? null : t, q: null, organizationId: null, action: null, actorId: null, invite: null, after: null, view: null, tag: null, area: null, from: null, to: null, page: null })}
        tabs={parts.map((p) => ({ id: p.id, label: p.label }))}
      />
      {part.id === "users" && <UsersTab />}
      {part.id === "audit" && <AuditTab />}
      {part.id === "remote" && <RemoteAccessTab />}
      {part.id === "agent-updates" && <AgentUpdatesTab />}
      {part.id === "notifications" && <NotificationsTab />}
      {part.id === "forwarding" && <AuditForwardingTab />}
      {part.id === "easypatch" && <EasyPatchTab />}
      {part.id === "patching" && <PatchingTab />}
      {part.id === "sso" && <SingleSignOnTab />}
    </>
  );
}
