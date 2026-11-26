import { Navigate } from "react-router";
import { useAuth } from "../../auth/AuthContext";
import { PageHeader, Tabs } from "../../components/ui";
import { useUrlState } from "../../lib/urlState";
import { settingsParts } from "../../nav/SectionNav";
import { AgentFilesTab } from "./AgentFilesTab";
import { AlertPoliciesSettings } from "./AlertPoliciesSettings";
import { CertificatesTab } from "./CertificatesTab";
import { GeneralTab } from "./GeneralTab";
import { KeystoreTab } from "./KeystoreTab";
import { AgentUpdatesTab } from "./AgentUpdatesTab";
import { AuditForwardingTab } from "./AuditForwardingTab";
import { AuditTab } from "./AuditTab";
import { NotificationsTab } from "./NotificationsTab";
import { ChannelsPanel } from "../notifications/ChannelsPanel";
import { PlatformControls } from "../notifications/PlatformControls";
import { RulesPanel } from "../notifications/RulesPanel";
import { WindowsPanel } from "../notifications/WindowsPanel";
import { PatchingTab } from "./PatchingTab";
import { RemoteAccessTab } from "./RemoteAccessTab";
import { SingleSignOnTab } from "./SingleSignOnTab";
import { UsersTab } from "./UsersTab";

const SUBTITLES: Record<string, string> = {
  users: "People who can sign in to EasyRMM, and the roles that decide what they can do where.",
  audit: "Everything people, agents and the platform did, in a tamper-evident log.",
  remote: "The MeshCentral service behind remote desktop, terminal and files.",
  "agent-updates": "Keep every EasyRMM agent on the build this server ships, a few devices at a time.",
  "agent-files": "Every file this server hands out or the agents install, with MD5 and SHA-256, kept current.",
  notifications: "The mail server EasyRMM sends invitations, password resets and the patching engine's email through, how much mail it sends, and the platform's notification channels, shared with organizations from here.",
  forwarding: "A copy of every audit record, sent as it is written to your syslog server or SIEM.",
  "alert-policies": "Shared alert policies: what raises an alert on every device in every organization. An organization's or a site's own are on its page.",
  patching:
    "The patching engine, the default patch policy and tags every organization starts from, and the engine's own settings, OS lifecycle dates, agent packages, alert rules, notifications and audit log. An organization's or a site's own patching settings are on its page.",
  certificates: "The certificates for this server's names: where they come from, when they renew, and what to do when one is failing.",
  keystore: "The service that holds the key protecting disk recovery keys: its state, its key versions and the alerts about it. An organization's own reads and switches are on its page.",
  general: "App-wide defaults, set by super administrators. For now: how long a new Quick Assist link lasts.",
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
  // Moved places (ADR-0072): the engine is a view of Patching; report schedules are each organization's own.
  if (requested === "easypatch") return <Navigate to="/settings?tab=patching&view=engine" replace />;
  if (requested === "patching" && url.get("view") === "reports") {
    const org = url.get("organizationId");
    return <Navigate to={org ? `/organizations/${org}?tab=patching` : "/organizations"} replace />;
  }
  // The organization's own people are its People tab (ADR-0072); the old filtered link goes there.
  const peopleOf = url.get("organizationId");
  if (requested === "users" && peopleOf) return <Navigate to={`/organizations/${encodeURIComponent(peopleOf)}?tab=people`} replace />;
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
      {part.id === "agent-files" && <AgentFilesTab />}
      {part.id === "notifications" && (
        <>
          <NotificationsTab />
          <div className="mt-5">
            <ChannelsPanel organizationId={null} />
          </div>
          <div className="mt-5 flex flex-col gap-5">
            <RulesPanel organizationId={null} />
            <WindowsPanel organizationId={null} />
            <PlatformControls />
          </div>
        </>
      )}
      {part.id === "forwarding" && <AuditForwardingTab />}
      {part.id === "alert-policies" && <AlertPoliciesSettings />}
      {part.id === "patching" && <PatchingTab />}
      {part.id === "certificates" && <CertificatesTab />}
      {part.id === "keystore" && <KeystoreTab />}
      {part.id === "sso" && <SingleSignOnTab />}
      {part.id === "general" && <GeneralTab />}
    </>
  );
}
