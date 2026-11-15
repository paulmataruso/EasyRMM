import { Navigate } from "react-router";
import { useAuth } from "../../auth/AuthContext";
import { PageHeader, Tabs } from "../../components/ui";
import { useUrlState } from "../../lib/urlState";
import { AuditTab } from "./AuditTab";
import { UsersTab } from "./UsersTab";

export function SettingsPage() {
  const url = useUrlState();
  const { can } = useAuth();
  const tabs = [
    { id: "users", label: "Users", hidden: !can("user.view") },
    { id: "audit", label: "Audit log", hidden: !can("audit.view") },
  ];
  const visible = tabs.filter((t) => !t.hidden);
  const first = visible[0];
  if (!first) return <Navigate to="/" replace />;
  const requested = url.get("tab");
  const tab = visible.some((t) => t.id === requested) ? requested : first.id;

  return (
    <>
      <PageHeader title="Settings" subtitle="People who can sign in to EasyRMM, their roles, and the audit log of everything they do." />
      <Tabs
        active={tab}
        onChange={(t) => url.set({ tab: t === first.id ? null : t, q: null, organizationId: null, action: null, actorId: null, invite: null, after: null })}
        tabs={tabs}
      />
      {tab === "users" && <UsersTab />}
      {tab === "audit" && <AuditTab />}
    </>
  );
}
