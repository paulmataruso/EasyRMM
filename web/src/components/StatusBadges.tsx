import type { Assignment, AuditEntry, AuditOutcome, Device, EnrollmentTokenStatus, RemoteKind, Role, User } from "../api/types";
import { Badge, Dot, type Tone } from "./ui";

export const ROLE_NAMES: Record<Role, string> = {
  super_admin: "Super Administrator",
  org_admin: "Organization Administrator",
  site_admin: "Site Administrator",
  technician: "Technician",
  read_only: "Read-Only",
  key_reader: "Recovery Key Reader",
  key_approver: "Recovery Key Approver",
};

export function roleName(role: Role): string {
  return ROLE_NAMES[role] ?? role;
}

/** "Technician · Contoso / London" */
export function describeAssignment(a: Assignment): string {
  const scope = a.siteId ? `${a.organizationName ?? "Organization"} / ${a.siteName ?? "Site"}` : a.organizationId ? (a.organizationName ?? "Organization") : "All organizations";
  return `${roleName(a.role)} · ${scope}`;
}

export function userState(u: Pick<User, "status" | "locked" | "passwordSet" | "mfaEnabled">): { label: string; tone: Tone; title: string } {
  if (u.status === "disabled") return { label: "Disabled", tone: "neutral", title: "This account cannot sign in." };
  if (u.locked) return { label: "Locked", tone: "danger", title: "Locked after repeated failed sign-ins. Unlock it, or it unlocks on its own after the lockout period." };
  if (!u.passwordSet) return { label: "Invited", tone: "info", title: "The invitation has not been accepted yet." };
  if (!u.mfaEnabled) return { label: "MFA pending", tone: "warn", title: "Sets up a second factor at next sign-in." };
  return { label: "Active", tone: "ok", title: "Can sign in." };
}

export function UserStatusBadge({ user }: { user: Pick<User, "status" | "locked" | "passwordSet" | "mfaEnabled"> }) {
  const s = userState(user);
  return (
    <Badge tone={s.tone} title={s.title}>
      {s.label}
    </Badge>
  );
}

const OUTCOME: Record<AuditOutcome, { label: string; tone: Tone }> = {
  success: { label: "Success", tone: "ok" },
  failure: { label: "Failed", tone: "danger" },
  denied: { label: "Denied", tone: "warn" },
};

export function OutcomeBadge({ outcome }: { outcome: AuditOutcome }) {
  const o = OUTCOME[outcome] ?? { label: outcome, tone: "neutral" as Tone };
  return <Badge tone={o.tone}>{o.label}</Badge>;
}

const ACTIONS: Record<string, string> = {
  "auth.login": "Signed in",
  "auth.logout": "Signed out",
  "auth.mfa_enroll": "Set up authenticator",
  "auth.mfa_verify": "Verified second factor",
  "auth.password_change": "Changed password",
  "auth.password_reset": "Reset password",
  "auth.password_reset_request": "Requested password reset",
  "auth.recovery_codes_regenerate": "Replaced recovery codes",
  "auth.session_revoke": "Ended a session",
  "auth.step_up": "Confirmed a second factor again",
  "auth.webauthn_add": "Added a security key",
  "auth.webauthn_remove": "Removed a security key",
  "auth.sso_link": "Linked a single sign-on account",
  "auth.sso_unlink": "Unlinked a single sign-on account",
  "sso.provider_create": "Added identity provider",
  "sso.provider_update": "Changed identity provider",
  "sso.provider_delete": "Removed identity provider",
  "setup.complete": "Completed first-run setup",
  "organization.create": "Created organization",
  "organization.update": "Updated organization",
  "organization.delete": "Deleted organization",
  "organization.details_update": "Changed contact information",
  "site.create": "Created site",
  "site.update": "Updated site",
  "site.delete": "Deleted site",
  "site.details_update": "Changed address and hours",
  "contact.create": "Added contact",
  "contact.update": "Changed contact",
  "contact.delete": "Deleted contact",
  "site_place.create": "Added place",
  "site_place.update": "Changed place",
  "site_place.delete": "Deleted place",
  "device_group.create": "Created device group",
  "device_group.update": "Updated device group",
  "device_group.delete": "Deleted device group",
  "user.invite": "Invited user",
  "user.update": "Updated user",
  "user.roles_change": "Changed roles",
  "user.disable": "Disabled user",
  "user.enable": "Enabled user",
  "user.unlock": "Unlocked user",
  "user.mfa_reset": "Reset second factor",
  "user.password_link": "Issued password link",
  "user.delete": "Deleted user",
  "device.remote_session": "Started remote session",
  "device.enroll": "Enrolled device",
  "device.remote_link": "Connected remote access",
  "enrollment_token.create": "Created deployment token",
  "enrollment_token.revoke": "Revoked deployment token",
  "enrollment_token.reveal": "Showed deployment token again",
  "approval_token.create": "Created approval token",
  "approval_token.revoke": "Revoked approval token",
  "approval_token.reveal": "Showed approval token again",
  "enrollment_request.create": "Device asked for approval",
  "enrollment_request.approve": "Approved device",
  "enrollment_request.reject": "Rejected device",
  "script.create": "Added script",
  "script.update": "Changed script",
  "script.delete": "Deleted script",
  "device.script_run": "Ran script",
  "device.software_action": "Software action",
  "device.hardening": "Hardening job",
  "device.package_recovery": "Package database recovery",
  "device.agent_update": "Updated agent",
  "device.agent_update_request": "Asked for an agent update",
  "device.repair_request": "Asked to reconnect remote access",
  "device.repair_end": "Repair ended",
  "device.removal_request": "Asked to remove device",
  "device.removal_cancel": "Cancelled device removal",
  "device.removal_failed": "Agent could not remove itself",
  "device.remove": "Removed device",
  "device.retired_cleanup": "Removed agent of a removed device",
  "agent_updates.update": "Changed agent update settings",
  "agent_updates.request_all": "Asked to update every outdated agent",
  "agent_updates.signed_upload": "Uploaded a signed Windows agent build",
  "agent_updates.signed_remove": "Removed a signed Windows agent build",
  "report.export": "Downloaded report",
  "job.cancel": "Stopped script run",
  "job_run.output_view": "Viewed job output",
  "job.arguments_view": "Viewed job arguments",
  "job.results_export": "Downloaded job results",
  "job_run.output_remove": "Removed job output",
  "alert_policy.create": "Added alert policy",
  "alert_policy.update": "Changed alert policy",
  "alert_policy.delete": "Deleted alert policy",
  "alert.acknowledge": "Acknowledged alert",
  "alert.resolve": "Resolved alert",
  "mail_server.update": "Changed the mail server",
  "mail_server.delete": "Removed the mail server",
  "mail_server.limits_update": "Changed the mail limits",
  "mail_server.test": "Sent a test message",
  "audit_forwarding.update": "Changed audit forwarding",
  "audit_forwarding.test": "Tested audit forwarding",
  "easypatch.connection_update": "Changed the patching engine connection",
  "easypatch.connection_delete": "Removed the patching engine connection",
  "easypatch.organization_link": "Linked organization to the patching engine",
  "easypatch.organization_unlink": "Unlinked organization from the patching engine",
  "easypatch.organization_update": "Changed automatic EasyPatch agent installs",
  "patch.scan": "Scanned for updates",
  "patch.install": "Installed updates",
  "patch.install_all": "Installed updates across an organization or site",
  "patch.cancel": "Cancelled patch job",
  "patch.agent_install": "Requested EasyPatch agent install",
  "patch.restart": "Requested a restart",
  "patch.restart_all": "Requested a restart across an organization or site",
  "patch.retry": "Retried patch job",
  "patch.stop": "Stopped patching",
  "patch.allow": "Allowed patching again",
  "patch.endpoint_remove": "Removed a patching-only endpoint",
  "patch.exclude": "Excluded an update",
  "patch.include": "Included an update again",
  "patch.remove_update": "Requested an update removal",
  "patch.notify": "Messaged a device's users",
  "patch.agent_update": "Requested EasyPatch agent update",
  "patch.hold": "Held an update",
  "patch.release_hold": "Released an update's hold",
  "patch.policy_update": "Changed a patch policy",
  "patch.policy_reset": "Reset a patch policy",
  "patch.tag_create": "Added a patch tag",
  "patch.tag_update": "Changed a patch tag",
  "patch.tag_delete": "Deleted a patch tag",
  "patch.tag_assign": "Changed patch tags",
  "patch.report_generate": "Made a monthly patch report",
  "patch.report_download": "Downloaded a monthly patch report",
  "patch.report_send": "Emailed a monthly patch report",
  "patch.report_delete": "Deleted a monthly patch report",
  "patch.report_schedule": "Changed a patch report schedule",
  "patch.settings_update": "Changed the patching engine's server settings",
  "patch.lifecycle_create": "Added an OS lifecycle entry",
  "patch.lifecycle_update": "Changed an OS lifecycle entry",
  "patch.lifecycle_delete": "Deleted an OS lifecycle entry",
  "patch.alert_acknowledge": "Acknowledged patching alerts",
  "patch.alert_rule_create": "Added a patching alert rule",
  "patch.alert_rule_update": "Changed a patching alert rule",
  "patch.alert_rule_delete": "Deleted a patching alert rule",
  "patch.channel_create": "Added a notification channel",
  "patch.channel_update": "Changed a notification channel",
  "patch.channel_delete": "Deleted a notification channel",
  "patch.channel_test": "Sent a test notification",
  "patch.channel_rotate_secret": "Made a new webhook signing key",
  "patch.notifications_update": "Changed patching notification settings",
};

/** An action's name; with the entry's details, a read of job output that was a download says so (ADR-0064). */
export function actionLabel(action: string, details?: Record<string, unknown> | null): string {
  if (action === "job_run.output_view" && typeof details?.download === "string") return "Downloaded job output";
  return ACTIONS[action] ?? action;
}

/** Audit areas offered as filters (action prefixes the server accepts). */
export const ACTION_GROUPS: [string, string][] = [
  ["auth", "Sign-in and security"],
  ["organization", "Organizations"],
  ["site", "Sites"],
  ["contact", "Contacts"],
  ["site_place", "Places"],
  ["device_group", "Device groups"],
  ["device", "Devices"],
  ["enrollment_token", "Deployment tokens"],
  ["approval_token", "Approval tokens"],
  ["enrollment_request", "Device approvals"],
  ["script", "Scripts"],
  ["job", "Jobs"],
  ["job_run", "Job output"],
  ["agent_updates", "Agent updates"],
  ["report", "Reports"],
  ["alert_policy", "Alert policies"],
  ["alert", "Alerts"],
  ["user", "Users"],
  ["mail_server", "Mail server"],
  ["audit_forwarding", "Audit forwarding"],
  ["patch", "Patching"],
  ["easypatch", "Patching engine settings"],
  ["sso", "Single sign-on settings"],
  ["setup", "Setup"],
];

/** What an audit entry acted on, from its details (names and emails are recorded at the time). */
export function auditTarget(e: AuditEntry): string {
  const d = e.details ?? {};
  const name = typeof d.name === "string" ? d.name : typeof d.email === "string" ? d.email : null;
  if (name && typeof d.device === "string") return `${name} on ${d.device}`;
  if (name) return name;
  if (typeof d.script === "string" && typeof d.device === "string") return `${d.script} on ${d.device}`;
  if (typeof d.script === "string" && e.targetType === "job") return d.script;
  if (e.action === "patch.alert_acknowledge" && typeof d.alerts === "number") {
    const n = d.alerts === 1 ? "1 alert" : `${d.alerts.toLocaleString()} alerts`;
    return typeof d.device === "string" ? `${n} on ${d.device}` : `${n} of the organization`;
  }
  if (typeof d.package === "string" && typeof d.device === "string") {
    const verb = typeof d.action === "string" ? SOFTWARE_VERBS[d.action] : undefined;
    return `${verb ? `${verb} ` : ""}${d.package} on ${d.device}`;
  }
  if (typeof d.device === "string") return typeof d.kind === "string" ? `${d.device} (${REMOTE_KIND_NAMES[d.kind as RemoteKind] ?? d.kind})` : d.device;
  if (e.targetType === "session") return "Session";
  // A contact's name is personal data and stays out of the audit log (ADR-0066); a place's kind is all it records.
  if (e.targetType === "contact") return "Contact";
  if (e.targetType === "site_place") return typeof d.kind === "string" ? `Place (${d.kind})` : "Place";
  if (e.targetType === "report") return REPORT_TITLES[e.targetId ?? ""] ?? "Report";
  if (e.targetType === "audit_forwarding") return e.targetId ? `Collector ${e.targetId}` : "Collector";
  if (e.targetType === "mail_server") {
    if (e.targetId === "limits") return "Mail limits";
    if (e.action === "mail_server.test" && typeof d.to === "string") return `To ${d.to} through ${e.targetId ?? "the mail server"}`;
    return e.targetId ? `Mail server ${e.targetId}` : "Mail server";
  }
  if (e.action.startsWith("easypatch.organization_") && typeof d.organization === "string") {
    return typeof d.easyPatchName === "string" ? `${d.organization} → ${d.easyPatchName}` : d.organization;
  }
  if (e.targetType === "easypatch") return typeof d.url === "string" ? d.url : "Patching engine";
  if (e.targetType === "easypatch_settings") return "Patching engine server settings";
  if (e.targetType === "easypatch_notifications") return "Patching notifications";
  if (e.targetType === "easypatch_lifecycle" && typeof d.product === "string") {
    return typeof d.versionLabel === "string" ? `${d.product} ${d.versionLabel}` : d.product;
  }
  if (e.actorType === "user" && e.targetType === "user" && e.targetId === e.actorId) return "Own account";
  return e.targetType ? e.targetType.replace(/_/g, " ") : "—";
}

const REPORT_TITLES: Record<string, string> = {
  devices: "Device inventory",
  software: "Installed software",
  health: "Device health",
  alerts: "Alert history",
  contacts: "Contacts",
};

const SOFTWARE_VERBS: Record<string, string> = { install: "Install", upgrade: "Update", uninstall: "Uninstall" };

export const REMOTE_KIND_NAMES: Record<RemoteKind, string> = {
  desktop: "Remote desktop",
  rdp: "RDP",
  terminal: "Terminal",
  files: "Files",
};

/** Online, offline, or no agent at all. */
export function DeviceStatusBadge({ device }: { device: Pick<Device, "online" | "agent" | "remoteAgent" | "removal"> }) {
  if (device.removal) {
    const failed = device.removal.error !== "";
    return (
      <Badge
        tone={failed ? "danger" : "warn"}
        icon={<Dot tone={failed ? "danger" : "warn"} />}
        title={failed ? `The agent could not uninstall itself: ${device.removal.error}` : "Waiting for the agent to uninstall itself."}
      >
        {failed ? "Removal failed" : "Removing"}
      </Badge>
    );
  }
  if (!device.agent && !device.remoteAgent) {
    return (
      <Badge tone="neutral" title="No agent has connected for this device.">
        No agent
      </Badge>
    );
  }
  return device.online ? (
    <Badge tone="ok" icon={<Dot tone="ok" />}>
      Online
    </Badge>
  ) : (
    <Badge tone="neutral" icon={<Dot tone="neutral" />}>
      Offline
    </Badge>
  );
}

const TOKEN_STATUS: Record<EnrollmentTokenStatus, { label: string; tone: Tone; title: string }> = {
  active: { label: "Usable", tone: "ok", title: "Devices can enroll with this token." },
  expired: { label: "Expired", tone: "neutral", title: "The token has expired." },
  revoked: { label: "Revoked", tone: "neutral", title: "The token was revoked." },
  used_up: { label: "Used up", tone: "neutral", title: "As many devices as the token allows have enrolled." },
};

export function TokenStatusBadge({ status }: { status: EnrollmentTokenStatus }) {
  const s = TOKEN_STATUS[status] ?? { label: status, tone: "neutral" as Tone, title: "" };
  return (
    <Badge tone={s.tone} title={s.title}>
      {s.label}
    </Badge>
  );
}
