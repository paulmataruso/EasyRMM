import { useState } from "react";
import type { Device } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { Dialog } from "../../../components/Dialog";
import { useToast } from "../../../components/Toast";
import { Badge, Button, Card, Field, InlineError, Input, KeyValueList, Select, type Tone } from "../../../components/ui";
import { formatDateTime, formatRelative } from "../../../lib/format";
import { ModuleTab } from "./ModuleTab";
import { Loading, SkeletonKeyValue } from "./skeletons";
import { failureText, useWinmodChange, useWinmodRead } from "./winmod";

interface LapsAdminAccount {
  name: string;
  enabled: boolean;
  lastLogon: string | null;
  passwordLastSet: string | null;
  passwordExpires: string | null;
}

interface LapsStatus {
  windowsLaps: boolean;
  legacyLaps: boolean;
  domainJoined: boolean;
  policy: Record<string, unknown> | null;
  adminAccount: LapsAdminAccount | null;
  adPasswordExpiry: string | null;
}

const BOOL_TONE: Record<string, Tone> = { true: "ok", false: "neutral" };

export function LapsTab({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const toast = useToast();
  const configure = canAt("device.configure", { organizationId: device.organizationId, siteId: device.siteId });
  const status = useWinmodRead<LapsStatus>(device.id, "laps.status", {});
  const change = useWinmodChange(device.id, "laps");
  const [dialog, setDialog] = useState<null | "configure">(null);

  const st = status.data?.data ?? null;
  const failure = status.data?.failure ?? null;
  const lost = status.data?.lost ?? null;
  const loading = !st && !failure && !lost && !status.error;

  const resetPassword = async () => {
    change.reset();
    try {
      await change.mutateAsync({ action: "laps.reset_password", params: {} });
      toast.success("LAPS password rotation triggered.");
    } catch {
      // shown inline
    }
  };

  return (
    <ModuleTab
      name="Local Admin Passwords"
      asOf={st ? (status.data?.finishedAt ?? null) : null}
      refreshing={status.isFetching}
      loading={loading}
      skeleton={
        <Loading name="Local Admin Passwords">
          <SkeletonKeyValue title="LAPS" rows={4} />
          <SkeletonKeyValue title="Administrator Account" rows={5} />
        </Loading>
      }
      offline={status.data?.offline}
      unavailable={failure ? failureText(failure) : (lost ?? undefined)}
    >
      <InlineError error={status.error} />
      {st && (
        <>
          <Card
            title="LAPS"
            actions={configure && (
              <span className="flex gap-2">
                <Button size="sm" onClick={() => { change.reset(); setDialog("configure"); }}>Configure LAPS</Button>
                {st.domainJoined && (st.windowsLaps || st.legacyLaps) && (
                  <Button size="sm" loading={change.isPending} onClick={resetPassword}>Rotate password</Button>
                )}
              </span>
            )}
          >
            <KeyValueList
              items={[
                ["Windows LAPS", <Badge key="wl" tone={BOOL_TONE[String(st.windowsLaps)]}>{st.windowsLaps ? "Configured" : "Not configured"}</Badge>],
                ["Legacy LAPS", <Badge key="ll" tone={BOOL_TONE[String(st.legacyLaps)]}>{st.legacyLaps ? "Installed" : "Not installed"}</Badge>],
                ["Domain joined", <Badge key="dj" tone={st.domainJoined ? "ok" : "warn"}>{st.domainJoined ? "Yes" : "No"}</Badge>],
                ...(st.adPasswordExpiry ? [["AD password expiry", <span key="pe" title={formatDateTime(st.adPasswordExpiry)}>{formatRelative(st.adPasswordExpiry)}</span>] as [string, React.ReactNode]] : []),
              ]}
            />
            <InlineError error={change.error} />
          </Card>
          {st.adminAccount && (
            <Card title="Administrator account">
              <KeyValueList
                items={[
                  ["Name", st.adminAccount.name],
                  ["Enabled", <Badge key="en" tone={st.adminAccount.enabled ? "ok" : "neutral"}>{st.adminAccount.enabled ? "Yes" : "No"}</Badge>],
                  ["Last logon", st.adminAccount.lastLogon ? <span key="ll" title={formatDateTime(st.adminAccount.lastLogon)}>{formatRelative(st.adminAccount.lastLogon)}</span> : "Never"],
                  ["Password last set", st.adminAccount.passwordLastSet ? <span key="ps" title={formatDateTime(st.adminAccount.passwordLastSet)}>{formatRelative(st.adminAccount.passwordLastSet)}</span> : "Never"],
                  ...(st.adminAccount.passwordExpires ? [["Password expires", <span key="px" title={formatDateTime(st.adminAccount.passwordExpires)}>{formatRelative(st.adminAccount.passwordExpires)}</span>] as [string, React.ReactNode]] : []),
                ]}
              />
            </Card>
          )}
          {st.policy && Object.keys(st.policy).length > 0 && (
            <Card title="LAPS policy">
              <KeyValueList
                items={Object.entries(st.policy).map(([k, v]) => [k, String(v)])}
              />
            </Card>
          )}
        </>
      )}
      {dialog === "configure" && (
        <ConfigureDialog
          device={device}
          policy={st?.policy ?? null}
          change={change}
          onClose={() => setDialog(null)}
          onSuccess={(msg) => { setDialog(null); toast.success(msg); }}
        />
      )}
    </ModuleTab>
  );
}

function ConfigureDialog({ device, policy, change, onClose, onSuccess }: {
  device: Device;
  policy: Record<string, unknown> | null;
  change: ReturnType<typeof useWinmodChange>;
  onClose: () => void;
  onSuccess: (msg: string) => void;
}) {
  const cur = (key: string) => policy?.[key] != null ? String(policy[key]) : "";
  const [backupDirectory, setBackupDirectory] = useState(cur("BackupDirectory") || "2");
  const [passwordAgeDays, setPasswordAgeDays] = useState(cur("PasswordAgeDays") || "");
  const [passwordLength, setPasswordLength] = useState(cur("PasswordLength") || "");
  const [passwordComplexity, setPasswordComplexity] = useState(cur("PasswordComplexity") || "");
  const [adminName, setAdminName] = useState(cur("AdministratorAccountName") || "");
  const [expirationProtection, setExpirationProtection] = useState(cur("PasswordExpirationProtectionEnabled") || "");
  const [encryptionEnabled, setEncryptionEnabled] = useState(cur("ADPasswordEncryptionEnabled") || "");
  const [encryptionPrincipal, setEncryptionPrincipal] = useState(cur("ADPasswordEncryptionPrincipal") || "");
  const [postAuthDelay, setPostAuthDelay] = useState(cur("PostAuthenticationResetDelay") || "");
  const [postAuthActions, setPostAuthActions] = useState(cur("PostAuthenticationActions") || "");

  const submit = async () => {
    const params: Record<string, string | number> = { backupDirectory };
    if (passwordAgeDays) params.passwordAgeDays = Number(passwordAgeDays);
    if (passwordLength) params.passwordLength = Number(passwordLength);
    if (passwordComplexity) params.passwordComplexity = passwordComplexity;
    if (adminName !== "") params.administratorAccountName = adminName;
    if (expirationProtection) params.passwordExpirationProtectionEnabled = expirationProtection;
    if (encryptionEnabled) params.adPasswordEncryptionEnabled = encryptionEnabled;
    if (encryptionPrincipal !== "") params.adPasswordEncryptionPrincipal = encryptionPrincipal;
    if (postAuthDelay) params.postAuthenticationResetDelay = Number(postAuthDelay);
    if (postAuthActions) params.postAuthenticationActions = postAuthActions;
    try {
      await change.mutateAsync({ action: "laps.configure", params });
      onSuccess("LAPS policy configured.");
    } catch {
      // shown inline
    }
  };

  return (
    <Dialog open onClose={onClose} title="Configure Windows LAPS" description={`Set the LAPS policy on ${device.name} via local registry. This does not use Group Policy.`} size="lg">
      <div className="flex flex-col gap-3">
        <Field label="Backup directory" htmlFor="laps-backup" required>
          <Select id="laps-backup" value={backupDirectory} onChange={(e) => setBackupDirectory(e.target.value)}>
            <option value="2">Active Directory</option>
            <option value="1">Azure AD</option>
          </Select>
        </Field>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Password age (days)" htmlFor="laps-age" hint="1–365, default 30">
            <Input id="laps-age" type="number" min={1} max={365} value={passwordAgeDays} onChange={(e) => setPasswordAgeDays(e.target.value)} placeholder="30" />
          </Field>
          <Field label="Password length" htmlFor="laps-len" hint="8–64, default 14">
            <Input id="laps-len" type="number" min={8} max={64} value={passwordLength} onChange={(e) => setPasswordLength(e.target.value)} placeholder="14" />
          </Field>
        </div>
        <Field label="Password complexity" htmlFor="laps-complex">
          <Select id="laps-complex" value={passwordComplexity} onChange={(e) => setPasswordComplexity(e.target.value)}>
            <option value="">Default (large + small + digits + specials)</option>
            <option value="1">Large letters only</option>
            <option value="2">Large + small letters</option>
            <option value="3">Large + small + digits</option>
            <option value="4">Large + small + digits + specials</option>
          </Select>
        </Field>
        <Field label="Administrator account name" htmlFor="laps-admin" hint="Blank = built-in RID 500">
          <Input id="laps-admin" value={adminName} onChange={(e) => setAdminName(e.target.value)} placeholder="Administrator" />
        </Field>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Expiration protection" htmlFor="laps-exp">
            <Select id="laps-exp" value={expirationProtection} onChange={(e) => setExpirationProtection(e.target.value)}>
              <option value="">Default (enabled)</option>
              <option value="1">Enabled</option>
              <option value="0">Disabled</option>
            </Select>
          </Field>
          <Field label="AD password encryption" htmlFor="laps-enc">
            <Select id="laps-enc" value={encryptionEnabled} onChange={(e) => setEncryptionEnabled(e.target.value)}>
              <option value="">Default (enabled when AD)</option>
              <option value="1">Enabled</option>
              <option value="0">Disabled</option>
            </Select>
          </Field>
        </div>
        <Field label="Encryption principal" htmlFor="laps-enc-p" hint="Group that can decrypt the password">
          <Input id="laps-enc-p" value={encryptionPrincipal} onChange={(e) => setEncryptionPrincipal(e.target.value)} placeholder="Domain Admins" />
        </Field>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Post-auth reset delay (hours)" htmlFor="laps-delay" hint="0 = disabled, default 24">
            <Input id="laps-delay" type="number" min={0} max={720} value={postAuthDelay} onChange={(e) => setPostAuthDelay(e.target.value)} placeholder="24" />
          </Field>
          <Field label="Post-auth actions" htmlFor="laps-post">
            <Select id="laps-post" value={postAuthActions} onChange={(e) => setPostAuthActions(e.target.value)}>
              <option value="">Default (reset password)</option>
              <option value="1">Reset password</option>
              <option value="3">Reset password + logoff</option>
              <option value="5">Reset password + reboot</option>
            </Select>
          </Field>
        </div>
      </div>
      <InlineError error={change.error} />
      <div className="mt-4 flex justify-end gap-2 border-t border-line pt-3">
        <Button onClick={onClose} disabled={change.isPending}>Cancel</Button>
        <Button variant="primary" loading={change.isPending} onClick={submit}>Apply LAPS policy</Button>
      </div>
    </Dialog>
  );
}
