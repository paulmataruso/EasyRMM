import type { Device } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import { Badge, Button, Card, InlineError, KeyValueList, type Tone } from "../../../components/ui";
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
            actions={configure && st.domainJoined && (st.windowsLaps || st.legacyLaps) && (
              <Button size="sm" loading={change.isPending} onClick={resetPassword}>Rotate password</Button>
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
    </ModuleTab>
  );
}
