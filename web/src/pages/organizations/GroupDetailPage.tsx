import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { Pencil, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useList } from "../../api/hooks";
import type { Device, DeviceGroupDetail } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { useToast } from "../../components/Toast";
import {
  Alert,
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  InlineError,
  KeyValueList,
  PageHeader,
  SelectField,
  Spinner,
  TableWrap,
  Tabs,
} from "../../components/ui";
import { formatDateTime } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { DEFAULT_VERBOSE_HOURS, VERBOSE_HOURS } from "../devices/agentLogsText";
import { HardeningTab } from "./tabs/HardeningTab";
import { DeleteGroupDialog, DeviceGroupDialog } from "./GroupDialogs";

/** What a change to a group's logging refreshes. */
const GROUP_PATH = (id: string) => `/device-groups/${id}`;

/**
 * A device group's page (ADR-0072): its devices on Overview, and its settings. Today the only setting is group-wide
 * verbose agent logging, which moved here from the device's Logs tab.
 */
export function GroupDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const url = useUrlState();
  const { canAt } = useAuth();
  const group = useApi<DeviceGroupDetail>(GROUP_PATH(id));
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);

  if (group.isPending) return <Spinner />;
  if (group.isError) return <ErrorState error={group.error} onRetry={() => void group.refetch()} />;
  const g = group.data;
  // A tab that does not apply is hidden, never greyed.
  const showHardening = canAt("device.view", { organizationId: g.organizationId, siteId: g.siteId });
  const tab = g.canEditDevices && url.get("tab") === "settings" ? "settings" : showHardening && url.get("tab") === "hardening" ? "hardening" : "overview";

  return (
    <>
      <PageHeader
        breadcrumb={
          <>
            <Link to="/organizations" className="hover:text-fg">
              Organizations
            </Link>
            <span className="mx-1.5" aria-hidden>
              /
            </span>
            <Link to={`/organizations/${g.organizationId}`} className="hover:text-fg">
              {g.organizationName}
            </Link>
            <span className="mx-1.5" aria-hidden>
              /
            </span>
            <Link to={`/sites/${g.siteId}`} className="hover:text-fg">
              {g.siteName}
            </Link>
          </>
        }
        title={g.name}
        subtitle={g.description || undefined}
        actions={
          g.canManage && (
            <>
              <Button icon={<Pencil className="size-4" aria-hidden />} onClick={() => setEditing(true)}>
                Rename
              </Button>
              <Button variant="danger-ghost" icon={<Trash2 className="size-4" aria-hidden />} onClick={() => setDeleting(true)}>
                Delete
              </Button>
            </>
          )
        }
      />

      <Tabs
        tabs={[
          { id: "overview", label: "Overview" },
          { id: "hardening", label: "Hardening", hidden: !showHardening },
          { id: "settings", label: "Settings", hidden: !g.canEditDevices },
        ]}
        active={tab}
        onChange={(t) => url.set({ tab: t === "overview" ? null : t })}
      />

      {tab === "overview" && <Overview group={g} />}
      {tab === "hardening" && (
        <div role="tabpanel" aria-labelledby="tab-hardening">
          <HardeningTab level="group" id={g.id} />
        </div>
      )}
      {tab === "settings" && (
        <div role="tabpanel" aria-labelledby="tab-settings">
          <VerboseLogging group={g} />
        </div>
      )}

      <DeviceGroupDialog open={editing} siteId={g.siteId} group={g} onClose={() => setEditing(false)} />
      <DeleteGroupDialog
        group={deleting ? g : null}
        siteName={g.siteName}
        onClose={() => {
          if (deleting) {
            setDeleting(false);
            navigate(`/sites/${g.siteId}`, { replace: true });
          }
        }}
      />
    </>
  );
}

function Overview({ group: g }: { group: DeviceGroupDetail }) {
  const devices = useList<Device>("/devices", { groupId: g.id });
  return (
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
      <div className="xl:col-span-2">
        <Card
          title="Devices"
          padded={false}
          actions={
            <Link
              to={`/devices?organizationId=${g.organizationId}&siteId=${g.siteId}&groupId=${g.id}`}
              className="text-sm text-accent hover:underline"
            >
              Open in Devices
            </Link>
          }
        >
          {devices.isPending ? (
            <Spinner />
          ) : devices.isError ? (
            <ErrorState error={devices.error} onRetry={() => void devices.refetch()} compact />
          ) : devices.items.length === 0 ? (
            <EmptyState title="No devices in this group">Move a device here from its page or the navigation tree.</EmptyState>
          ) : (
            <TableWrap className="rounded-none border-0">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Status</th>
                    <th>System</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.items.map((d) => (
                    <tr key={d.id}>
                      <td className="font-medium">
                        <Link to={`/devices/${d.id}`} className="hover:text-accent hover:underline">
                          {d.name}
                        </Link>
                      </td>
                      <td>
                        <Badge tone={d.online ? "ok" : "neutral"}>{d.online ? "Online" : "Offline"}</Badge>
                      </td>
                      <td className="max-w-md truncate text-muted">{d.osDescription || d.platform}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Card>
      </div>
      <Card title="Details">
        <KeyValueList
          narrow
          items={[
            [
              "Organization",
              <Link to={`/organizations/${g.organizationId}`} className="text-accent hover:underline">
                {g.organizationName}
              </Link>,
            ],
            [
              "Site",
              <Link to={`/sites/${g.siteId}`} className="text-accent hover:underline">
                {g.siteName}
              </Link>,
            ],
            ["Devices", String(g.deviceCount)],
            ["Created", formatDateTime(g.createdAt)],
            ["Updated", formatDateTime(g.updatedAt)],
            ["Your access", g.canManage ? "Manage" : "View only"],
          ]}
        />
      </Card>
    </div>
  );
}

/** Group-wide verbose agent logging: every device in the group logs at Debug for a while, including ones added meanwhile. */
function VerboseLogging({ group: g }: { group: DeviceGroupDetail }) {
  const toast = useToast();
  const [hours, setHours] = useState(DEFAULT_VERBOSE_HOURS);
  const on = g.verboseUntil !== null && new Date(g.verboseUntil).getTime() > Date.now();
  const start = useApiMutation(
    () =>
      api.put<{ until: string }>(`${GROUP_PATH(g.id)}/agent-logs/verbose`, {
        hours,
      }),
    {
      invalidate: [GROUP_PATH(g.id), "/audit"],
      onSuccess: (r) => toast.success(`Verbose logging is on until ${formatDateTime(r.until)}.`),
    },
  );
  const stop = useApiMutation(() => api.del(`${GROUP_PATH(g.id)}/agent-logs/verbose`), {
    invalidate: [GROUP_PATH(g.id), "/audit"],
    onSuccess: () => toast.success("Verbose logging turned off."),
  });
  return (
    <Card title="Verbose agent logging">
      <div className="flex max-w-xl flex-col gap-3.5">
        <p className="text-sm text-muted">
          The EasyRMM agent on every device in this group logs at Debug for a while, which shows more of what it does. It covers devices
          added meanwhile, returns to Info by itself, and turning it on is recorded in the audit log.
        </p>
        {on ? (
          <Alert tone="info" title="Verbose logging is on">
            <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span>Until {formatDateTime(g.verboseUntil!)}.</span>
              <Button size="sm" onClick={() => stop.mutate(undefined)} loading={stop.isPending}>
                Turn off
              </Button>
            </span>
          </Alert>
        ) : (
          <>
            <SelectField
              label="For"
              value={String(hours)}
              onChange={(e) => setHours(Number(e.target.value))}
              error={fieldError(start.error, "hours")}
            >
              {VERBOSE_HOURS.map((h) => (
                <option key={h} value={h}>
                  {h === 1 ? "1 hour" : `${h} hours`}
                  {h === DEFAULT_VERBOSE_HOURS ? " (default)" : ""}
                </option>
              ))}
            </SelectField>
            <div>
              <Button variant="primary" onClick={() => start.mutate(undefined)} loading={start.isPending}>
                Turn on
              </Button>
            </div>
          </>
        )}
        <InlineError error={start.error ?? stop.error} fields={["hours"]} />
      </div>
    </Card>
  );
}
