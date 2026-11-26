import { useState } from "react";
import type { Device } from "../../../../../api/types";
import { useAuth } from "../../../../../auth/AuthContext";
import { Alert, Badge, Button, Card, EmptyState, InlineError, KeyValueList, Segmented, TableWrap } from "../../../../../components/ui";
import { formatSize } from "../../../../../lib/format";
import { ModuleTab } from "../../ModuleTab";
import { SkeletonKeyValue, SkeletonSegmented, SkeletonTable } from "../../skeletons";
import { failureText, useWinmodChange, useWinmodRead } from "../../winmod";
import { ActionDialog, send, type Op } from "../kit";
import type { Hardening, PrintDriver, PrintJobDocs, PrintJobList, PrintPort, PrintStatus, Printer, PrinterList } from "./types";

const M = "print";
type Dialog =
  | { op: Op; title: string; label: string; body: string; danger: boolean }
  | null;

/** The Print server module (ADR-0076, section 7). */
export function PrintView({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const at = { organizationId: device.organizationId, siteId: device.siteId };
  const manage = canAt("print.manage", at);
  const destroy = canAt("print.destroy", at);
  const sensitive = canAt("print.view_sensitive", at);
  const [panel, setPanel] = useState<"printers" | "security" | "drivers">("printers");
  const [printer, setPrinter] = useState<string | null>(null);
  const [dialog, setDialog] = useState<Dialog>(null);
  const status = useWinmodRead<PrintStatus>(device.id, `${M}.status`, {});
  const printers = useWinmodRead<PrinterList>(device.id, `${M}.printer_list`, {});
  const hardening = useWinmodRead<Hardening>(device.id, `${M}.hardening_status`, {});
  const jobs = useWinmodRead<PrintJobList>(device.id, `${M}.job_list`, { printer: printer ?? "" }, printer !== null);
  const docs = useWinmodRead<PrintJobDocs>(device.id, `${M}.job_list_sensitive`, { printer: printer ?? "" }, printer !== null && sensitive);
  const ports = useWinmodRead<{ ports: PrintPort[] }>(device.id, `${M}.port_list`, {}, panel === "drivers");
  const drivers = useWinmodRead<{ drivers: PrintDriver[] }>(device.id, `${M}.driver_list`, {}, panel === "drivers");
  const change = useWinmodChange(device.id, M);

  const reads = [status, printers, hardening, ...(printer ? [jobs, ...(sensitive ? [docs] : [])] : []), ...(panel === "drivers" ? [ports, drivers] : [])];
  const failure = reads.map((r) => r.data?.failure).find(Boolean);
  const lost = reads.map((r) => r.data?.lost).find(Boolean);
  const st = status.data?.data ?? null;
  const list = printers.data?.data ?? null;
  const hd = hardening.data?.data ?? null;
  const ask = (d: NonNullable<Dialog>) => {
    change.reset();
    setDialog(d);
  };
  // Tier 1 changes (pause, resume, cancel) have no dialog: one click.
  const quick = (action: string, params: Record<string, unknown>) => send(change, device, { action: `${M}.${action}`, params, confirmed: false }, () => undefined);
  const docOf = (id: number) => docs.data?.data?.jobs.find((j) => j.id === id);

  return (
    <ModuleTab
      name="Print server"
      asOf={st ? (status.data?.finishedAt ?? null) : null}
      refreshing={reads.some((r) => r.isFetching)}
      loading={!st && !failure && !lost && !status.error}
      skeleton={
        <>
          <SkeletonKeyValue title="Server" rows={4} />
          <SkeletonSegmented />
          <SkeletonTable title="Printers" columns={4} rows={4} />
        </>
      }
      offline={status.data?.offline}
      unavailable={failure ? failureText(failure) : (lost ?? undefined)}
    >
      <InlineError error={reads.map((r) => r.error).find(Boolean) ?? change.error} />
      {hd?.weakened && (
        <Alert tone="danger" title="Point and Print is weakened">
          Drivers can be installed without an administrator or without a warning. This is the route of PrintNightmare (CVE-2021-34527).
        </Alert>
      )}
      {st && (
        <Card title="Server">
          <KeyValueList
            items={[
              ["Print Spooler", <Badge key="s" tone={st.serviceState === "running" ? "ok" : "danger"}>{st.serviceState}</Badge>],
              ["Printers", `${st.printerCount} (${st.sharedCount} shared)`],
              ["Jobs waiting", String(st.jobCount)],
            ]}
          />
          {st.domainController && <p className="mt-2 text-xs text-muted">This is a domain controller. Microsoft advises stopping the Print Spooler where nothing prints; the console does not do that.</p>}
          {destroy && (
            <Button className="mt-3" size="sm" variant="danger-ghost" onClick={() => ask({ danger: true, title: "Restart the Print Spooler", label: "Restart spooler", body: "Queued jobs persist, but all printing on this computer stops while the spooler restarts. This needs a second factor.", op: { action: `${M}.spooler_restart`, params: {}, confirmed: true } })}>
              Restart the Print Spooler
            </Button>
          )}
        </Card>
      )}
      {list && (
        <Segmented
          label="View"
          value={panel}
          onChange={setPanel}
          options={[
            { value: "printers", label: "Printers and queues" },
            { value: "security", label: "Security" },
            { value: "drivers", label: "Drivers and ports" },
          ]}
        />
      )}
      {list && panel === "printers" && (
        <Card title="Printers" padded={false}>
          {list.printers.length === 0 ? (
            <EmptyState compact title="No printers">This server has no printers.</EmptyState>
          ) : (
            <TableWrap className="rounded-none border-0">
              <table className="table-base">
                <thead>
                  <tr>
                    <th scope="col">Printer</th>
                    <th scope="col">Status</th>
                    <th scope="col">Jobs</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {list.printers.map((p: Printer) => (
                    <tr key={p.name} aria-selected={p.name === printer}>
                      <td className="font-medium">
                        {p.name}
                        {p.shared && <Badge className="ml-2">shared as {p.shareName}</Badge>}
                      </td>
                      <td>{p.paused ? <Badge tone="warn">paused</Badge> : p.offline ? <Badge tone="warn">offline</Badge> : p.status}</td>
                      <td>{p.jobCount}{p.jobsInError > 0 && <Badge tone="danger" className="ml-2">{p.jobsInError} in error</Badge>}</td>
                      <td className="text-right whitespace-nowrap">
                        <Button size="sm" variant="ghost" onClick={() => setPrinter(p.name)}>Jobs</Button>
                        {manage && <Button size="sm" variant="ghost" onClick={() => quick(p.paused ? "printer_resume" : "printer_pause", { printer: p.name })}>{p.paused ? "Resume" : "Pause"}</Button>}
                        {destroy && p.jobCount > 0 && (
                          <Button size="sm" variant="danger-ghost" onClick={() => ask({ danger: true, title: "Cancel every job", label: "Cancel all jobs", body: `Cancel all ${p.jobCount} jobs of ${p.name}? People must print again. This needs a second factor.`, op: { action: `${M}.queue_clear`, params: { printer: p.name }, confirmed: true } })}>
                            Clear queue
                          </Button>
                        )}
                        {destroy && (
                          <Button size="sm" variant="danger-ghost" onClick={() => ask({ danger: true, title: "Remove printer", label: "Remove printer", body: `Remove ${p.name} and its share? Computers that print to it lose it. This needs a second factor.`, op: { action: `${M}.printer_remove`, params: { printer: p.name }, confirmed: true } })}>
                            Remove
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Card>
      )}
      {panel === "printers" && printer && (
        <Card title={`Jobs of ${printer}`} padded={false}>
          {(jobs.data?.data?.jobs.length ?? 0) === 0 ? (
            <EmptyState compact title="No jobs">{jobs.data?.data ? "The queue is empty." : "Reading the queue…"}</EmptyState>
          ) : (
            <TableWrap className="rounded-none border-0">
              <table className="table-base">
                <thead>
                  <tr>
                    <th scope="col">Job</th>
                    {sensitive && <th scope="col">Document</th>}
                    <th scope="col">Status</th>
                    <th scope="col" className="hidden sm:table-cell">Size</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.data!.data!.jobs.map((j) => (
                    <tr key={j.id}>
                      <td>{j.id}{j.ageMinutes !== null && <span className="ml-2 text-xs text-muted">{j.ageMinutes} min</span>}</td>
                      {sensitive && <td>{docOf(j.id) ? `${docOf(j.id)!.document} (${docOf(j.id)!.owner})` : "—"}</td>}
                      <td>{j.status || "Waiting"}</td>
                      <td className="hidden sm:table-cell">{formatSize(j.sizeBytes)}</td>
                      <td className="text-right whitespace-nowrap">
                        {manage && (
                          <>
                            <Button size="sm" variant="ghost" onClick={() => quick("job_pause", { printer, ids: String(j.id) })}>Pause</Button>
                            <Button size="sm" variant="ghost" onClick={() => quick("job_resume", { printer, ids: String(j.id) })}>Resume</Button>
                            <Button size="sm" variant="ghost" onClick={() => quick("job_restart", { printer, ids: String(j.id) })}>Restart</Button>
                            <Button size="sm" variant="danger-ghost" onClick={() => quick("job_cancel", { printer, ids: String(j.id) })}>Cancel</Button>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
          {!sensitive && <p className="border-t border-line px-4 py-2 text-xs text-muted">Document names and owners are shown to Site Administrators and above.</p>}
        </Card>
      )}
      {panel === "security" && hd && (
        <Card title="Point and Print">
          <KeyValueList
            items={[
              ["Driver installation needs an administrator", hd.restrictDriverInstall === null ? "Not set (the default on updated Windows)" : hd.restrictDriverInstall === 1 ? "Yes" : <Badge key="r" tone="danger">No</Badge>],
              ["Installs without a warning or elevation", hd.noWarningNoElevation === 1 ? <Badge key="n" tone="danger">Yes</Badge> : "No"],
              ["Update prompt", hd.updatePromptSettings === null ? "Not set" : hd.updatePromptSettings === 2 ? <Badge key="u" tone="danger">No warning</Badge> : "Warns"],
            ]}
          />
          <p className="mt-2 text-xs text-muted">A Group Policy that enforces these overrides this computer. The console only offers the safe direction.</p>
          {manage && hd.restrictDriverInstall !== 1 && (
            <Button className="mt-3" variant="primary" onClick={() => ask({ danger: false, title: "Restrict driver installation", label: "Restrict", body: "Require an administrator to install or update printer drivers. This changes only that one setting, and only towards safer.", op: { action: `${M}.point_and_print_restrict`, params: {}, confirmed: true } })}>
              Require administrators for driver installation
            </Button>
          )}
        </Card>
      )}
      {panel === "drivers" && (
        <>
          <Card title="Ports" padded={false}>
            <TableWrap className="rounded-none border-0">
              <table className="table-base">
                <thead><tr><th scope="col">Port</th><th scope="col">Address</th></tr></thead>
                <tbody>
                  {(ports.data?.data?.ports ?? []).map((p) => (
                    <tr key={p.name}><td>{p.name}</td><td>{p.address ? `${p.address}:${p.portNumber}` : p.description}</td></tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </Card>
          <Card title="Drivers" padded={false}>
            <TableWrap className="rounded-none border-0">
              <table className="table-base">
                <thead><tr><th scope="col">Driver</th><th scope="col">Version</th><th scope="col">Source</th></tr></thead>
                <tbody>
                  {(drivers.data?.data?.drivers ?? []).map((d) => (
                    <tr key={`${d.name}|${d.environment}`}><td>{d.name}</td><td>{d.version}</td><td>{d.inbox ? "Windows" : d.manufacturer || "Third party"}</td></tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </Card>
        </>
      )}
      {dialog && (
        <ActionDialog title={dialog.title} label={dialog.label} op={dialog.op} danger={dialog.danger} device={device} change={change} onClose={() => setDialog(null)}>
          {dialog.body}
        </ActionDialog>
      )}
    </ModuleTab>
  );
}
