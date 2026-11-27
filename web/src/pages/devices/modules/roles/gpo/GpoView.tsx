import { useState } from "react";
import { Plus } from "lucide-react";
import { useApi } from "../../../../../api/hooks";
import type { Device } from "../../../../../api/types";
import { useAuth } from "../../../../../auth/AuthContext";
import { Alert, Badge, Button, Card, EmptyState, InlineError, KeyValueList, Segmented, TableWrap, TextField } from "../../../../../components/ui";
import { formatDateTime } from "../../../../../lib/format";
import type { AdDomains } from "../../directory/types";
import { ModuleTab } from "../../ModuleTab";
import { SkeletonKeyValue, SkeletonTable } from "../../skeletons";
import { failureText, useWinmodRead } from "../../winmod";
import { ApprovalsPanel } from "./ApprovalsPanel";
import { BackupsPanel } from "./BackupsPanel";
import { BlockDialog, CreateGpoDialog } from "./GpoDialogs";
import { GpoDetailDialog } from "./GpoDetail";
import { KIND_LABEL, MODULE, STATUS_LABEL, versionText } from "./gpoText";
import { SettingsTree } from "./SettingsTree";
import type { Gpo, GpoPage, GpoReport, GpoStatus, LinkTree, WmiFilters } from "./types";

type Panel = "gpos" | "links" | "settings" | "wmi" | "backups" | "approvals";

/**
 * The Group Policy view of a domain controller's Roles tab (ADR-0083, slice 1): the GPOs, the link tree, every setting of a
 * GPO read-only, the WMI filters, the automatic backups and the requests waiting for a second person. Everything is read from
 * the controller by itself and kept fresh; a change is a dialog with a reason, and goes through the controller the domain's
 * changes use.
 */
export function GpoView({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const at = { organizationId: device.organizationId, siteId: device.siteId };
  const perms = { manage: canAt("gpo.manage", at), link: canAt("gpo.link", at), edit: canAt("gpo.edit", at) };
  const [panel, setPanel] = useState<Panel>("gpos");
  const [settingsGpo, setSettingsGpo] = useState<Gpo | null>(null);
  const status = useWinmodRead<GpoStatus>(device.id, `${MODULE}.status`, {});
  const domains = useApi<AdDomains>(canAt("ad.view", at) ? `/organizations/${device.organizationId}/ad/domains` : null, undefined, { staleTime: 30_000 });
  const st = status.data?.data ?? null;
  const failure = status.data?.failure;
  const lost = status.data?.lost;
  const mine = domains.data?.domains.find((d) => d.controllers.some((c) => c.deviceId === device.id));
  const chosen = mine?.controllers.find((c) => c.deviceId === mine.chosen);
  const other = chosen && chosen.deviceId !== device.id ? chosen : null;
  const writable = !other;

  return (
    <ModuleTab
      name="Group Policy"
      asOf={st ? (status.data?.finishedAt ?? null) : null}
      refreshing={status.isFetching}
      loading={!st && !failure && !lost && !status.error}
      skeleton={
        <>
          <SkeletonKeyValue title="Domain" rows={4} />
          <SkeletonTable title="Group Policy objects" columns={5} rows={5} toolbar />
        </>
      }
      offline={status.data?.offline}
      unavailable={failure ? failureText(failure) : (lost ?? undefined)}
    >
      <InlineError error={status.error} />
      {st && (
        <>
          <Alert tone="info">
            Changes are made through this controller, {st.controller}. EasyRMM calls only Microsoft&apos;s Group Policy tools: it never
            writes SYSVOL or a GPO&apos;s directory attributes. A backup of a GPO is taken before every change. Changes made in the Group
            Policy Management Console are not tracked by EasyRMM; the directory&apos;s own audit log has them.
          </Alert>
          {other && (
            <Alert tone="warn" title="This view only reads">
              The domain&apos;s changes go through {other.name}. Open Group Policy there to change anything.
            </Alert>
          )}
          <Card title={st.domain}>
            <KeyValueList
              items={[
                ["Group Policy objects", String(st.gpoCount)],
                ["Not linked anywhere", st.unlinked === null ? "Not counted (a large domain)" : String(st.unlinked)],
                ["Never saved (no settings)", String(st.empty)],
                ["Places a GPO can be linked", String(st.targets)],
              ]}
            />
          </Card>
          <Segmented
            label="Group Policy"
            value={panel}
            onChange={setPanel}
            options={[
              { value: "gpos", label: "GPOs" },
              { value: "links", label: "Links" },
              { value: "settings", label: "Settings" },
              ...(perms.manage ? [{ value: "wmi" as const, label: "WMI filters" }] : []),
              { value: "backups", label: "Backups" },
              { value: "approvals", label: "Approvals" },
            ]}
          />
          {panel === "gpos" && (
            <GposPanel device={device} perms={perms} writable={writable} onSettings={(g) => { setSettingsGpo(g); setPanel("settings"); }} />
          )}
          {panel === "links" && <LinksPanel device={device} perms={perms} writable={writable} />}
          {panel === "settings" && <SettingsPanel device={device} gpo={settingsGpo} onPick={setSettingsGpo} />}
          {panel === "wmi" && <WmiPanel device={device} />}
          {panel === "backups" && <BackupsPanel device={device} perms={perms} writable={writable} />}
          {panel === "approvals" && <ApprovalsPanel device={device} perms={perms} />}
        </>
      )}
    </ModuleTab>
  );
}

function GposPanel({ device, perms, writable, onSettings }: { device: Device; perms: { manage: boolean; link: boolean }; writable: boolean; onSettings: (g: Gpo) => void }) {
  const [offset, setOffset] = useState(0);
  const [match, setMatch] = useState("");
  const [creating, setCreating] = useState(false);
  const [detail, setDetail] = useState<Gpo | null>(null);
  const read = useWinmodRead<GpoPage>(device.id, `${MODULE}.gpo_list`, { offset, pageSize: 30, ...(match.trim() ? { match: match.trim() } : {}) });
  const page = read.data?.data ?? null;
  return (
    <Card
      title="Group Policy objects"
      padded={false}
      actions={writable && perms.manage && <Button size="sm" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setCreating(true)}>Create a GPO</Button>}
    >
      <div className="border-b border-line px-4 py-3">
        <TextField label="Find a GPO" value={match} onChange={(e) => { setMatch(e.target.value); setOffset(0); }} placeholder="Part of a name" />
      </div>
      <InlineError error={read.error} />
      {read.data?.failure && <Alert tone="warn" className="m-3">{failureText(read.data.failure)}</Alert>}
      {!page ? (
        <SkeletonTable columns={5} rows={5} />
      ) : page.items.length === 0 ? (
        <EmptyState compact title="No GPOs">{match ? "No GPO has that in its name." : "The domain has no Group Policy objects."}</EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Status</th>
                <th scope="col" className="hidden md:table-cell">Versions (computer, user)</th>
                <th scope="col">Links</th>
                <th scope="col" className="hidden lg:table-cell">WMI filter</th>
                <th scope="col" className="hidden lg:table-cell">Owner</th>
                <th scope="col"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((g) => (
                <tr key={g.id}>
                  <td className="font-medium">{g.name} {g.default && <Badge tone="info">Default</Badge>}</td>
                  <td><Badge tone={g.status === "AllSettingsEnabled" ? "ok" : "warn"}>{STATUS_LABEL[g.status]}</Badge></td>
                  <td className="hidden md:table-cell">{versionText(g.computer)}, {versionText(g.user)}</td>
                  <td title={g.links.map((l) => l.targetName).join(", ")}>{page.walked ? (g.linkCount === 0 ? <Badge tone="warn">None</Badge> : g.linkCount) : "—"}</td>
                  <td className="hidden lg:table-cell">{g.wmiFilter || "—"}</td>
                  <td className="hidden lg:table-cell">{g.owner}</td>
                  <td className="text-right whitespace-nowrap">
                    <Button size="sm" variant="ghost" onClick={() => onSettings(g)}>Settings</Button>
                    <Button size="sm" variant="ghost" onClick={() => setDetail(g)}>Details</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {page && (
        <div className="flex items-center justify-between border-t border-line px-4 py-2 text-xs text-muted">
          <span>{page.total === 0 ? "" : `${page.offset + 1} to ${page.offset + page.items.length} of ${page.total}`}</span>
          <span className="flex gap-2">
            <Button size="sm" variant="ghost" disabled={page.offset === 0} onClick={() => setOffset(Math.max(0, offset - 30))}>Previous</Button>
            <Button size="sm" variant="ghost" disabled={page.next === null} onClick={() => page.next !== null && setOffset(page.next)}>Next</Button>
          </span>
        </div>
      )}
      {creating && <CreateGpoDialog device={device} onClose={() => setCreating(false)} />}
      {detail && <GpoDetailDialog device={device} gpo={detail} perms={perms} writable={writable} onReport={() => { onSettings(detail); setDetail(null); }} onClose={() => setDetail(null)} />}
    </Card>
  );
}

function LinksPanel({ device, perms, writable }: { device: Device; perms: { link: boolean }; writable: boolean }) {
  const [offset, setOffset] = useState(0);
  const [block, setBlock] = useState<{ dn: string; blocked: boolean } | null>(null);
  const read = useWinmodRead<LinkTree>(device.id, `${MODULE}.link_tree`, { offset, pageSize: 40 });
  const tree = read.data?.data ?? null;
  return (
    <Card title="Link tree" padded={false}>
      <InlineError error={read.error} />
      {!tree ? (
        <SkeletonTable columns={3} rows={6} />
      ) : (
        <>
          <p className="border-b border-line px-4 py-2 text-xs text-muted">
            The domain, its organizational units and the sites, with the GPOs linked to each in the order they apply. A GPO linked
            at the domain root, to the Domain Controllers OU or to a site reaches many computers: changes there need a second person.
          </p>
          <TableWrap className="rounded-none border-0">
            <table className="table-base">
              <thead>
                <tr><th scope="col">Container</th><th scope="col">Linked GPOs (order)</th><th scope="col"><span className="sr-only">Actions</span></th></tr>
              </thead>
              <tbody>
                {tree.targets.map((t) => (
                  <tr key={t.dn}>
                    <td>
                      <span className="font-medium">{t.name}</span> <Badge>{KIND_LABEL[t.kind]}</Badge> {t.sensitive && <Badge tone="warn">reaches many</Badge>}
                      {t.inheritanceBlocked && <Badge tone="warn" className="ml-1">blocks inheritance</Badge>}
                      <div className="text-xs text-muted break-all">{t.dn}</div>
                    </td>
                    <td>
                      {t.links.length === 0 ? <span className="text-muted">None</span> : (
                        <ol className="text-sm">
                          {t.links.map((l) => (
                            <li key={l.gpoId}>{l.order}. {l.gpoName} {!l.enabled && <Badge tone="warn">disabled</Badge>} {l.enforced && <Badge tone="info">enforced</Badge>}</li>
                          ))}
                        </ol>
                      )}
                    </td>
                    <td className="text-right whitespace-nowrap">
                      {writable && perms.link && t.kind !== "site" && (
                        <Button size="sm" variant="ghost" onClick={() => setBlock({ dn: t.dn, blocked: t.inheritanceBlocked })}>
                          {t.inheritanceBlocked ? "Allow inheritance" : "Block inheritance"}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <div className="flex items-center justify-between border-t border-line px-4 py-2 text-xs text-muted">
            <span>{`${tree.offset + 1} to ${tree.offset + tree.targets.length} of ${tree.total}`}</span>
            <span className="flex gap-2">
              <Button size="sm" variant="ghost" disabled={tree.offset === 0} onClick={() => setOffset(Math.max(0, offset - 40))}>Previous</Button>
              <Button size="sm" variant="ghost" disabled={tree.next === null} onClick={() => tree.next !== null && setOffset(tree.next)}>Next</Button>
            </span>
          </div>
        </>
      )}
      {block && <BlockDialog device={device} target={block.dn} blocked={block.blocked} onClose={() => setBlock(null)} />}
    </Card>
  );
}

function SettingsPanel({ device, gpo, onPick }: { device: Device; gpo: Gpo | null; onPick: (g: Gpo | null) => void }) {
  const [offset, setOffset] = useState(0);
  const list = useWinmodRead<GpoPage>(device.id, `${MODULE}.gpo_list`, { offset, pageSize: 30 }, gpo === null);
  const report = useWinmodRead<GpoReport>(device.id, `${MODULE}.gpo_report`, { id: gpo?.id ?? "" }, gpo !== null);
  if (!gpo) {
    const page = list.data?.data;
    return (
      <Card title="Choose a GPO to read" padded={false}>
        {!page ? <SkeletonTable columns={2} rows={5} /> : (
          <ul className="divide-y divide-line">
            {page.items.map((g) => (
              <li key={g.id} className="flex items-center justify-between px-4 py-2">
                <span>{g.name}</span>
                <Button size="sm" onClick={() => onPick(g)}>Read the settings</Button>
              </li>
            ))}
            <li className="flex justify-end gap-2 px-4 py-2">
              <Button size="sm" variant="ghost" disabled={page.offset === 0} onClick={() => setOffset(Math.max(0, offset - 30))}>Previous</Button>
              <Button size="sm" variant="ghost" disabled={page.next === null} onClick={() => page.next !== null && setOffset(page.next)}>Next</Button>
            </li>
          </ul>
        )}
      </Card>
    );
  }
  const r = report.data?.data ?? null;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="text-sm font-semibold">{gpo.name}</h3>
        <Badge>Read-only</Badge>
        <Button size="sm" variant="ghost" onClick={() => onPick(null)}>Choose another GPO</Button>
        {r && <span className="text-xs text-muted">Modified {r.modified ? formatDateTime(r.modified) : "—"}</span>}
      </div>
      <InlineError error={report.error} />
      {report.data?.failure && <Alert tone="warn">{failureText(report.data.failure)}</Alert>}
      {r ? <SettingsTree report={r} /> : !report.data?.failure && <SkeletonTable title="Settings" columns={2} rows={6} />}
    </div>
  );
}

function WmiPanel({ device }: { device: Device }) {
  const read = useWinmodRead<WmiFilters>(device.id, `${MODULE}.wmi_filters`, {});
  const filters = read.data?.data?.filters;
  return (
    <Card title="WMI filters" padded={false}>
      <InlineError error={read.error} />
      {read.data?.failure && <Alert tone="warn" className="m-3">{failureText(read.data.failure)}</Alert>}
      {!filters ? <SkeletonTable columns={3} rows={3} /> : filters.length === 0 ? (
        <EmptyState compact title="No WMI filters">The domain has none. They are made in the Group Policy Management Console.</EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead><tr><th scope="col">Name</th><th scope="col">Description</th><th scope="col">Queries</th></tr></thead>
            <tbody>
              {filters.map((f) => (
                <tr key={f.id || f.name}>
                  <td className="font-medium">{f.name}</td>
                  <td>{f.description || "—"}</td>
                  <td><code className="text-xs break-all">{f.queries.join(" ; ") || "—"}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Card>
  );
}
