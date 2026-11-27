import { useState } from "react";
import type { Device } from "../../../../../api/types";
import { Dialog } from "../../../../../components/Dialog";
import { Alert, Badge, Button, InlineError, KeyValueList, TableWrap } from "../../../../../components/ui";
import { formatDateTime } from "../../../../../lib/format";
import { SkeletonKeyValue } from "../../skeletons";
import { failureText, useWinmodRead } from "../../winmod";
import {
  BackupNowDialog, CopyGpoDialog, DeleteGpoDialog, LinkAddDialog, LinkEditDialog, LinkRemoveDialog, RenameGpoDialog, SecurityAddDialog,
  SecurityRemoveDialog, StatusDialog, WmiDialog, type LinkEdit,
} from "./GpoDialogs";
import { MODULE, STATUS_LABEL, versionText } from "./gpoText";
import type { Gpo, GpoDetail, LinkTree, Trustee, WmiFilters } from "./types";

type Open =
  | { k: "copy" | "rename" | "delete" | "status" | "wmi" | "backup" | "secAdd" | "linkAdd" }
  | { k: "secRemove"; t: Trustee }
  | { k: "linkRemove"; target: string }
  | { k: "linkEdit"; target: string; edit: LinkEdit; link: { order: number; enabled: boolean; enforced: boolean } };

/** One GPO: its state, links, security filtering and delegation, and the changes the person may make (ADR-0083 section 2). */
export function GpoDetailDialog({
  device,
  gpo,
  perms,
  writable,
  onReport,
  onClose,
}: {
  device: Device;
  gpo: Gpo;
  perms: { manage: boolean; link: boolean };
  writable: boolean;
  onReport: () => void;
  onClose: () => void;
}) {
  const read = useWinmodRead<GpoDetail>(device.id, `${MODULE}.gpo_get`, { id: gpo.id });
  const wmi = useWinmodRead<WmiFilters>(device.id, `${MODULE}.wmi_filters`, {}, perms.manage);
  const tree = useWinmodRead<LinkTree>(device.id, `${MODULE}.link_tree`, { offset: 0, pageSize: 60 }, perms.link);
  const [open, setOpen] = useState<Open | null>(null);
  const d = read.data?.data ?? null;
  const g: Gpo = d ?? gpo;
  const close = () => setOpen(null);
  const can = writable && !read.data?.offline;
  const filtering = (d?.trustees ?? []).filter((t) => t.apply);
  const failure = read.data?.failure;

  return (
    <Dialog open onClose={onClose} title={g.name} description={g.default ? "A Default policy: changes need a second person and its name typed in full." : g.description || undefined} size="lg">
      <div className="flex flex-col gap-4">
        <InlineError error={read.error} />
        {failure && <Alert tone="warn">{failureText(failure)}</Alert>}
        {!d && !failure ? (
          <SkeletonKeyValue rows={6} />
        ) : (
          <>
            <KeyValueList
              items={[
                ["Status", <Badge key="s" tone={g.status === "AllSettingsEnabled" ? "ok" : "warn"}>{STATUS_LABEL[g.status]}</Badge>],
                ["Computer version", versionText(g.computer)],
                ["User version", versionText(g.user)],
                ["WMI filter", g.wmiFilter || "None"],
                ["Owner", g.owner],
                ["Modified", g.modified ? formatDateTime(g.modified) : "—"],
                ["Identifier", <code key="i" className="text-xs">{g.id}</code>],
              ]}
            />
            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={onReport}>Show every setting</Button>
              {can && perms.manage && (
                <>
                  <Button size="sm" onClick={() => setOpen({ k: "status" })}>Status</Button>
                  <Button size="sm" onClick={() => setOpen({ k: "wmi" })}>WMI filter</Button>
                  <Button size="sm" onClick={() => setOpen({ k: "backup" })}>Back up</Button>
                  <Button size="sm" onClick={() => setOpen({ k: "copy" })}>Copy</Button>
                  {!g.default && <Button size="sm" onClick={() => setOpen({ k: "rename" })}>Rename</Button>}
                  {!g.default && <Button size="sm" variant="danger-ghost" onClick={() => setOpen({ k: "delete" })}>Delete</Button>}
                </>
              )}
              {can && perms.link && <Button size="sm" onClick={() => setOpen({ k: "linkAdd" })}>Link…</Button>}
            </div>
            <section aria-label="Links">
              <h3 className="mb-1 text-sm font-semibold">Links</h3>
              {(d?.reportLinks ?? []).length === 0 ? (
                <p className="text-sm text-muted">Not linked anywhere. It applies to nobody until it is.</p>
              ) : (
                <TableWrap>
                  <table className="table-base">
                    <thead>
                      <tr><th scope="col">Linked to</th><th scope="col">Enabled</th><th scope="col">Enforced</th><th scope="col"><span className="sr-only">Actions</span></th></tr>
                    </thead>
                    <tbody>
                      {d!.reportLinks.map((l) => (
                        <tr key={l.path}>
                          <td>{l.path} {l.sensitive && <Badge tone="warn">reaches many</Badge>}</td>
                          <td>{l.enabled ? "Yes" : "No"}</td>
                          <td>{l.enforced ? "Yes" : "No"}</td>
                          <td className="text-right">
                            {can && perms.link && tree.data?.data && (
                              <LinkRowActions tree={tree.data.data} path={l.path} gpoId={g.id} isDefault={g.default} setOpen={setOpen} />
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
              )}
            </section>
            <section aria-label="Security filtering">
              <h3 className="mb-1 text-sm font-semibold">Security filtering (who the GPO applies to)</h3>
              <ul className="text-sm">
                {filtering.map((t) => (
                  <li key={t.sid} className="flex items-center justify-between gap-2 py-0.5">
                    <span>{t.name} <span className="text-xs text-muted">({t.type.replace("_", " ")})</span></span>
                    {can && perms.manage && <Button size="sm" variant="danger-ghost" onClick={() => setOpen({ k: "secRemove", t })}>Remove</Button>}
                  </li>
                ))}
                {filtering.length === 0 && <li className="text-muted">Nobody has Apply group policy.</li>}
              </ul>
              {can && perms.manage && <Button size="sm" className="mt-1" onClick={() => setOpen({ k: "secAdd" })}>Add a principal…</Button>}
            </section>
            <section aria-label="Delegation">
              <h3 className="mb-1 text-sm font-semibold">Delegation</h3>
              <TableWrap>
                <table className="table-base">
                  <thead><tr><th scope="col">Name</th><th scope="col">Permission</th><th scope="col">Inherited</th></tr></thead>
                  <tbody>
                    {(d?.trustees ?? []).map((t) => (
                      <tr key={`${t.sid}-${t.permission}-${t.denied}`}>
                        <td>{t.name}</td>
                        <td>{t.denied ? "Deny " : ""}{t.permission}</td>
                        <td>{t.inherited ? "Yes" : "No"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </section>
          </>
        )}
        {open?.k === "copy" && <CopyGpoDialog device={device} gpo={g} onClose={close} />}
        {open?.k === "rename" && <RenameGpoDialog device={device} gpo={g} onClose={() => { close(); onClose(); }} />}
        {open?.k === "delete" && <DeleteGpoDialog device={device} gpo={g} onClose={() => { close(); onClose(); }} />}
        {open?.k === "status" && <StatusDialog device={device} gpo={g} onClose={close} />}
        {open?.k === "wmi" && <WmiDialog device={device} gpo={g} filters={(wmi.data?.data?.filters ?? []).map((f) => f.name)} onClose={close} />}
        {open?.k === "backup" && <BackupNowDialog device={device} gpo={g} onClose={close} />}
        {open?.k === "secAdd" && <SecurityAddDialog device={device} gpo={g} onClose={close} />}
        {open?.k === "secRemove" && <SecurityRemoveDialog device={device} gpo={g} trustee={open.t} onClose={close} />}
        {open?.k === "linkAdd" && <LinkAddDialog device={device} gpo={g} targets={tree.data?.data?.targets ?? []} onClose={close} />}
        {open?.k === "linkRemove" && <LinkRemoveDialog device={device} gpo={g} target={open.target} onClose={close} />}
        {open?.k === "linkEdit" && <LinkEditDialog device={device} gpo={g} target={open.target} kind={open.edit} current={open.link} onClose={close} />}
      </div>
    </Dialog>
  );
}

/** The report names a link by its path; the link tree has its distinguished name, order and flags. */
function LinkRowActions({ tree, path, gpoId, isDefault, setOpen }: { tree: LinkTree; path: string; gpoId: string; isDefault: boolean; setOpen: (o: Open) => void }) {
  const hit = tree.targets
    .map((t) => ({ t, l: t.links.find((x) => x.gpoId === gpoId) }))
    .find((x) => x.l && (x.t.name === path.split("/").pop() || path.endsWith(x.t.name)));
  if (!hit?.l) return null;
  const { t, l } = hit;
  const link = { order: l.order, enabled: l.enabled, enforced: l.enforced };
  return (
    <span className="whitespace-nowrap">
      <Button size="sm" variant="ghost" onClick={() => setOpen({ k: "linkEdit", target: t.dn, edit: "order", link })}>Order</Button>
      <Button size="sm" variant="ghost" onClick={() => setOpen({ k: "linkEdit", target: t.dn, edit: "enabled", link })}>{l.enabled ? "Disable" : "Enable"}</Button>
      <Button size="sm" variant="ghost" onClick={() => setOpen({ k: "linkEdit", target: t.dn, edit: "enforced", link })}>{l.enforced ? "Release" : "Enforce"}</Button>
      {!isDefault && <Button size="sm" variant="danger-ghost" onClick={() => setOpen({ k: "linkRemove", target: t.dn })}>Remove</Button>}
    </span>
  );
}
