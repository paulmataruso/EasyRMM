// Assets at an organization, a site or a device group (ADR-0066, slice 2): the key fields, sortable and filterable,
// and the organization's age policy.

import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { ArrowDown, ArrowUp, Plus, Settings2 } from "lucide-react";
import { api, ApiError, fieldError } from "../../api/client";
import { useApi, useApiMutation, useList } from "../../api/hooks";
import type { Asset, AssetAgePolicy, AssetPage } from "../../api/assetTypes";
import type { Site } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, InlineError, SelectField, Spinner, TableWrap, TextField } from "../../components/ui";
import { formatDate } from "../../lib/format";
import { useDebounced } from "../../nav/useDebounced";
import { ageBadge, assetTitle, ASSET_KINDS, ASSET_STATUSES, kindLabel, statusLabel, warrantyBadge } from "./assetText";

const PAGE = 50;

const COLUMNS: { sort: string; label: string }[] = [
  { sort: "name", label: "Name" },
  { sort: "kind", label: "Kind" },
  { sort: "manufacturer", label: "Manufacturer" },
  { sort: "model", label: "Model" },
  { sort: "serial_number", label: "Serial" },
  { sort: "asset_tag", label: "Tag" },
  { sort: "status", label: "Status" },
  { sort: "purchase_date", label: "Purchased" },
  { sort: "warranty_expiry", label: "Warranty" },
];

export function AssetsList({ organizationId, siteId, groupId }: { organizationId: string; siteId?: string; groupId?: string }) {
  const { canAt } = useAuth();
  const [kind, setKind] = useState("");
  const [status, setStatus] = useState("");
  const [warranty, setWarranty] = useState("");
  const [age, setAge] = useState("");
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim(), 300);
  const [sort, setSort] = useState("name");
  const [desc, setDesc] = useState(false);
  const [offset, setOffset] = useState(0);
  const [adding, setAdding] = useState(false);
  const [policyOpen, setPolicyOpen] = useState(false);
  useEffect(() => setOffset(0), [kind, status, warranty, age, q, sort, desc]);

  const page = useApi<AssetPage>(
    `/organizations/${organizationId}/assets`,
    {
      ...(siteId && { siteId }),
      ...(groupId && { groupId }),
      ...(kind && { kind }),
      ...(status && { status }),
      ...(warranty && { warranty }),
      ...(age && { age }),
      ...(q && { q }),
      sort,
      dir: desc ? "desc" : "asc",
      limit: String(PAGE),
      offset: String(offset),
    },
    { keepPrevious: true },
  );
  const manage = canAt("doc.manage", siteId ? { organizationId, siteId } : { organizationId });
  const filtered = kind || status || warranty || age || q;

  function header(c: { sort: string; label: string }) {
    const active = sort === c.sort;
    return (
      <th key={c.sort} scope="col" aria-sort={active ? (desc ? "descending" : "ascending") : "none"} className="px-3 py-2 text-left font-medium">
        <button
          type="button"
          className="inline-flex items-center gap-1 hover:text-fg"
          onClick={() => {
            if (active) setDesc(!desc);
            else {
              setSort(c.sort);
              setDesc(false);
            }
          }}
        >
          {c.label}
          {active && (desc ? <ArrowDown className="size-3" aria-hidden /> : <ArrowUp className="size-3" aria-hidden />)}
        </button>
      </th>
    );
  }

  return (
    <Card
      title="Assets"
      actions={
        <div className="flex gap-2">
          {manage && !groupId && (
            <Button size="sm" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setAdding(true)}>
              Add asset
            </Button>
          )}
          {!siteId && !groupId && (
            <Button size="sm" icon={<Settings2 className="size-3.5" aria-hidden />} onClick={() => setPolicyOpen(true)}>
              Age policy
            </Button>
          )}
        </div>
      }
    >
      <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-5">
        <TextField label="Search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Name, model, serial, tag" className="col-span-2 md:col-span-1" />
        <SelectField label="Kind" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">All kinds</option>
          {ASSET_KINDS.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </SelectField>
        <SelectField label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">Any status</option>
          {ASSET_STATUSES.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </SelectField>
        <SelectField label="Warranty" value={warranty} onChange={(e) => setWarranty(e.target.value)}>
          <option value="">Any warranty</option>
          <option value="active">In warranty</option>
          <option value="expiring">Expiring in 90 days</option>
          <option value="expired">Out of warranty</option>
          <option value="none">No date recorded</option>
        </SelectField>
        <SelectField label="Age" value={age} onChange={(e) => setAge(e.target.value)}>
          <option value="">Any age</option>
          <option value="ok">Current</option>
          <option value="aging">Aging</option>
          <option value="end_of_life">End of life</option>
        </SelectField>
      </div>
      {page.isPending ? (
        <Spinner />
      ) : page.isError ? (
        <ErrorState error={page.error} onRetry={() => void page.refetch()} />
      ) : page.data.items.length === 0 ? (
        <EmptyState title={filtered ? "No assets match" : "No assets yet"} compact>
          {filtered ? "Change the filters to see more." : "Assets are made for each computer whose agent reports its hardware, or added by hand."}
        </EmptyState>
      ) : (
        <>
          <TableWrap>
            <table className="w-full text-sm">
              <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
                <tr>
                  {COLUMNS.map(header)}
                  <th scope="col" className="px-3 py-2 text-left font-medium">
                    Age
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {page.data.items.map((a) => (
                  <AssetRow key={a.id} a={a} showSite={!siteId} />
                ))}
              </tbody>
            </table>
          </TableWrap>
          <div className="mt-3 flex items-center justify-between text-sm text-muted">
            <span>
              {offset + 1}–{offset + page.data.items.length} of {page.data.total}
            </span>
            <div className="flex gap-2">
              <Button size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
                Previous
              </Button>
              <Button size="sm" disabled={offset + PAGE >= page.data.total} onClick={() => setOffset(offset + PAGE)}>
                Next
              </Button>
            </div>
          </div>
        </>
      )}
      <AddAssetDialog open={adding} onClose={() => setAdding(false)} organizationId={organizationId} siteId={siteId} />
      <PolicyDialog open={policyOpen} onClose={() => setPolicyOpen(false)} organizationId={organizationId} canManage={canAt("doc.manage", { organizationId })} />
    </Card>
  );
}

function AssetRow({ a, showSite }: { a: Asset; showSite: boolean }) {
  const w = warrantyBadge(a.warrantyState);
  const age = ageBadge(a.ageStatus);
  const title = assetTitle(a);
  return (
    <tr>
      <td className="px-3 py-2 font-medium">
        {a.deviceId ? (
          <Link to={`/devices/${a.deviceId}?tab=asset`} className="hover:underline">
            {title}
          </Link>
        ) : (
          title
        )}
        {showSite && <div className="text-xs font-normal text-muted">{a.siteName}</div>}
      </td>
      <td className="px-3 py-2">{kindLabel(a.kind)}</td>
      <td className="px-3 py-2">{a.manufacturer || "—"}</td>
      <td className="px-3 py-2">{a.model || "—"}</td>
      <td className="px-3 py-2 font-mono text-xs">{a.serialNumber || "—"}</td>
      <td className="px-3 py-2">{a.assetTag || "—"}</td>
      <td className="px-3 py-2">{statusLabel(a.status)}</td>
      <td className="px-3 py-2">{formatDate(a.purchaseDate)}</td>
      <td className="px-3 py-2">
        {a.warrantyExpiry ? (
          <span className="inline-flex flex-wrap items-center gap-1.5">
            {formatDate(a.warrantyExpiry)} <Badge tone={w.tone}>{w.label}</Badge>
          </span>
        ) : (
          "—"
        )}
      </td>
      <td className="px-3 py-2">{age ? <Badge tone={age.tone}>{age.label}</Badge> : "—"}</td>
    </tr>
  );
}

function AddAssetDialog({ open, onClose, organizationId, siteId }: { open: boolean; onClose: () => void; organizationId: string; siteId?: string }) {
  const toast = useToast();
  const sites = useList<Site>(open ? `/organizations/${organizationId}/sites` : null);
  const [site, setSite] = useState(siteId ?? "");
  const [kind, setKind] = useState("workstation");
  const [values, setValues] = useState<Record<string, string>>({});
  useEffect(() => {
    if (open) {
      setSite(siteId ?? "");
      setKind("workstation");
      setValues({});
    }
  }, [open, siteId]);
  const save = useApiMutation(
    (confirm: boolean) =>
      api.post<Asset>(`/organizations/${organizationId}/assets`, {
        siteId: site,
        kind,
        fields: Object.fromEntries(Object.entries(values).filter(([, v]) => v.trim() !== "")),
        confirmDuplicateSerial: confirm,
      }),
    {
      invalidate: [`/organizations/${organizationId}/assets`, "/audit"],
      onSuccess: () => {
        toast.success("Asset added.");
        onClose();
      },
    },
  );
  useEffect(() => {
    if (open) save.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  const duplicate = save.error instanceof ApiError && save.error.code === "duplicate_serial";
  const set = (k: string, v: string) => setValues((x) => ({ ...x, [k]: v }));
  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate(false);
  }
  return (
    <Dialog open={open} onClose={onClose} title="Add asset" description="Hardware without an agent, or recorded ahead of it." size="md">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <SelectField label="Site" value={site} onChange={(e) => setSite(e.target.value)} required error={fieldError(save.error, "siteId")}>
          <option value="">Choose a site</option>
          {sites.items.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </SelectField>
        <SelectField label="Kind" value={kind} onChange={(e) => setKind(e.target.value)} error={fieldError(save.error, "kind")}>
          {ASSET_KINDS.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </SelectField>
        {(
          [
            ["name", "Name"],
            ["manufacturer", "Manufacturer"],
            ["model", "Model"],
            ["serial_number", "Serial number"],
            ["asset_tag", "Asset tag"],
          ] as const
        ).map(([k, label]) => (
          <TextField key={k} label={label} value={values[k] ?? ""} maxLength={200} onChange={(e) => set(k, e.target.value)} error={fieldError(save.error, k)} />
        ))}
        <TextField label="Purchase date" type="date" value={values.purchase_date ?? ""} onChange={(e) => set("purchase_date", e.target.value)} error={fieldError(save.error, "purchase_date")} />
        <TextField label="Warranty expires" type="date" value={values.warranty_expiry ?? ""} onChange={(e) => set("warranty_expiry", e.target.value)} error={fieldError(save.error, "warranty_expiry")} />
        {duplicate ? (
          <Alert tone="warn">
            An asset with this serial number already exists in this organization.
            <Button className="ml-2" size="sm" loading={save.isPending} onClick={() => save.mutate(true)}>
              Save anyway
            </Button>
          </Alert>
        ) : (
          <InlineError error={save.error} fields={["siteId", "kind", "name", "manufacturer", "model", "serial_number", "asset_tag", "purchase_date", "warranty_expiry"]} />
        )}
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!site}>
            Add asset
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

/** The organization's thresholds for when hardware is aging and when it is at the end of its life. */
function PolicyDialog({ open, onClose, organizationId, canManage }: { open: boolean; onClose: () => void; organizationId: string; canManage: boolean }) {
  const toast = useToast();
  const path = `/organizations/${organizationId}/asset-policy`;
  const policy = useApi<AssetAgePolicy>(open ? path : null);
  const [aging, setAging] = useState("36");
  const [eol, setEol] = useState("60");
  useEffect(() => {
    if (policy.data) {
      setAging(String(policy.data.agingMonths));
      setEol(String(policy.data.eolMonths));
    }
  }, [policy.data]);
  const save = useApiMutation((p: AssetAgePolicy) => api.put<AssetAgePolicy>(path, p), {
    invalidate: [path, `/organizations/${organizationId}/assets`, "/audit"],
    onSuccess: () => {
      toast.success("Age policy saved.");
      onClose();
    },
  });
  useEffect(() => {
    if (open) save.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ agingMonths: Number(aging), eolMonths: Number(eol) });
  }
  return (
    <Dialog open={open} onClose={onClose} title="Age policy" description="Judged from each asset's purchase date." size="sm">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <TextField label="Aging after (months)" type="number" min={1} max={240} value={aging} onChange={(e) => setAging(e.target.value)} disabled={!canManage} error={fieldError(save.error, "agingMonths")} />
        <TextField label="End of life after (months)" type="number" min={1} max={240} value={eol} onChange={(e) => setEol(e.target.value)} disabled={!canManage} error={fieldError(save.error, "eolMonths")} />
        <InlineError error={save.error} fields={["agingMonths", "eolMonths"]} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>{canManage ? "Cancel" : "Close"}</Button>
          {canManage && (
            <Button type="submit" variant="primary" loading={save.isPending}>
              Save policy
            </Button>
          )}
        </div>
      </form>
    </Dialog>
  );
}
