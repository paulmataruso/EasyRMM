import { useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { ExternalLink, PauseCircle } from "lucide-react";
import { useApi } from "../../api/hooks";
import type { PatchHold, PatchPage, PatchUpdateDevice, PatchUpdateState, PatchUpdateView, PatchVulnerability } from "../../api/types";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, KeyValueList, PageHeader, Segmented, Spinner, TableWrap, type Tone } from "../../components/ui";
import { formatDate, formatDateTime, formatRelative, formatSize, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { categoryLabel, Pager, UpdateStateBadge } from "./patchText";
import { scopeQuery } from "./PatchUpdates";
import { FleetInstallDialog, FleetRemoveDialog, HoldDialog, ReleaseHoldDialog } from "./UpdateDialogs";

/** States a device's install can start from. */
const SELECTABLE: PatchUpdateState[] = ["Missing", "Failed"];

/**
 * One update across the devices in scope: what it fixes, where it is missing, failed or
 * installed, its holds, and installing, removing or holding it.
 */
export function UpdatePage() {
  const { guid = "" } = useParams();
  const url = useUrlState();
  const organizationId = url.get("organizationId");
  const siteId = url.get("siteId");
  const state = url.get("state");
  const page = Math.max(1, Number(url.get("page")) || 1);
  const scope = { organizationId: organizationId || undefined, siteId: siteId || undefined };
  const view = useApi<PatchUpdateView>(`/patching/updates/${guid}`, scope, { refetchInterval: 60_000 });
  const devices = useApi<PatchPage<PatchUpdateDevice>>(
    `/patching/updates/${guid}/devices`,
    { ...scope, state: state || undefined, page: page > 1 ? String(page) : undefined },
    { keepPrevious: true, refetchInterval: 30_000 },
  );
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<"install" | "remove" | "hold" | null>(null);
  const [releasing, setReleasing] = useState<PatchHold | null>(null);
  const back = `/patching?${new URLSearchParams({ tab: "updates", ...(organizationId ? { organizationId } : {}), ...(siteId ? { siteId } : {}) }).toString()}`;

  // Only devices still listed can stay selected.
  const selectable = useMemo(
    () =>
      new Set(
        (devices.data?.items ?? [])
          .filter((d) => d.deviceId && d.canManage && !d.isExcluded && SELECTABLE.includes(d.state))
          .map((d) => d.deviceId as string),
      ),
    [devices.data],
  );
  const chosen = [...selected].filter((id) => selectable.has(id));

  if (view.isPending) return <Spinner />;
  if (view.isError) {
    return (
      <>
        <PageHeader breadcrumb={<Crumb back={back} />} title="Update" />
        <ErrorState error={view.error} onRetry={() => void view.refetch()} />
      </>
    );
  }
  const v = view.data;
  const u = v.summary;
  const missing = u.missingCount + u.failedCount;
  const installed = u.installedCount + u.pendingRebootCount;
  // EasyPatch removes Windows updates; packages and applications are updated, not removed.
  const removable = !u.package && u.category !== "Application" && installed > 0;
  const windows = !u.package && u.category !== "Application";
  const states: { value: string; label: string }[] = [
    { value: "", label: "Every device" },
    ...(
      [
        ["Missing", u.missingCount],
        ["Reoffered", u.reofferedCount],
        ["Failed", u.failedCount],
        ["PendingReboot", u.pendingRebootCount],
        ["Installed", u.installedCount],
        ["Excluded", u.excludedCount],
      ] as [PatchUpdateState, number][]
    )
      .filter(([s, n]) => n > 0 || s === state)
      .map(([s, n]) => ({ value: s, label: `${STATE_LABEL[s]} ${n.toLocaleString()}` })),
  ];

  return (
    <>
      <PageHeader
        breadcrumb={<Crumb back={back} />}
        title={u.title}
        subtitle={
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>
              {[u.kbNumber && `KB${u.kbNumber.replace(/^KB/i, "")}`, u.package && `${u.package.name} ${u.package.version}`, categoryLabel(u.category), u.msrcSeverity]
                .filter(Boolean)
                .join(" · ")}
            </span>
            {u.knownExploited && <Badge tone="danger">Exploited in the wild</Badge>}
            {v.holds.length > 0 && (
              <Badge tone="warn" icon={<PauseCircle className="size-3" aria-hidden />}>
                On hold
              </Badge>
            )}
          </span>
        }
        actions={
          <>
            {v.canManage && missing > 0 && (
              <Button variant="primary" onClick={() => setDialog("install")}>
                {chosen.length > 0 ? `Install on ${plural(chosen.length, "device")}` : "Install where missing…"}
              </Button>
            )}
            {v.canManage && removable && <Button onClick={() => setDialog("remove")}>Remove…</Button>}
            {v.canHold && <Button onClick={() => setDialog("hold")}>Hold…</Button>}
          </>
        }
      />

      {v.holds.map((h) => (
        <Alert
          key={h.id}
          tone="warn"
          className="mb-4"
          title={h.organizationId ? `On hold in ${h.organizationName}` : "On hold in every organization"}
        >
          <p>
            {h.source === "Automatic"
              ? `The patching engine held it after it failed on ${h.failedEndpoints ?? "?"} of ${h.attemptedEndpoints ?? "?"} devices it was tried on.`
              : h.reason}
          </p>
          <p className="mt-1 text-xs text-muted">
            {h.source === "Automatic" ? "Held automatically" : `Held by ${h.createdBy}`},{" "}
            <span title={formatDateTime(h.createdAt)}>{formatRelative(h.createdAt)}</span>. Scheduled installs leave it out; installing it by hand still
            installs it.
          </p>
          {h.canRelease && (
            <Button size="sm" className="mt-2" onClick={() => setReleasing(h)}>
              Release hold
            </Button>
          )}
        </Alert>
      ))}

      <Card title="About this update" className="mb-5">
        {v.description && <p className="mb-4 max-w-prose text-sm whitespace-pre-line text-fg">{v.description}</p>}
        <KeyValueList
          items={[
            ["Released", u.releaseDate ? formatDate(u.releaseDate) : null],
            ["Size", u.sizeBytes ? formatSize(u.sizeBytes) : null],
            ["Classification", v.msClassification || categoryLabel(u.category)],
            ["Products", v.products.length > 0 ? v.products.join(", ") : null],
            ["Knowledge base", v.kbNumbers.length > 0 ? v.kbNumbers.map((k) => `KB${k.replace(/^KB/i, "")}`).join(", ") : null],
            ...(u.package
              ? ([
                  ["Package", `${u.package.name} ${u.package.version}${u.package.repository ? ` (${u.package.repository})` : ""}`],
                  ["Advisories", u.package.advisories && u.package.advisories.length > 0 ? u.package.advisories.join(", ") : null],
                ] as [string, string | null][])
              : []),
            ["Restart", v.rebootLikely ? "Likely needed to finish installing" : "Not expected"],
            ["Replaces", v.supersededUpdateGuids.length > 0 ? plural(v.supersededUpdateGuids.length, "earlier update") : null],
            [
              "More",
              v.supportUrl && /^https?:\/\//i.test(v.supportUrl) ? (
                <a href={v.supportUrl} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-accent hover:underline">
                  Vendor's page <ExternalLink className="size-3" aria-hidden />
                </a>
              ) : null,
            ],
          ]}
        />
      </Card>

      {v.vulnerabilities.length > 0 && <Vulnerabilities list={v.vulnerabilities} windows={windows} />}

      <Card
        title="Devices"
        padded={false}
        actions={<Segmented label="Devices where it is" options={states} value={state} onChange={(s) => url.set({ state: s || null, page: null })} />}
      >
        {devices.isPending ? (
          <Spinner />
        ) : devices.isError ? (
          <div className="p-4">
            <ErrorState error={devices.error} onRetry={() => void devices.refetch()} />
          </div>
        ) : devices.data.items.length === 0 ? (
          <EmptyState title="No devices" compact>
            {state ? "No device in this view is in that state." : "No device in this view reports this update."}
          </EmptyState>
        ) : (
          <>
            <TableWrap className="rounded-none border-0">
              <table className="table-base">
                <thead>
                  <tr>
                    {v.canManage && (
                      <th className="w-8">
                        <span className="sr-only">Choose</span>
                      </th>
                    )}
                    <th>Device</th>
                    <th>State</th>
                    <th className="hidden md:table-cell">Organization / site</th>
                    <th className="hidden lg:table-cell">Since</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.data.items.map((d) => {
                    const id = d.deviceId && selectable.has(d.deviceId) ? d.deviceId : null;
                    return (
                      <tr key={d.endpointId}>
                        {v.canManage && (
                          <td>
                            {id && (
                              <input
                                type="checkbox"
                                className="size-4 accent-accent"
                                aria-label={`Choose ${d.deviceName || d.hostname}`}
                                checked={selected.has(id)}
                                onChange={(e) =>
                                  setSelected((prev) => {
                                    const next = new Set(prev);
                                    if (e.target.checked) next.add(id);
                                    else next.delete(id);
                                    return next;
                                  })
                                }
                              />
                            )}
                          </td>
                        )}
                        <td>
                          {d.deviceId ? (
                            <Link to={`/devices/${d.deviceId}?tab=patches`} className="rounded-sm font-medium hover:text-accent">
                              {d.deviceName || d.hostname}
                            </Link>
                          ) : (
                            <span className="font-medium">{d.hostname}</span>
                          )}
                          {!d.deviceId && <p className="text-xs text-muted">No EasyRMM device</p>}
                          {d.deviceId && !d.isOnline && <p className="text-xs text-muted">EasyPatch agent offline</p>}
                        </td>
                        <td>
                          <span className="flex flex-wrap items-center gap-1">
                            <UpdateStateBadge state={d.state} />
                            {d.isExcluded && d.state !== "Excluded" && <Badge>Excluded</Badge>}
                          </span>
                          {d.state === "Failed" && (d.errorMessage || d.errorCode) && (
                            <p className="mt-1 max-w-md text-xs break-words text-danger">
                              {d.errorMessage || d.errorCode}
                              {d.failedAttempts > 1 && <> ({d.failedAttempts.toLocaleString()} attempts)</>}
                            </p>
                          )}
                        </td>
                        <td className="hidden text-muted md:table-cell">
                          {d.organizationName}
                          {d.siteName && <> / {d.siteName}</>}
                        </td>
                        <td className="hidden whitespace-nowrap text-muted lg:table-cell">
                          <span title={formatDateTime(d.stateChangedAt)}>{formatRelative(d.stateChangedAt)}</span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </TableWrap>
            <div className="px-4 pb-3">
              <Pager page={devices.data.page} total={devices.data.totalCount} size={devices.data.pageSize || 200} onPage={(p) => url.set({ page: p > 1 ? String(p) : null })} />
            </div>
          </>
        )}
      </Card>

      {v.canManage && (
        <>
          <FleetInstallDialog
            open={dialog === "install"}
            onClose={() => setDialog(null)}
            view={v}
            scope={{ organizationId, siteId }}
            deviceIds={chosen}
            missing={missing}
            onDone={() => setSelected(new Set())}
          />
          <FleetRemoveDialog open={dialog === "remove"} onClose={() => setDialog(null)} view={v} scope={{ organizationId, siteId }} installed={installed} />
        </>
      )}
      {v.canHold && <HoldDialog open={dialog === "hold"} onClose={() => setDialog(null)} view={v} organizationId={organizationId} />}
      <ReleaseHoldDialog hold={releasing} guid={u.updateGuid} onClose={() => setReleasing(null)} />
    </>
  );
}

const STATE_LABEL: Partial<Record<PatchUpdateState, string>> = {
  Missing: "Missing",
  Reoffered: "Offered again",
  Failed: "Failed",
  PendingReboot: "Needs a restart",
  Installed: "Installed",
  Excluded: "Excluded",
};

function Crumb({ back }: { back: string }) {
  return (
    <Link to={back} className="hover:text-fg">
      Patching / Updates
    </Link>
  );
}

const SEVERITY: Record<string, Tone> = { Critical: "danger", High: "warn", Important: "warn" };

/** The CVEs it fixes, those exploited in the wild first, as EasyPatch orders them. */
function Vulnerabilities({ list, windows }: { list: PatchVulnerability[]; windows: boolean }) {
  const exploited = list.filter((x) => x.kev).length;
  return (
    <Card
      title={`Vulnerabilities it fixes (${list.length.toLocaleString()})`}
      padded={false}
      className="mb-5"
      actions={exploited > 0 ? <span className="text-sm text-danger">{plural(exploited, "is", "are")} exploited in the wild</span> : undefined}
    >
      <TableWrap className="max-h-96 overflow-y-auto rounded-none border-0">
        <table className="table-base">
          <thead>
            <tr>
              <th>CVE</th>
              <th className="hidden md:table-cell">Title</th>
              <th>Severity</th>
              <th className="hidden text-right sm:table-cell">CVSS</th>
              <th>Exploitation</th>
            </tr>
          </thead>
          <tbody>
            {list.map((x) => (
              <tr key={x.cveId}>
                <td className="whitespace-nowrap">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(x.cveId)}`}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="inline-flex items-center gap-1 font-mono text-accent hover:underline"
                  >
                    {x.cveId} <ExternalLink className="size-3" aria-hidden />
                  </a>
                  {windows && (
                    <a
                      href={`https://msrc.microsoft.com/update-guide/vulnerability/${encodeURIComponent(x.cveId)}`}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="ml-2 text-xs text-muted hover:text-accent hover:underline"
                    >
                      MSRC
                    </a>
                  )}
                </td>
                <td className="hidden min-w-64 md:table-cell">{x.title || x.kevName || <span className="text-subtle">—</span>}</td>
                <td>{x.severity ? <Badge tone={SEVERITY[x.severity] ?? "neutral"}>{x.severity}</Badge> : <span className="text-subtle">—</span>}</td>
                <td className="hidden text-right tabular-nums sm:table-cell">{x.cvssBase !== null ? x.cvssBase.toFixed(1) : "—"}</td>
                <td>
                  {x.kev ? (
                    <div className="flex flex-col items-start gap-1">
                      <Badge tone="danger">Exploited in the wild</Badge>
                      <span className="text-xs text-muted">
                        In CISA's catalog since {x.kevDateAdded ?? "—"}
                        {x.kevDueDate && <>, due {x.kevDueDate}</>}
                      </span>
                      {x.kevRansomware && <Badge tone="danger">Used by ransomware</Badge>}
                    </div>
                  ) : x.msrcExploited ? (
                    <Badge tone="warn" title="Microsoft reports exploitation; not yet in CISA's Known Exploited Vulnerabilities catalog">
                      Exploited, says Microsoft
                    </Badge>
                  ) : (
                    <span className="text-subtle">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Card>
  );
}
