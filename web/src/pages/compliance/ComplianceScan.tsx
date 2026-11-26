import { useEffect, useId, useState } from "react";
import { ScanSearch } from "lucide-react";
import { api } from "../../api/client";
import { pathKey, useApi, useApiMutation, useList } from "../../api/hooks";
import { useQueryClient } from "@tanstack/react-query";
import type { ComplianceProfile } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Button, Field, InlineError, Select } from "../../components/ui";

/** Starts a scan of the organization, or of one computer (ADR-0078, section 4): the chosen profile's controls, read from a fresh check of the computers. */
export function ComplianceScan({ organizationId, deviceId, platform }: { organizationId: string; deviceId?: string; platform?: string }) {
  const id = useId();
  const toast = useToast();
  const profiles = useList<ComplianceProfile>("/compliance/profiles", undefined, { staleTime: 60_000 });
  const usable = profiles.items.filter((p) => !platform || (p.platform as { os?: string } | null)?.os === platform || (p.platform as { os?: string } | null)?.os === "any");
  const [profile, setProfile] = useState("");
  const chosen = profile || usable[0]?.key || "";
  const client = useQueryClient();
  const [scanId, setScanId] = useState<string | null>(null);
  const scan = useApiMutation(
    () => api.post<{ id: string }>(`/organizations/${organizationId}/compliance/scans`, { profile: chosen, run: true, ...(deviceId ? { deviceIds: [deviceId] } : {}) }),
    {
      onSuccess: (s) => {
        setScanId(s.id);
        toast.success("Scan started. The results show here when the computers answer.");
      },
    },
  );
  // Reading a scan moves it forward (the server reads what the computers reported), so the page asks until it ends.
  const progress = useApi<{ state: string; waiting: number }>(scanId ? `/organizations/${organizationId}/compliance/scans/${scanId}` : null, undefined, {
    refetchInterval: (d) => (d && d.state !== "planned" && d.state !== "running" ? false : 3000),
  });
  const running = scanId !== null && (!progress.data || progress.data.state === "planned" || progress.data.state === "running");
  const ended = progress.data && !running ? progress.data.state : null;
  useEffect(() => {
    if (ended) {
      void client.invalidateQueries({ queryKey: pathKey(`/organizations/${organizationId}/compliance`) });
      void client.invalidateQueries({ queryKey: pathKey(deviceId ? `/devices/${deviceId}/compliance` : "/devices") });
    }
  }, [ended, client, organizationId, deviceId]);
  return (
    <div className="flex flex-wrap items-end gap-3">
      <Field label="Profile" htmlFor={id} className="min-w-64">
        <Select id={id} value={chosen} onChange={(e) => setProfile(e.target.value)} disabled={usable.length === 0}>
          {usable.map((p) => (
            <option key={p.key} value={p.key}>
              {p.title}
            </option>
          ))}
        </Select>
      </Field>
      <Button variant="primary" icon={<ScanSearch className="size-4" aria-hidden />} disabled={chosen === ""} loading={scan.isPending || running} onClick={() => scan.mutate(undefined)}>
        Scan now
      </Button>
      {running && <span role="status" className="pb-2 text-sm text-muted">Scanning{progress.data ? `: waiting for ${progress.data.waiting} computer${progress.data.waiting === 1 ? "" : "s"}` : ""}…</span>}
      {ended && <span role="status" className="pb-2 text-sm text-muted">{ended === "done" ? "Scan finished." : ended === "partial" ? "Scan finished with some answers missing." : "The scan did not finish."}</span>}
      <InlineError error={scan.error} />
    </div>
  );
}
