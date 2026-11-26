import { Link } from "react-router";
import { useApi } from "../../api/hooks";
import type { SlowDevice } from "../../api/types";
import { Skeleton } from "../../components/ui";
import { plural } from "../../lib/format";
import { formatMinutes } from "./alertText";

/** How many devices the list shows before it says how many more there are. */
const SHOWN = 5;

/** The kinds whose wait follows the device's heartbeat interval (ADR-0058). */
export const WAITS_FOR_INTERVAL = ["offline", "cpu", "memory", "disk"];

/** What the heartbeat interval means for a policy: the sentence that says it waits longer, once saved. */
export function slowText(total: number, minutes: number): string {
  return `${plural(total, "device")} wait${total === 1 ? "s" : ""} longer than ${formatMinutes(minutes)}: a longer heartbeat interval makes this policy wait for it.`;
}

/**
 * The devices a saved policy covers whose heartbeat interval makes it wait longer than its minutes, and how long,
 * so the effect of a longer interval is never silent (ADR-0058). It loads by itself.
 */
export function SlowDevices({ policyId, minutes }: { policyId: string; minutes: number }) {
  const q = useApi<{ items: SlowDevice[]; total: number }>(`/alert-policies/${policyId}/slow-devices`);
  if (q.isPending) {
    return (
      <div aria-label="Checking the devices' heartbeat intervals" className="flex flex-col gap-2 rounded-md bg-raised px-3 py-2">
        <Skeleton className="w-2/3" />
        <Skeleton className="w-1/2" />
      </div>
    );
  }
  if (q.isError || q.data.total === 0) return null;
  const { items, total } = q.data;
  return (
    <section aria-label="Devices that wait longer" className="rounded-md bg-raised px-3 py-2 text-sm">
      <p className="font-medium text-fg">{slowText(total, minutes)}</p>
      <ul className="mt-1.5 flex flex-col gap-1 text-muted">
        {items.slice(0, SHOWN).map((d) => (
          <li key={d.deviceId}>
            <Link to={`/devices/${d.deviceId}`} className="text-fg underline-offset-2 hover:underline">
              {d.name}
            </Link>{" "}
            in {d.siteName}: checks in every {formatMinutes(Math.max(1, Math.round(d.heartbeatSeconds / 60)))}
            {d.heartbeatSeconds < 60 ? ` (${d.heartbeatSeconds} seconds)` : ""}, waits {formatMinutes(d.waitMinutes)}
          </li>
        ))}
      </ul>
      {total > SHOWN && <p className="mt-1 text-muted">and {total - SHOWN} more.</p>}
    </section>
  );
}
