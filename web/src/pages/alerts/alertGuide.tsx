// What each kind of alert means and what to do about it, for an alert's card. Every sentence says what EasyRMM checks
// (docs/operations/alerts.md) or where the console shows more; none guesses at the cause.
import type { ReactNode } from "react";
import type { AlertEntry } from "../../api/types";
import { Mono } from "../../components/ui";
import { formatMinutes } from "./alertText";

/** A tab of the device's page, linked from an alert's card. */
export interface DeviceTab {
  tab: "overview" | "hardware";
  label: string;
}

export interface AlertGuide {
  /** What holds while the alert is active. */
  means: string;
  /** What to check or do, in order. */
  next: ReactNode[];
  /** The device tabs that show more. */
  tabs: DeviceTab[];
}

const OVERVIEW: DeviceTab = { tab: "overview", label: "Overview: Health and Performance" };
const HARDWARE: DeviceTab = { tab: "hardware", label: "Hardware: Disks" };

const ACKNOWLEDGE = "Acknowledge the alert to say someone is on it: it stays active and resolves on its own when the condition clears.";
const RISING = "This count only rises, so the alert resolves only when the disk is replaced or the policy's threshold is raised. Acknowledge it rather than resolve it: resolved by hand while the count holds, it opens again within a minute.";
const STATUS = (
  <>
    On the device, <Mono>sudo easyrmm-agent status</Mono> (Linux) or{" "}
    <Mono>&amp; &quot;$env:ProgramFiles\EasyRMM\Agent\easyrmm-agent.exe&quot; status</Mono> (Windows) says whether the agent is
    running and connected.
  </>
);

type Kind = Pick<AlertEntry, "kind" | "checkName" | "threshold" | "minutes"> & { subjectLabel?: string };

export function alertGuide(a: Kind): AlertGuide {
  const span = formatMinutes(a.minutes);
  const at = `${a.threshold ?? 0}%`;
  switch (a.kind) {
    case "offline":
      return {
        means: `Neither the EasyRMM agent nor MeshAgent has checked in from this device for ${span} or more. The server cannot tell a device that is off from one that cannot reach it.`,
        next: [
          "Check that the device is on and connected to the network. The Overview's Details show when it was last seen.",
          STATUS,
          "The alert resolves as soon as the device checks in.",
        ],
        tabs: [OVERVIEW],
      };
    case "cpu":
    case "memory": {
      const what = a.kind === "cpu" ? "Processor use" : "Memory in use";
      return {
        means: `${what} was at ${at} or more in every measurement for ${span}. The agent measures once a minute.`,
        next: [
          `The Overview's Health shows the latest ${a.kind === "cpu" ? "processor use and process count" : "memory and swap use"}, and Performance charts the last hour, day or week.`,
          "To see which programs use it, open a remote terminal or desktop on the device.",
          `It resolves on its own when every measurement of the last 5 minutes (or ${span}, when shorter) is below ${at}. ${ACKNOWLEDGE}`,
        ],
        tabs: [OVERVIEW],
      };
    }
    case "disk":
      return {
        means: `The device's fullest filesystem was ${at} full or more in every measurement for ${span}.`,
        next: [
          "The Overview's Health lists the fullest filesystems with their free space.",
          "Free space on it or make it larger.",
          `It resolves on its own when every measurement of the last 5 minutes (or ${span}, when shorter) is below ${at}. ${ACKNOWLEDGE}`,
        ],
        tabs: [OVERVIEW, HARDWARE],
      };
    case "disk_health":
      return diskGuide(a);
    case "remote_down":
      return {
        means: `The EasyRMM agent checks in from this device, but MeshAgent has not been connected to MeshCentral for ${span} or more, so no remote session can start. The alert's details say why: MeshAgent is not installed, not running, has settings for another server, or its node is in another site's MeshCentral group.`,
        next: [
          "The device page says the same, and its Repair button has the EasyRMM agent restart MeshAgent and, if that does not help, put its program and settings back, keeping its identity.",
          "EasyRMM does this by itself where the organization allows it; the repairs tried since the alert opened are listed below.",
          "It resolves as soon as MeshCentral sees MeshAgent connected.",
        ],
        tabs: [OVERVIEW],
      };
    case "agent_silent":
      return {
        means: `MeshCentral sees MeshAgent connected on this device, but its EasyRMM agent has not checked in for ${span} or more. The device is on; the agent that reports, runs scripts and installs updates is not working.`,
        next: [
          "Open a remote terminal on the device and run the status command below.",
          STATUS,
          "It resolves as soon as the EasyRMM agent checks in.",
        ],
        tabs: [OVERVIEW],
      };
    case "repair_failed":
      return {
        means: `EasyRMM tried to repair this device's ${a.subjectLabel || "agent"} by itself and it is still not working. The alert's details are the last step's diagnostics.`,
        next: [
          "The repairs tried since the alert opened are listed below, each with its steps.",
          "The device page's repair buttons try again by hand; automatic repairs wait 6 hours between attempts and make at most 3 a day.",
          "It resolves on its own once the agent is back. An organization administrator can turn automatic repairs off in the organization's settings.",
        ],
        tabs: [OVERVIEW],
      };
    case "compliance_fix_failed":
      return {
        means: `A fix from the compliance queue was made on this computer for ${a.subjectLabel || "a control"}, and the change did not stand. The alert's details say why.`,
        next: [
          "Open the computer's Compliance tab and look at the item: it keeps the value before and after.",
          "Undo the fix there, or fix the cause and try again.",
          "It resolves once the item is undone, set aside or no longer failed.",
        ],
        tabs: [OVERVIEW],
      };
    case "compliance_scan_stale":
      return {
        means: "The newest compliance result for this computer is older than the organization's freshness window, so it no longer counts as meeting anything: stale results are treated as not passing.",
        next: [
          "Start a scan for the organization from its Compliance tab, or check that scheduled scans are on.",
          "Check that the computer is online and its agent checks in.",
          "It resolves once a newer result arrives.",
        ],
        tabs: [OVERVIEW],
      };
    default:
      return { means: `A ${String(a.kind)} alert, a kind this console does not know.`, next: [ACKNOWLEDGE], tabs: [OVERVIEW] };
  }
}

function diskGuide(a: Kind): AlertGuide {
  const n = (a.threshold ?? 0).toLocaleString();
  const disks = "The Hardware tab's Disks card shows each disk's facts and its last 30 days; select the disk for its panel.";
  const twoReadings = "The agent reads each disk every 30 minutes; the alert resolves on its own after two readings in a row clear it.";
  switch (a.checkName) {
    case "failing":
      return {
        means:
          "The disk's own verdict is failing: its SMART status reports threshold exceeded, a pre-fail attribute is at or below its threshold, or an NVMe disk raised a critical warning.",
        next: ["Back up what is on the disk now, then replace it.", disks, twoReadings],
        tabs: [HARDWARE],
      };
    case "errors":
      return {
        means: `The disk has ${n} or more reallocated sectors and NVMe media errors: sectors it replaced with spares, and reads or writes it could not recover.`,
        next: ["Back up what is on the disk, and watch whether the count keeps rising.", disks, RISING],
        tabs: [HARDWARE],
      };
    case "pending":
      return {
        means: `The disk has ${n} or more pending or offline-uncorrectable sectors: sectors it could not read, waiting to be reallocated.`,
        next: ["Back up what is on the disk.", disks, `Pending sectors can fall again once they are reallocated or read. ${twoReadings}`],
        tabs: [HARDWARE],
      };
    case "wear":
      return {
        means: `The disk has used ${n}% or more of its rated endurance, the writes its maker rates it for.`,
        next: ["Plan to replace the disk.", disks, RISING],
        tabs: [HARDWARE],
      };
    case "temperature":
      return {
        means:
          a.threshold === null
            ? `Every reading of the disk for ${formatMinutes(a.minutes)} was at or over the drive's own temperature limit.`
            : `Every reading of the disk for ${formatMinutes(a.minutes)} was at ${a.threshold} °C or more.`,
        next: [
          "Check the device's cooling: its fans, its airflow and the room.",
          disks,
          "It resolves on its own after two readings in a row at least 5 °C below the limit.",
        ],
        tabs: [HARDWARE],
      };
    default:
      return { means: "A disk health check this console does not know.", next: [disks, ACKNOWLEDGE], tabs: [HARDWARE] };
  }
}
