// The README's screenshots: the production build of the console, its API answered from the fictional data in
// demo.ts. Run with `npm run screenshots` (after `npm run build`); the images land in docs/images/, a dark and a light
// one per page, at the size of EasyPatch's own (1440 × 900 CSS pixels at 1.5×).
//
// This checks nothing about the server. It fails when the console asks for something the data does not answer, so a
// changed page cannot silently photograph an error or a spinner.

import { test, expect, type Page, type Route } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { jobRun } from "../src/test/fixtures";
import {
  alerts,
  alertSummary,
  defaultPolicyView,
  organizationPolicy,
  organizationTags,
  patchTags,
  auditLog,
  byId,
  devicePatching,
  devices,
  fleet,
  fleetUpdates,
  HEALTH_DEVICE,
  healthHistory,
  healthInventory,
  missingUpdates,
  NOW,
  organizations,
  PATCH_DEVICE,
  patchJobs,
  patchStatus,
  productSwitch,
  recentConnections,
  remoteAccess,
  session,
  sites,
  TIME_ZONE,
  UPDATE_GUID,
  updateDevices,
  updateView,
  users,
} from "./demo";

const OUT = process.env.EASYRMM_SCREENSHOTS_OUT ?? join(dirname(fileURLToPath(import.meta.url)), "..", "..", "docs", "images");

const list = <T,>(items: T[]) => ({ items });

/** The console's API, from demo.ts. Undefined for a request the data does not cover. */
function answer(method: string, path: string, q: URLSearchParams): unknown {
  if (method !== "GET") return undefined;
  const deviceMatch = /^\/devices\/([^/]+)(\/.*)?$/.exec(path);
  if (deviceMatch && deviceMatch[1] !== "recent-connections") {
    const [, id, rest = ""] = deviceMatch;
    const d = byId(id!);
    if (!d) return undefined;
    if (rest === "") return d;
    if (rest === "/inventory") return healthInventory;
    if (rest === "/metrics") return healthHistory(q.get("range") ?? "24h");
    return undefined;
  }
  const patchDevice = /^\/patching\/devices\/([^/]+)(\/.*)?$/.exec(path);
  if (patchDevice) {
    const [, id, rest = ""] = patchDevice;
    if (rest === "") return devicePatching(id!);
    if (rest === "/updates") return list(id === PATCH_DEVICE ? missingUpdates : []);
    if (rest === "/installed") return list([]);
    if (rest === "/history") return { items: [], page: 1, pageSize: 25, totalCount: 0 };
    if (rest === "/jobs") return { items: patchJobs.filter((j) => j.deviceId === id), page: 1, pageSize: 25, totalCount: 1 };
    return undefined;
  }
  const orgMatch = /^\/organizations\/([^/]+)(\/sites)?$/.exec(path);
  if (orgMatch) {
    const [, id, sub] = orgMatch;
    if (sub) return list(sites.filter((s) => s.organizationId === id));
    return organizations.find((o) => o.id === id);
  }
  switch (path) {
    case "/setup":
      return { required: false, passwordMinLength: 12 };
    case "/auth/session":
      return session;
    case "/auth/options":
      return { passwordResetAvailable: true, mfaRequired: true, passwordMinLength: 12, webauthn: { available: true, reason: "" } };
    case "/auth/sso":
      return { providers: [] };
    case "/organizations":
      return list(organizations);
    case "/sites":
      return list(q.get("organizationId") ? sites.filter((s) => s.organizationId === q.get("organizationId")) : sites);
    case "/users":
      return list(users);
    case "/devices": {
      const org = q.get("organizationId");
      return list(org ? devices.filter((d) => d.organizationId === org) : devices);
    }
    case "/devices/recent-connections":
      return list(recentConnections);
    case "/enrollment-requests/waiting":
      return { waiting: 0 };
    case "/remote-access/status":
      return remoteAccess;
    case "/alerts/summary":
      return alertSummary;
    case "/alerts": {
      const id = q.get("deviceId");
      return list(id ? alerts.filter((a) => a.deviceId === id) : alerts);
    }
    case "/alerts/devices":
      return list(
        [...new Set(alerts.map((a) => a.deviceId))].map((id) => {
          const own = alerts.filter((a) => a.deviceId === id);
          const d = byId(id)!;
          return { deviceId: id, organizationId: d.organizationId, siteId: d.siteId, active: own.length, critical: own.filter((a) => a.severity === "critical").length };
        }),
      );
    case "/audit": {
      const id = q.get("deviceId");
      if (!id) return list(auditLog);
      return list(auditLog.filter((e) => e.targetId === id && (!q.get("action") || e.action === q.get("action"))));
    }
    case "/job-runs": {
      const id = q.get("deviceId");
      const d = id ? byId(id) : undefined;
      if (!d) return list([]);
      const at = (m: number) => new Date(NOW.getTime() - m * 60_000).toISOString();
      const run = (n: number, script: string, minutes: number) =>
        jobRun(`r${n}`, d.id, d.name, "succeeded", {
          scriptName: script,
          organizationId: d.organizationId,
          organizationName: d.organizationName,
          siteId: d.siteId,
          siteName: d.siteName,
          createdAt: at(minutes),
          sentAt: at(minutes),
          startedAt: at(minutes),
          finishedAt: at(minutes - 0.4),
        });
      return list([run(3, "Check AD replication", 35), run(2, "Free space report", 60 * 20), run(1, "Restart print spooler", 60 * 49)]);
    }
    case "/scripts":
      return list([]);
    case "/patching":
      return patchStatus;
    case "/patching/switch":
      return productSwitch;
    case "/patching/devices":
      return fleet;
    case "/patching/jobs":
      return list(patchJobs);
    case "/patching/updates":
      return { items: fleetUpdates, page: 1, pageSize: 50, totalCount: fleetUpdates.length };
    case `/patching/updates/${UPDATE_GUID}`:
      return updateView;
    case `/patching/updates/${UPDATE_GUID}/devices`:
      return { items: updateDevices, page: 1, pageSize: 200, totalCount: updateDevices.length };
    case "/patching/policies/organization/o-harbor":
      return organizationPolicy;
    case "/patching/tags/of/organization/o-harbor":
      return { tags: organizationTags, canAssign: true };
    case "/patching/policies/default":
      return defaultPolicyView;
    case "/patching/tags":
      return { items: patchTags, canManage: true };
  }
  return undefined;
}

let unanswered: string[] = [];

async function open(page: Page, theme: "dark" | "light", path: string) {
  unanswered = [];
  await page.addInitScript((t) => window.localStorage.setItem("easyrmm.theme", t), theme);
  await page.clock.setFixedTime(NOW);
  await page.route("**/api/v1/**", (route: Route) => {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    const body = answer(req.method(), path, url.searchParams);
    if (body === undefined) {
      unanswered.push(`${req.method()} ${path}${url.search}`);
      return route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: { code: "not_found", message: "Not in the demo data." } }) });
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto(path);
  await page.locator("main").waitFor();
}

/** Waits for the page to settle, then photographs the viewport. */
async function shoot(page: Page, name: string, theme: "dark" | "light") {
  await expect(page.getByRole("status").filter({ hasText: /loading/i })).toHaveCount(0);
  await page.waitForLoadState("networkidle");
  // Charts and transitions finish drawing.
  await page.waitForTimeout(500);
  expect(unanswered, "requests the demo data does not answer").toEqual([]);
  await page.screenshot({ path: join(OUT, theme === "dark" ? `${name}.png` : `${name}-light.png`), animations: "disabled", caret: "hide" });
}

test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1.5, timezoneId: TIME_ZONE, locale: "en-US", colorScheme: "dark" });

for (const theme of ["dark", "light"] as const) {
  test.describe(theme, () => {
    test.use({ colorScheme: theme });

    test("dashboard", async ({ page }) => {
      await open(page, theme, "/");
      await expect(page.getByText("Needs attention")).toBeVisible();
      await shoot(page, "dashboard", theme);
    });

    test("devices", async ({ page }) => {
      await open(page, theme, "/devices");
      await expect(page.getByRole("link", { name: "HDG-DC01" }).first()).toBeVisible();
      await shoot(page, "devices", theme);
    });

    test("device", async ({ page }) => {
      await open(page, theme, `/devices/${HEALTH_DEVICE}`);
      await expect(page.getByText("Performance")).toBeVisible();
      await shoot(page, "device", theme);
    });

    test("device patches", async ({ page }) => {
      await open(page, theme, `/devices/${PATCH_DEVICE}?tab=patches`);
      await expect(page.getByText(missingUpdates[0]!.title).first()).toBeVisible();
      await shoot(page, "device-patches", theme);
    });

    test("patching", async ({ page }) => {
      await open(page, theme, "/patching?tab=devices");
      await expect(page.getByText("AF-FS01").first()).toBeVisible();
      await shoot(page, "patching", theme);
    });

    test("patching overview", async ({ page }) => {
      await open(page, theme, "/patching");
      await expect(page.getByText("HDG-FRONTDESK-2")).toBeVisible();
      await shoot(page, "patching-overview", theme);
    });

    test("patching update", async ({ page }) => {
      await open(page, theme, `/patching/updates/${UPDATE_GUID}`);
      await expect(page.getByText("CVE-2026-41001")).toBeVisible();
      await shoot(page, "patching-update", theme);
    });

    test("patch policy", async ({ page }) => {
      await open(page, theme, "/organizations/o-harbor?tab=patch-policy");
      await expect(page.getByRole("heading", { name: "Windows Update settings" })).toBeVisible();
      await shoot(page, "patch-policy", theme);
    });

    test("alerts", async ({ page }) => {
      await open(page, theme, "/alerts");
      await expect(page.getByText("Disk space").first()).toBeVisible();
      await shoot(page, "alerts", theme);
    });
  });
}
