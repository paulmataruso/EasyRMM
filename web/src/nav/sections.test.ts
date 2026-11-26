import { describe, expect, it } from "vitest";
import { sectionFor, selectedKey, targetHref } from "./sections";

describe("sections", () => {
  it("knows which section a page belongs to", () => {
    expect(sectionFor("/")).toBeNull();
    expect(sectionFor("/account")).toBeNull();
    expect(sectionFor("/organizations")).toBe("organizations");
    expect(sectionFor("/organizations/o1")).toBe("organizations");
    expect(sectionFor("/groups/g1")).toBe("organizations");
    expect(sectionFor("/sites/s1")).toBe("organizations");
    expect(sectionFor("/devices/d1/remote/desktop")).toBe("devices");
    expect(sectionFor("/devicesx")).toBeNull();
    expect(sectionFor("/alerts")).toBe("alerts");
    expect(sectionFor("/scripts/new")).toBe("scripts");
    expect(sectionFor("/jobs/j1")).toBe("jobs");
    expect(sectionFor("/patching")).toBe("patching");
    expect(sectionFor("/patching/devices/d1")).toBe("patching");
    expect(sectionFor("/settings")).toBe("settings");
    expect(sectionFor("/users/u1")).toBe("settings");
  });

  it("selects the row the page is about", () => {
    expect(selectedKey("organizations", "/organizations", "")).toBe("all");
    expect(selectedKey("organizations", "/organizations/o%201", "")).toBe("o:o 1");
    expect(selectedKey("organizations", "/sites/s1", "")).toBe("s:s1");
    expect(selectedKey("organizations", "/groups/g1", "")).toBe("g:g1");
    expect(selectedKey("organizations", "/organizations/o1/edit", "")).toBeNull();

    expect(selectedKey("devices", "/devices", "")).toBe("all");
    expect(selectedKey("devices", "/devices", "?organizationId=o1")).toBe("o:o1");
    expect(selectedKey("devices", "/devices", "?organizationId=o1&siteId=s1")).toBe("s:s1");
    expect(selectedKey("devices", "/devices/d1", "")).toBe("d:d1");
    expect(selectedKey("devices", "/devices/add", "")).toBeNull();
    expect(selectedKey("devices", "/devices/d1/remote/files", "")).toBeNull();

    expect(selectedKey("alerts", "/alerts", "?organizationId=o1&siteId=s1&deviceId=d1")).toBe("d:d1");
    expect(selectedKey("alerts", "/alerts", "?tab=policies")).toBeNull();
    expect(selectedKey("alerts", "/alerts", "?tab=policies&organizationId=o1")).toBe("o:o1");

    expect(selectedKey("scripts", "/scripts", "")).toBe("all");
    expect(selectedKey("scripts", "/scripts", "?library=shared")).toBe("shared");
    expect(selectedKey("scripts", "/scripts", "?library=o1")).toBe("o:o1");
    expect(selectedKey("scripts", "/scripts", "?library=o1&siteId=s1")).toBe("s:s1");
    expect(selectedKey("scripts", "/scripts/x", "")).toBeNull();

    expect(selectedKey("jobs", "/jobs", "?siteId=s2")).toBe("s:s2");
    expect(selectedKey("jobs", "/jobs/j1", "")).toBeNull();
    expect(selectedKey("patching", "/patching", "")).toBe("all");
    expect(selectedKey("patching", "/patching", "?tab=devices&organizationId=o1")).toBe("o:o1");
    expect(selectedKey("patching", "/patching", "?organizationId=o1&siteId=s1")).toBe("s:s1");
    expect(selectedKey("patching", "/patching", "?organizationId=o1&siteId=s1&groupId=g1")).toBe("g:g1");
    expect(selectedKey("patching", "/patching/devices/d1", "")).toBe("d:d1");
    expect(selectedKey("patching", "/patching/updates/g1", "")).toBeNull();
    expect(selectedKey("settings", "/settings", "")).toBeNull();
  });

  it("leads organizations and sites to their pages", () => {
    expect(targetHref("organizations", { kind: "all" }, "/sites/s1", "")).toBe("/organizations");
    expect(targetHref("organizations", { kind: "org", id: "o 1" }, "/organizations", "")).toBe("/organizations/o%201");
    expect(targetHref("organizations", { kind: "site", id: "s1", organizationId: "o1" }, "/organizations", "")).toBe("/sites/s1");
    expect(targetHref("organizations", { kind: "group", id: "g 1", organizationId: "o1", siteId: "s1" }, "/organizations", "")).toBe("/groups/g%201");
  });

  it("narrows a section's list, keeping its other filters and starting its pages again", () => {
    expect(targetHref("devices", { kind: "device", id: "d1", organizationId: "o1", siteId: "s1" }, "/devices", "")).toBe("/devices/d1");
    expect(targetHref("devices", { kind: "site", id: "s1", organizationId: "o1" }, "/devices", "?status=online&deviceId=d9&after=x")).toBe(
      "/devices?status=online&organizationId=o1&siteId=s1",
    );
    expect(targetHref("devices", { kind: "all" }, "/devices", "?status=online&organizationId=o1&siteId=s1")).toBe("/devices?status=online");
    // From another page of the section, the list opens with only the new scope.
    expect(targetHref("devices", { kind: "org", id: "o1" }, "/devices/d1", "?tab=software")).toBe("/devices?organizationId=o1");

    expect(targetHref("alerts", { kind: "device", id: "d1", organizationId: "o1", siteId: "s1" }, "/alerts", "?severity=critical&before=9")).toBe(
      "/alerts?severity=critical&organizationId=o1&siteId=s1&deviceId=d1",
    );
    // Policies narrow by organization; anything finer shows the alerts.
    expect(targetHref("alerts", { kind: "org", id: "o1" }, "/alerts", "?tab=policies")).toBe("/alerts?tab=policies&organizationId=o1");
    expect(targetHref("alerts", { kind: "site", id: "s1", organizationId: "o1" }, "/alerts", "?tab=policies")).toBe("/alerts?organizationId=o1&siteId=s1");

    expect(targetHref("scripts", { kind: "shared" }, "/scripts", "?q=disk&siteId=s1")).toBe("/scripts?q=disk&library=shared");
    expect(targetHref("scripts", { kind: "org", id: "o1" }, "/scripts", "")).toBe("/scripts?library=o1");
    expect(targetHref("scripts", { kind: "site", id: "s1", organizationId: "o1" }, "/scripts/new", "")).toBe("/scripts?library=o1&siteId=s1");
    expect(targetHref("scripts", { kind: "all" }, "/scripts", "?library=o1&siteId=s1")).toBe("/scripts");

    expect(targetHref("jobs", { kind: "device", id: "d1", organizationId: "o1", siteId: "s1" }, "/jobs/j1", "")).toBe("/jobs?organizationId=o1&siteId=s1&deviceId=d1");

    // Patching: a device has its own page in the section; a group keeps the list, narrowed to it.
    expect(targetHref("patching", { kind: "device", id: "d1", organizationId: "o1", siteId: "s1" }, "/patching", "?tab=updates")).toBe("/patching/devices/d1");
    expect(targetHref("patching", { kind: "group", id: "g1", organizationId: "o1", siteId: "s1" }, "/patching", "?tab=devices")).toBe(
      "/patching?tab=devices&organizationId=o1&siteId=s1&groupId=g1",
    );
    expect(targetHref("patching", { kind: "org", id: "o1" }, "/patching/devices/d1", "")).toBe("/patching?organizationId=o1");
    expect(targetHref("settings", { kind: "all" }, "/settings", "")).toBe("/");
  });
});
