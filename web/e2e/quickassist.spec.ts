// ADR-0080: Quick Assist, in the browser, against the real server and the real agent. The console makes a one-time
// link; the program the link serves is the real agent, run here as the user would run it: it shows a code and asks,
// the technician accepts in the console by typing the code, the computer is listed as active, and ending the session
// from the console makes the program remove its folder and report that it did. Runs after console.spec.ts, which
// leaves the signed-in administrator behind.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, writeFileSync, chmodSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { nextCode } from "./authenticator";

const ADMIN = { email: "alex@example.com", password: "harbor lantern quietly 42" };

let admin: Page;
test.describe.configure({ mode: "serial" });
test.beforeAll(async ({ browser }) => {
  admin = await (await browser.newContext()).newPage();
  await admin.goto("/login");
  await admin.getByLabel(/^Email/).fill(ADMIN.email);
  await admin.getByLabel(/^Password/).fill(ADMIN.password);
  await admin.getByRole("button", { name: "Sign in" }).click();
  await admin.getByLabel(/^Verification code/).fill(await nextCode(admin, ADMIN.email));
  await admin.getByRole("button", { name: "Verify" }).click();
  await expect(admin).toHaveURL(/\/$/);
});
test.afterAll(async () => {
  await admin.context().close();
});

test("a link, the real program, acceptance by the code, the active list, and a verified clean-up", async () => {
  test.setTimeout(120_000);
  const page = admin;
  await page.goto("/quickassist?view=links");
  await expect(page.getByText(/only one-time test links can be made/)).toBeVisible();
  await page.getByRole("button", { name: "New link" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Name the user sees").fill("Support for Northwind");
  await expect(dialog.getByRole("option", { name: /Permanent/ })).toHaveCount(0);
  await dialog.getByRole("button", { name: "Make link" }).click();
  const link = await page.getByRole("textbox", { name: "Link", exact: true }).inputValue();
  await page.getByRole("button", { name: "Done" }).click();

  // The user opens the page, and downloads the program.
  const shown = await page.request.get(link);
  expect(shown.status()).toBe(200);
  expect(await shown.text()).toContain("Support for Northwind");
  const file = await page.request.get(`${link}/download?os=linux`);
  expect(file.status()).toBe(200);
  const dir = mkdtempSync(join(tmpdir(), "qa-e2e-"));
  const exe = join(dir, "easyrmm-quick-assist");
  writeFileSync(exe, await file.body());
  chmodSync(exe, 0o700);
  // A one-time link serves once.
  expect((await page.request.get(`${link}/download?os=linux`)).status()).toBe(404);

  const proc = spawn(exe, ["quick-assist", "--server", new URL(page.url()).origin, "--base-dir", dir, "--poll", "300ms"], { stdio: ["pipe", "pipe", "inherit"] });
  let out = "";
  proc.stdout.on("data", (b: Buffer) => (out += b.toString()));
  const exited = new Promise<number | null>((r) => proc.on("exit", (c) => r(c)));
  await expect.poll(() => /Your session code: (\d{6})/.test(out), { timeout: 30_000 }).toBe(true);
  const code = /Your session code: (\d{6})/.exec(out)?.[1] ?? "";
  proc.stdin.write("YES\n");

  // The technician sees the request, and the code is nowhere on the page.
  await page.goto("/quickassist");
  const row = page.getByRole("row").filter({ hasText: "Support for Northwind" });
  await expect(row).toBeVisible({ timeout: 30_000 });
  await expect(page.locator("body")).not.toContainText(code);
  await row.getByRole("button", { name: /Accept/ }).click();
  const accept = page.getByRole("dialog");
  await accept.getByLabel("Code from the user's screen").fill("000000");
  await accept.getByRole("button", { name: "Accept" }).click();
  await expect(accept.getByText(/Tries left: 2/)).toBeVisible();
  await accept.getByLabel("Code from the user's screen").fill(code);
  await accept.getByRole("button", { name: "Accept" }).click();

  await page.goto("/quickassist?view=active");
  const active = page.getByRole("row").filter({ hasText: "Support for Northwind" });
  await expect(active).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => /accepted/.test(out), { timeout: 30_000 }).toBe(true);
  // The computer is not in the ordinary Devices list.
  await page.goto("/devices");
  await expect(page.getByRole("link", { name: new RegExp(hostname()) })).toHaveCount(0);

  await page.goto("/quickassist?view=active");
  await page.getByRole("button", { name: "End session" }).click();
  expect(await exited).toBe(0);
  expect(readdirSync(dir).filter((n) => n.startsWith("easyrmm-qa-"))).toEqual([]);
  expect(existsSync(exe)).toBe(true); // the user's download is theirs to delete

  await page.goto("/quickassist?view=ended");
  await expect(page.getByText(/Ended by the technician\. Cleaned up, verified\./)).toBeVisible({ timeout: 30_000 });
});
