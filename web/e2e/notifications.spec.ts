// ADR-0053, slice 3: notification channels in the browser, against the real server and database. A super
// administrator adds a platform webhook to a receiver of their own (an HTTPS server this spec starts, trusted through
// the channel's certificate authority), tests it, and the receiver gets a request signed with the secret the console
// shows again. An organization's administrator adds an email channel and a webhook to a loopback address, which the
// address policy refuses for an organization, in EasyRMM's own words.

import { createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { nextCode } from "./authenticator";

const ADMIN = { email: "alex@example.com", password: "harbor lantern quietly 42" };

interface Received {
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

let admin: Page;
let receiver: Server;
let authority = "";
let port = 0;
const received: Received[] = [];

test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ browser }) => {
  // A receiver with a certificate of its own, which is its own authority.
  const dir = mkdtempSync(join(tmpdir(), "easyrmm-e2e-hook-"));
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
    "-subj", "/CN=receiver", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"),
    "-addext", "subjectAltName=IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
  ], { stdio: "ignore" });
  authority = readFileSync(join(dir, "cert.pem"), "utf8");
  receiver = createServer({ key: readFileSync(join(dir, "key.pem")), cert: authority }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      received.push({ path: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(204).end();
    });
  });
  await new Promise<void>((resolve) => receiver.listen(0, "127.0.0.1", resolve));
  const addr = receiver.address();
  port = typeof addr === "object" && addr ? addr.port : 0;

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
  await new Promise((resolve) => receiver.close(resolve));
});

test("a platform webhook is added, tested, received signed, and its secret shown again", async () => {
  const page = admin;
  await page.goto("/settings?tab=notifications");
  await page.getByRole("button", { name: /Add channel/ }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Kind").selectOption("webhook");
  await dialog.getByLabel(/^Name/).fill("E2E receiver");
  await dialog.getByLabel(/^Web address/).fill(`https://127.0.0.1:${port}/hook?token=e2e-secret-token`);
  await dialog.getByLabel(/^Certificate authority/).fill(authority);
  await dialog.getByRole("button", { name: "Add channel" }).click();
  await expect(page.getByRole("cell", { name: /^E2E receiver/ })).toBeVisible();
  // The list shows the host, never the address's path or query.
  await expect(page.getByText("e2e-secret-token")).toHaveCount(0);

  await page.getByRole("button", { name: "Test E2E receiver" }).click();
  await expect(page.getByText("Test sent")).toBeVisible({ timeout: 30_000 });
  expect(received).toHaveLength(1);
  const req = received[0]!;
  expect(req.path).toBe("/hook?token=e2e-secret-token");
  expect(req.headers["x-easyrmm-event"]).toBe("test");

  await page.getByRole("button", { name: "Show secret of E2E receiver" }).click();
  const secrets = page.getByRole("dialog");
  await expect(secrets.getByText(`https://127.0.0.1:${port}/hook?token=e2e-secret-token`)).toBeVisible();
  const secret = (await secrets.locator("div:has(> div:text-is('Signing secret')) .font-mono").first().innerText()).trim();
  const [t, v1] = String(req.headers["x-easyrmm-signature"]).split(",").map((p) => p.slice(p.indexOf("=") + 1));
  expect(createHmac("sha256", secret).update(`${t}.${req.body}`).digest("hex")).toBe(v1);
  await secrets.getByRole("button", { name: "Close" }).last().click(); // the footer's, not the corner X

  // Tested again at once: the server's own limit of one test every 30 seconds answers, in the engine's words.
  await page.getByRole("button", { name: "Test E2E receiver" }).click();
  await expect(page.getByText(/less than 30 seconds ago/)).toBeVisible();
});

test("an organization's administrator adds an email channel, and a loopback webhook is refused for it", async () => {
  const page = admin;
  await page.goto("/organizations");
  await page.getByRole("link", { name: "Northwind Traders" }).first().click();
  await page.getByRole("tab", { name: "Notifications" }).click();

  await page.getByRole("button", { name: /Add channel/ }).click();
  let dialog = page.getByRole("dialog");
  await dialog.getByLabel(/^Name/).fill("Service desk");
  await dialog.getByLabel(/^Recipients/).fill("desk@example.com, lead@example.com");
  await dialog.getByRole("button", { name: "Add channel" }).click();
  await expect(page.getByRole("cell", { name: /^Service desk/ })).toBeVisible();
  await expect(page.getByText("2 recipients")).toBeVisible();

  // No mail server runs in this suite: the test says so, and the message waits.
  await page.getByRole("button", { name: "Test Service desk" }).click();
  await expect(page.getByText(/no mail server/i)).toBeVisible({ timeout: 30_000 });

  await page.getByRole("button", { name: /Add channel/ }).click();
  dialog = page.getByRole("dialog");
  await dialog.getByLabel("Kind").selectOption("webhook");
  await dialog.getByLabel(/^Name/).fill("Loopback hook");
  await dialog.getByLabel(/^Web address/).fill(`https://127.0.0.1:${port}/hook`);
  await dialog.getByLabel(/^Certificate authority/).fill(authority);
  await dialog.getByRole("button", { name: "Add channel" }).click();
  await expect(page.getByRole("cell", { name: /^Loopback hook/ })).toBeVisible();
  const before = received.length;
  await page.getByRole("button", { name: "Test Loopback hook" }).click();
  await expect(page.getByText(/does not connect to 127\.0\.0\.1/).first()).toBeVisible({ timeout: 30_000 });
  // Nothing reached the receiver: the policy refused it after name resolution, before any connection.
  expect(received).toHaveLength(before);
});
