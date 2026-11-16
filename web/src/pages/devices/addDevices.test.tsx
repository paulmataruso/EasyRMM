import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { EnrollmentToken, EnrollmentTokenInput } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { group, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { addressLabel, archName, byArch, formatBytes, linuxInstallCommand, windowsInstallCommand } from "./AddDevicesPage";

const TLS12 = "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072";

const ADMIN = sessionView({ permissions: [...sessionView().permissions, "enrollment.manage", "device.view"] });
const SECRET = "ert_AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIIIjjjjKKK";
const SHA = "9f2c4e1a7b3d5f60819a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70";

function token(id: string, name: string, extra: Partial<EnrollmentToken> = {}): EnrollmentToken {
  return {
    id,
    organizationId: "o1",
    organizationName: "Northwind Traders",
    siteId: "s1",
    siteName: "Head office",
    deviceGroupId: null,
    name,
    expiresAt: "2030-01-01T00:00:00Z",
    maxUses: null,
    uses: 0,
    createdByName: "Alex Rivera",
    createdAt: "2026-11-01T10:00:00Z",
    lastUsedAt: null,
    revokedAt: null,
    status: "active",
    ...extra,
  };
}

const TOKENS = [token("t1", "Head office rollout", { uses: 3, maxUses: 10 }), token("t2", "Old laptops", { status: "used_up", uses: 5, maxUses: 5 })];

/** Routes the deployment page needs, answering the token list the way the server filters. */
function routes(extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(ADMIN),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office"), site("s2", "o1", "Warehouse"), site("s3", "o2", "Clinic", { organizationName: "Contoso Dental Group" })] }),
    "GET /sites/:id/device-groups": (r: FakeRequest) => ok({ items: r.params.id === "s2" ? [group("g1", "s2", "Scanners")] : [] }),
    "GET /agent-downloads": ok({
      serverUrl: "https://rmm.example.com",
      items: [{ os: "linux", arch: "amd64", file: "easyrmm-agent-linux-amd64", size: 7_065_760, sha256: SHA }],
    }),
    "GET /enrollment-tokens": (r: FakeRequest) => ok({ items: TOKENS.filter((t) => r.query.get("status") !== "active" || t.status === "active") }),
    ...extra,
  };
}

describe("add devices", () => {
  it("creates a deployment token and shows the install command once", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes({
        "POST /sites/:id/enrollment-tokens": (r: FakeRequest) => {
          const input = r.body as EnrollmentTokenInput;
          return {
            status: 201,
            body: {
              token: token("t3", input.name, { siteId: "s2", siteName: "Warehouse", deviceGroupId: "g1", deviceGroupName: "Scanners", maxUses: input.maxUses }),
              secret: SECRET,
              serverUrl: "https://rmm.example.com",
            },
          };
        },
      }),
    );
    // Arriving from a site page picks the site.
    renderApp("/devices/add?siteId=s2");
    const siteField = await screen.findByLabelText(/^Site/);
    expect(siteField).toHaveValue("s2");
    // Sites are grouped by organization.
    expect(within(siteField).getByRole("group", { name: "Contoso Dental Group" })).toBeInTheDocument();

    await waitFor(() => expect(within(screen.getByLabelText(/Device group/)).getAllByRole("option").map((o) => o.textContent)).toEqual(["None", "Scanners"]));
    await user.selectOptions(screen.getByLabelText(/Device group/), "g1");
    await user.type(screen.getByLabelText(/Token name/), "  Warehouse scanners ");
    await user.selectOptions(screen.getByLabelText("Expires after"), "30");
    await user.type(screen.getByLabelText("Device limit"), "25");
    await user.click(screen.getByRole("button", { name: "Create token" }));

    expect(await screen.findByText("Copy the command now. The token is not shown again.")).toBeInTheDocument();
    const create = server.call("POST /sites/:id/enrollment-tokens");
    expect(create.params.id).toBe("s2");
    expect(create.body).toEqual({ name: "Warehouse scanners", deviceGroupId: "g1", expiresInDays: 30, maxUses: 25 });
    // Windows first: the PowerShell command.
    expect(screen.getByRole("radio", { name: "Windows" })).toBeChecked();
    expect(screen.getByText("Windows PowerShell")).toBeInTheDocument();
    expect(
      screen.getByText(
        `${TLS12}; & ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://rmm.example.com/api/agent/v1/install.ps1'))) -Token '${SECRET}'`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/easyrmm-agent\.exe install --server https:\/\/rmm\.example\.com/)).toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: "Linux" }));
    expect(
      screen.getByText(
        `export EASYRMM_TOKEN='${SECRET}'; curl -fsSL https://rmm.example.com/api/agent/v1/install.sh | sudo --preserve-env=EASYRMM_TOKEN sh; unset EASYRMM_TOKEN`,
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/install\.ps1/)).not.toBeInTheDocument();
    expect(screen.getByText("Northwind Traders / Warehouse")).toBeInTheDocument();
    expect(screen.getByText("25")).toBeInTheDocument();
    // The token list was refreshed.
    await waitFor(() => expect(server.callsTo("GET /enrollment-tokens").length).toBeGreaterThan(1));

    await user.click(screen.getByRole("button", { name: "Create another token" }));
    expect(screen.queryByText(SECRET, { exact: false })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create token" })).toBeInTheDocument();
  });

  it("shows the server's objections next to the fields", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes({ "POST /sites/:id/enrollment-tokens": fail(400, "validation_failed", "The request is invalid.", { maxUses: "Choose between 1 and 100,000 devices, or no limit." }) }),
    );
    renderApp("/devices/add");
    const create = await screen.findByRole("button", { name: "Create token" });
    // Nothing to send until a site and a name are chosen.
    expect(create).toBeDisabled();
    await user.selectOptions(screen.getByLabelText(/^Site/), "s1");
    await user.type(screen.getByLabelText(/Token name/), "Lab");
    await user.click(create);
    expect(await screen.findByText("Choose between 1 and 100,000 devices, or no limit.")).toBeInTheDocument();
    // No limit and no group are sent as null.
    expect(server.call("POST /sites/:id/enrollment-tokens").body).toEqual({ name: "Lab", deviceGroupId: null, expiresInDays: 7, maxUses: null });
  });

  it("offers the server's IP address, with a pinned command and its certificate authority", async () => {
    const user = userEvent.setup();
    const PIN = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    const KEY_PIN = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
    const FINGERPRINT = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
    installFakeApi(
      routes({
        "GET /agent-downloads": ok({
          serverUrl: "https://rmm.example.com",
          items: [],
          addresses: [{ url: "https://rmm.example.com" }, { url: "https://203.0.113.10", pin: PIN, keyPin: KEY_PIN }],
          // This console was opened at the IP address.
          current: "https://203.0.113.10",
          certificateAuthority: { fingerprint: FINGERPRINT, url: "/api/agent/v1/ca.pem", certUrl: "/api/agent/v1/easyrmm-ca.crt" },
        }),
        "POST /sites/:id/enrollment-tokens": () => ({
          status: 201,
          body: { token: token("t3", "Lab", { siteId: "s1", siteName: "Head office" }), secret: SECRET, serverUrl: "https://rmm.example.com" },
        }),
      }),
    );
    renderApp("/devices/add");
    // The certificate authority, to check and install.
    expect(await screen.findByText(FINGERPRINT)).toBeInTheDocument();
    // A .crt Windows installs from its context menu, and the PEM beside it.
    expect(screen.getByRole("link", { name: "Download easyrmm-ca.crt" })).toHaveAttribute("href", "/api/agent/v1/easyrmm-ca.crt");
    expect(screen.getByRole("link", { name: "easyrmm-ca.pem" })).toHaveAttribute("href", "/api/agent/v1/ca.pem");
    expect(screen.getByText("Trusted Root Certification Authorities")).toBeInTheDocument();
    expect(screen.getByText(/Import-Certificate -FilePath \.\\easyrmm-ca\.crt -CertStoreLocation Cert:\\LocalMachine\\Root/)).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText(/^Site/), "s1");
    await user.type(screen.getByLabelText(/Token name/), "Lab");
    await user.click(screen.getByRole("button", { name: "Create token" }));
    const address = await screen.findByLabelText(/Server address/);
    expect(within(address).getAllByRole("option").map((o) => o.textContent)).toEqual(["rmm.example.com", "203.0.113.10 (IP address)"]);
    // The address the console was opened at comes first.
    expect(address).toHaveValue("https://203.0.113.10");
    // Windows: the download trusts the server's key, then the callback is removed.
    const ps = screen.getByText(/ServerCertificateValidationCallback/).textContent ?? "";
    expect(ps).toContain(`-eq '${KEY_PIN}' }`);
    expect(ps).toContain("DownloadString('https://203.0.113.10/api/agent/v1/install.ps1') } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $null }");
    expect(ps).toMatch(new RegExp(`-Token '${SECRET}'$`));
    expect(screen.getByText(/PowerShell 7 cannot run this check/)).toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: "Linux" }));
    expect(
      screen.getByText(
        `export EASYRMM_TOKEN='${SECRET}'; curl -fsSL --insecure --pinnedpubkey '${PIN}' https://203.0.113.10/api/agent/v1/install.sh | sudo --preserve-env=EASYRMM_TOKEN sh; unset EASYRMM_TOKEN`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/checks the server's public key instead/)).toBeInTheDocument();
    expect(screen.getByText(/--ca-file easyrmm-ca.pem/)).toBeInTheDocument();

    await user.selectOptions(address, "https://rmm.example.com");
    expect(
      screen.getByText(
        `export EASYRMM_TOKEN='${SECRET}'; curl -fsSL https://rmm.example.com/api/agent/v1/install.sh | sudo --preserve-env=EASYRMM_TOKEN sh; unset EASYRMM_TOKEN`,
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/--ca-file easyrmm-ca.pem/)).not.toBeInTheDocument();
  });

  it("lists agent downloads with their checksums", async () => {
    installFakeApi(routes());
    renderApp("/devices/add");
    expect(await screen.findByText("Linux x86-64")).toBeInTheDocument();
    expect(screen.getByText("6.7 MB")).toBeInTheDocument();
    expect(screen.getByText(SHA)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download easyrmm-agent-linux-amd64" })).toHaveAttribute("href", "/api/agent/v1/download/easyrmm-agent-linux-amd64");
    expect(screen.getByRole("link", { name: "SHA256SUMS" })).toHaveAttribute("href", "/api/agent/v1/download/SHA256SUMS");
  });

  it("says when the server has no agents to hand out", async () => {
    installFakeApi(routes({ "GET /agent-downloads": ok({ serverUrl: "https://rmm.example.com", items: [] }) }));
    renderApp("/devices/add");
    expect(await screen.findByText("No agents on this server")).toBeInTheDocument();
    expect(screen.getByText("make build-agents")).toBeInTheDocument();
    // One address and no certificate authority: nothing to choose or install.
    expect(screen.queryByText("Server certificate authority")).not.toBeInTheDocument();
  });

  it("lists tokens and revokes one", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes({ "POST /enrollment-tokens/:id/revoke": (r: FakeRequest) => ok(token(r.params.id ?? "", "Head office rollout", { status: "revoked" })) }));
    renderApp("/devices/add");
    const row = await screen.findByRole("row", { name: /Head office rollout/ });
    expect(within(row).getByText("3 of 10")).toBeInTheDocument();
    expect(within(row).getByText("Usable")).toBeInTheDocument();
    // Usable tokens only, until asked for all.
    expect(screen.queryByText("Old laptops")).not.toBeInTheDocument();
    expect(server.call("GET /enrollment-tokens").query.get("status")).toBe("active");
    await user.selectOptions(screen.getByLabelText("Which deployment tokens"), "all");
    const used = await screen.findByRole("row", { name: /Old laptops/ });
    expect(within(used).getByText("Used up")).toBeInTheDocument();
    expect(within(used).queryByRole("button", { name: /Revoke/ })).not.toBeInTheDocument();
    expect(server.callsTo("GET /enrollment-tokens").at(-1)?.query.get("status")).toBeNull();

    await user.click(within(row).getByRole("button", { name: "Revoke Head office rollout" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke deployment token" });
    expect(within(dialog).getByText(/Devices that already enrolled with it keep working/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Revoke token" }));
    expect(await screen.findByText("Token “Head office rollout” revoked.")).toBeInTheDocument();
    expect(server.call("POST /enrollment-tokens/:id/revoke").params.id).toBe("t1");
  });

  it("is closed to roles that do not manage enrollment", async () => {
    installFakeApi({ ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] })) });
    renderApp("/devices/add");
    expect(await screen.findByText("Not available to your role")).toBeInTheDocument();
  });

  it("is offered from a site page", async () => {
    installFakeApi({
      ...routes(),
      "GET /sites/:id": ok(site("s2", "o1", "Warehouse")),
      "GET /organizations/:id": ok({ id: "o1", name: "Northwind Traders", notes: "", siteCount: 2, canManage: true, createdAt: "2026-11-01T10:00:00Z", updatedAt: "2026-11-01T10:00:00Z" }),
    });
    renderApp("/sites/s2");
    expect(await screen.findByRole("link", { name: "Add devices" })).toHaveAttribute("href", "/devices/add?siteId=s2");
  });
});

describe("deployment helpers", () => {
  it("formats sizes, architectures and the install command", () => {
    expect([formatBytes(512), formatBytes(2048), formatBytes(7_065_760)]).toEqual(["512 B", "2.0 KB", "6.7 MB"]);
    expect([archName("amd64"), archName("arm"), archName("riscv64")]).toEqual(["x86-64", "ARMv7 32-bit", "riscv64"]);
    const b = (arch: string, os = "linux") => ({ os, arch, file: `easyrmm-agent-${os}-${arch}`, size: 1, sha256: "", version: "" });
    expect([b("386"), b("riscv64"), b("arm"), b("arm64", "windows"), b("amd64", "windows"), b("amd64"), b("arm64")].sort(byArch).map((x) => x.file)).toEqual([
      "easyrmm-agent-windows-amd64",
      "easyrmm-agent-windows-arm64",
      "easyrmm-agent-linux-amd64",
      "easyrmm-agent-linux-arm64",
      "easyrmm-agent-linux-arm",
      "easyrmm-agent-linux-386",
      "easyrmm-agent-linux-riscv64",
    ]);
    expect(windowsInstallCommand("https://rmm.example.com", "ert_x")).toBe(
      `${TLS12}; & ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://rmm.example.com/api/agent/v1/install.ps1'))) -Token 'ert_x'`,
    );
    expect(windowsInstallCommand("https://203.0.113.10", "ert_x", "ABC123")).toBe(
      [
        TLS12,
        "[Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s, $c) ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.GetPublicKey())) -replace '-') -eq 'ABC123' }",
        "try { $i = (New-Object Net.WebClient).DownloadString('https://203.0.113.10/api/agent/v1/install.ps1') } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $null }",
        "& ([scriptblock]::Create($i)) -Token 'ert_x'",
      ].join("; "),
    );
    expect(linuxInstallCommand("https://rmm.example.com", "ert_x")).toBe(
      "export EASYRMM_TOKEN='ert_x'; curl -fsSL https://rmm.example.com/api/agent/v1/install.sh | sudo --preserve-env=EASYRMM_TOKEN sh; unset EASYRMM_TOKEN",
    );
    expect(linuxInstallCommand("https://[2001:db8::10]", "ert_x", "sha256//p=")).toBe(
      "export EASYRMM_TOKEN='ert_x'; curl -fsSL --insecure --pinnedpubkey 'sha256//p=' https://[2001:db8::10]/api/agent/v1/install.sh | sudo --preserve-env=EASYRMM_TOKEN sh; unset EASYRMM_TOKEN",
    );
    expect([addressLabel({ url: "https://rmm.example.com" }, true), addressLabel({ url: "https://[2001:db8::10]:8443" }, false)]).toEqual([
      "rmm.example.com",
      "[2001:db8::10]:8443 (IP address)",
    ]);
  });
});
