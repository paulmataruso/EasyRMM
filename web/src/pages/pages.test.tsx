import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, type FakeRequest } from "../test/fakeApi";
import { auditEntry, group, org, person, ROLES, sessionItem, site } from "../test/fixtures";
import { renderApp } from "../test/render";

const location = () => screen.getByTestId("location").textContent;
const dialog = (name: string) => screen.findByRole("dialog", { name });

const ORGS = [org("o1", "Northwind Traders", { siteCount: 2 }), org("o2", "Contoso Dental Group", { notes: "Three clinics." }), org("o3", "Fabrikam Logistics")];

/** Detail endpoints that row hover/focus prefetches; any org or site id resolves. */
const detailRoutes = {
  "GET /organizations/:id": (r: FakeRequest) => ok(ORGS.find((o) => o.id === r.params.id) ?? org(r.params.id ?? "", "New org")),
  "GET /organizations/:id/sites": ok({ items: [] }),
  "GET /sites/:id": (r: FakeRequest) => ok(site(r.params.id ?? "", "o1", "Head office")),
  "GET /sites/:id/device-groups": ok({ items: [] }),
  "GET /users/:id": (r: FakeRequest) => ok(person(r.params.id ?? "", "Sam Okafor", "sam@example.com")),
};

describe("organizations", () => {
  it("filters the list as you type and keeps the query in the URL", async () => {
    const user = userEvent.setup();
    installFakeApi({ ...baseRoutes(sessionView()), "GET /organizations": ok({ items: ORGS }), ...detailRoutes });
    renderApp("/organizations");
    expect(await screen.findByRole("link", { name: "Northwind Traders" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Search"), "dental");
    expect(screen.queryByRole("link", { name: "Northwind Traders" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Contoso Dental Group" })).toBeInTheDocument();
    expect(screen.getByText("1 of 3 organizations")).toBeInTheDocument();
    expect(location()).toBe("/organizations?q=dental");

    await user.clear(screen.getByLabelText("Search"));
    await user.type(screen.getByLabelText("Search"), "zzz");
    expect(screen.getByText("No organizations match your search")).toBeInTheDocument();
  });

  it("moves between rows with j and k", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...baseRoutes(sessionView()), "GET /organizations": ok({ items: ORGS }), ...detailRoutes });
    renderApp("/organizations");
    await screen.findByRole("link", { name: "Northwind Traders" });
    await user.keyboard("j");
    expect(screen.getByRole("link", { name: "Northwind Traders" })).toHaveFocus();
    await user.keyboard("jj");
    expect(screen.getByRole("link", { name: "Fabrikam Logistics" })).toHaveFocus();
    await user.keyboard("j");
    expect(screen.getByRole("link", { name: "Fabrikam Logistics" })).toHaveFocus();
    await user.keyboard("k");
    expect(screen.getByRole("link", { name: "Contoso Dental Group" })).toHaveFocus();
    // Focus warms the detail view so Enter opens it without a spinner.
    await waitFor(() => expect(server.callsTo("GET /organizations/:id").map((c) => c.params.id)).toContain("o2"));
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("heading", { name: "Contoso Dental Group" })).toBeInTheDocument();
    expect(location()).toBe("/organizations/o2");
  });

  it("creates an organization and opens it", async () => {
    const user = userEvent.setup();
    let created = false;
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /organizations": () => ok({ items: created ? [...ORGS, org("o9", "Tailspin Toys")] : ORGS }),
      "POST /organizations": (r) => {
        const body = r.body as { name: string };
        if (body.name === "Northwind Traders") return fail(409, "conflict", "That name is already used.", { name: "Another organization already has this name." });
        created = true;
        return { status: 201, body: org("o9", body.name) };
      },
      "GET /sites": ok({ items: [] }),
      "GET /audit": ok({ items: [] }),
      ...detailRoutes,
    });
    renderApp("/organizations");
    await user.click(await screen.findByRole("button", { name: "New organization" }));
    const form = await dialog("New organization");
    expect(location()).toBe("/organizations?new=1");

    await user.type(within(form).getByLabelText(/^Name/), "Northwind Traders");
    await user.click(within(form).getByRole("button", { name: "Create organization" }));
    expect(await within(form).findByText("Another organization already has this name.")).toBeInTheDocument();

    await user.clear(within(form).getByLabelText(/^Name/));
    await user.type(within(form).getByLabelText(/^Name/), "  Tailspin Toys ");
    await user.type(within(form).getByLabelText(/^Notes/), "Onboarding in progress.");
    await user.click(within(form).getByRole("button", { name: "Create organization" }));
    expect(await screen.findByText("Organization “Tailspin Toys” created.")).toBeInTheDocument();
    await waitFor(() => expect(location()).toBe("/organizations/o9"));
    expect(server.call("POST /organizations", 1).body).toEqual({ name: "Tailspin Toys", notes: "Onboarding in progress." });
  });

  it("does not offer creation to people without org.create", async () => {
    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view"] })),
      "GET /organizations": ok({ items: [] }),
    });
    renderApp("/organizations?new=1");
    expect(await screen.findByText(/You have not been given access to any organization yet/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /organization/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("deletes an organization only after its name is typed", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /organizations/:id": ok(ORGS[2]),
      "GET /organizations/:id/sites": ok({ items: [] }),
      "DELETE /organizations/:id": noContent,
      "GET /organizations": ok({ items: ORGS.slice(0, 2) }),
    });
    renderApp("/organizations/o3");
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    const confirm = await dialog("Delete organization");
    const submit = within(confirm).getByRole("button", { name: "Delete organization" });
    expect(submit).toBeDisabled();
    await user.type(within(confirm).getByLabelText(/Type .* to confirm/), "Fabrikam");
    expect(submit).toBeDisabled();
    await user.type(within(confirm).getByLabelText(/Type .* to confirm/), " Logistics");
    await user.click(submit);
    await waitFor(() => expect(location()).toBe("/organizations"));
    expect(server.callsTo("DELETE /organizations/:id")).toHaveLength(1);
    expect(await screen.findByText("Organization “Fabrikam Logistics” deleted.")).toBeInTheDocument();
  });

  it("explains why a non-empty organization cannot be deleted", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(sessionView()),
      ...detailRoutes,
      "GET /organizations/:id": ok(ORGS[0]),
      "GET /organizations/:id/sites": ok({ items: [site("s1", "o1", "Head office")] }),
      "DELETE /organizations/:id": fail(409, "organization_not_empty", "Delete the organization's sites first."),
    });
    renderApp("/organizations/o1");
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    const confirm = await dialog("Delete organization");
    await user.type(within(confirm).getByLabelText(/Type .* to confirm/), "Northwind Traders");
    await user.click(within(confirm).getByRole("button", { name: "Delete organization" }));
    expect(await within(confirm).findByText("Delete the organization's sites first.")).toBeInTheDocument();
    expect(location()).toBe("/organizations/o1");
  });
});

describe("sites and device groups", () => {
  it("adds a device group to a site", async () => {
    const user = userEvent.setup();
    let groups = [group("g1", "s1", "Servers")];
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /sites/:id": ok(site("s1", "o1", "Head office", { deviceGroupCount: 1 })),
      "GET /organizations/:id": ok(ORGS[0]),
      "GET /sites/:id/device-groups": () => ok({ items: groups }),
      "POST /sites/:id/device-groups": (r) => {
        const g = group("g2", "s1", (r.body as { name: string }).name);
        groups = [...groups, g];
        return { status: 201, body: g };
      },
    });
    renderApp("/sites/s1");
    expect(await screen.findByRole("heading", { name: "Head office" })).toBeInTheDocument();
    // Breadcrumb and details both lead back to the organization.
    for (const link of screen.getAllByRole("link", { name: "Northwind Traders" })) expect(link).toHaveAttribute("href", "/organizations/o1");
    await user.click(screen.getByRole("button", { name: "Add device group" }));
    const form = await dialog("New device group");
    await user.type(within(form).getByLabelText(/^Name/), "Workstations");
    await user.click(within(form).getByRole("button", { name: "Create device group" }));
    expect(await screen.findByRole("cell", { name: "Workstations" })).toBeInTheDocument();
    expect(server.call("POST /sites/:id/device-groups").body).toEqual({ name: "Workstations", description: "" });
  });
});

describe("users and invitations", () => {
  const routes = {
    ...baseRoutes(sessionView()),
    "GET /users": ok({ items: [person("u-alex", "Alex Rivera", "alex@example.com", { isSelf: true }), person("u-sam", "Sam Okafor", "sam@example.com", { passwordSet: false, lastLoginAt: null })] }),
    "GET /organizations": ok({ items: ORGS }),
    "GET /roles": ok({ items: ROLES }),
    "GET /sites": (r: FakeRequest) => ok({ items: r.query.get("organizationId") === "o1" ? [site("s1", "o1", "Head office")] : [] }),
    "GET /audit": ok({ items: [] }),
    ...detailRoutes,
  };

  it("shows a one-time invitation link when the server cannot email it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes,
      "POST /users": ok({ user: person("u-new", "Riley Chen", "riley@example.com"), link: "https://rmm.example.com/welcome#token=abc", emailed: false }),
    });
    renderApp("/settings");
    expect(await screen.findByRole("link", { name: "Sam Okafor" })).toBeInTheDocument();
    expect(screen.getByText("Invited")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Invite user" }));
    const form = await dialog("Invite user");
    const send = within(form).getByRole("button", { name: "Send invitation" });
    await user.type(within(form).getByLabelText(/^Email/), "riley@example.com");
    await user.type(within(form).getByLabelText(/^Name/), "Riley Chen");
    expect(send).toBeDisabled();
    await user.selectOptions(within(form).getByLabelText("Role"), "technician");
    await user.selectOptions(within(form).getByLabelText("Organization"), "o1");
    await user.selectOptions(await within(form).findByLabelText("Site"), "s1");
    await user.click(send);

    const notice = await dialog("Send this invitation link");
    expect(within(notice).getByText("https://rmm.example.com/welcome#token=abc")).toBeInTheDocument();
    expect(within(notice).getByText(/shown only once/)).toBeInTheDocument();
    // Escape must not throw the link away before it is copied.
    expect(within(notice).queryByRole("button", { name: "Close" })).not.toBeInTheDocument();
    expect(server.call("POST /users").body).toEqual({
      email: "riley@example.com",
      displayName: "Riley Chen",
      assignments: [{ role: "technician", organizationId: "o1", siteId: "s1" }],
    });
    await user.click(within(notice).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("puts a server's assignment error on the row it belongs to", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...routes,
      "POST /users": fail(400, "validation_failed", "The request is invalid.", { "assignments.0": "You cannot grant a role above your own." }),
    });
    renderApp("/settings?invite=1");
    const form = await dialog("Invite user");
    await user.type(within(form).getByLabelText(/^Email/), "riley@example.com");
    await user.type(within(form).getByLabelText(/^Name/), "Riley Chen");
    await user.selectOptions(await within(form).findByLabelText("Role"), "org_admin");
    await user.selectOptions(within(form).getByLabelText("Organization"), "o2");
    await user.click(within(form).getByRole("button", { name: "Send invitation" }));
    expect(await within(form).findAllByText("You cannot grant a role above your own.")).toHaveLength(1);
  });

  it("offers super administrator only to super administrators", async () => {
    installFakeApi({
      ...routes,
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "user.view", "user.manage"] })),
    });
    renderApp("/settings?invite=1");
    const form = await dialog("Invite user");
    const role = await within(form).findByLabelText("Role");
    await waitFor(() => expect(within(role).getAllByRole("option").length).toBeGreaterThan(1));
    expect(within(role).queryByRole("option", { name: "Super Administrator" })).not.toBeInTheDocument();
  });
});

describe("user detail", () => {
  it("disables a user after confirmation", async () => {
    const user = userEvent.setup();
    let status: "active" | "disabled" = "active";
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /users/:id": () => ok(person("u-sam", "Sam Okafor", "sam@example.com", { status })),
      "POST /users/:id/disable": () => {
        status = "disabled";
        return ok(person("u-sam", "Sam Okafor", "sam@example.com", { status }));
      },
      "GET /roles": ok({ items: ROLES }),
      "GET /organizations": ok({ items: ORGS }),
      "GET /sites": ok({ items: [] }),
      "GET /users": ok({ items: [] }),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/users/u-sam");
    await user.click(await screen.findByRole("button", { name: "Disable" }));
    const confirm = await screen.findByRole("dialog");
    await user.click(within(confirm).getByRole("button", { name: /Disable/ }));
    expect(await screen.findByText("Sam Okafor is disabled and has been signed out.")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Enable" })).toBeInTheDocument();
    expect(server.callsTo("POST /users/:id/disable")).toHaveLength(1);
  });

  it("keeps people from managing their own account here", async () => {
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /users/:id": ok(person("u-alex", "Alex Rivera", "alex@example.com", { isSelf: true })),
      "GET /roles": ok({ items: ROLES }),
      "GET /organizations": ok({ items: ORGS }),
      "GET /sites": ok({ items: [] }),
    });
    renderApp("/users/u-alex");
    expect(await screen.findByText(/This is your account/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Disable" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
  });
});

describe("audit log", () => {
  it("filters by area and verifies the hash chain", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /audit": (r) =>
        ok({ items: r.query.get("action") === "user" ? [auditEntry(2, "user.invite")] : [auditEntry(1, "organization.create", { organizationId: "o1" }), auditEntry(2, "user.invite")] }),
      "GET /audit/verify": ok({ checked: 2 }),
      "GET /organizations": ok({ items: ORGS }),
    });
    renderApp("/settings?tab=audit");
    expect(await screen.findByText("Created organization")).toBeInTheDocument();
    expect(screen.getByText("Created organization")).toHaveAttribute("title", "organization.create");
    expect(screen.getByRole("link", { name: "Northwind Traders" })).toHaveAttribute("href", "/organizations/o1");

    await user.selectOptions(screen.getByLabelText("Area"), "Users");
    await waitFor(() => expect(screen.queryByText("Created organization")).not.toBeInTheDocument());
    expect(location()).toBe("/settings?tab=audit&action=user");

    await user.click(screen.getByRole("button", { name: "Verify integrity" }));
    expect(await screen.findByText("Intact: 2 entries checked, none altered or removed.")).toBeInTheDocument();
    expect(server.call("GET /audit/verify").query.get("limit")).toBe("1000000");
  });

  it("says where the chain breaks", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /audit": ok({ items: [auditEntry(1, "user.login")] }),
      "GET /audit/verify": ok({ checked: 40, firstBadId: 17 }),
      "GET /organizations": ok({ items: [] }),
    });
    renderApp("/settings?tab=audit");
    await user.click(await screen.findByRole("button", { name: "Verify integrity" }));
    expect(await screen.findByText("The audit log has been altered")).toBeInTheDocument();
    expect(screen.getByText(/Entry #17 does not match the chain/)).toBeInTheDocument();
  });
});

describe("account", () => {
  const routes = {
    ...baseRoutes(sessionView()),
    "GET /auth/sessions": ok({ items: [sessionItem("s-me", { current: true }), sessionItem("s-old", { userAgent: "Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/133.0" })] }),
  };

  it("changes the password", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...routes, "POST /auth/password": noContent, "GET /audit": ok({ items: [] }) });
    renderApp("/account");
    const card = (await screen.findByRole("heading", { name: "Password" })).closest("section") ?? document.body;
    const change = within(card as HTMLElement).getByRole("button", { name: "Change password" });
    await user.type(screen.getByLabelText(/^Current password/), "old password value");
    await user.type(screen.getByLabelText(/^New password/), "a brand new passphrase");
    await user.type(screen.getByLabelText(/^Confirm new password/), "a brand new passphrasx");
    expect(change).toBeDisabled();
    await user.clear(screen.getByLabelText(/^Confirm new password/));
    await user.type(screen.getByLabelText(/^Confirm new password/), "a brand new passphrase");
    await user.click(change);
    expect(await screen.findByText("Password changed. Your other sessions were signed out.")).toBeInTheDocument();
    expect(server.call("POST /auth/password").body).toEqual({ currentPassword: "old password value", newPassword: "a brand new passphrase" });
    expect(screen.getByLabelText(/^Current password/)).toHaveValue("");
  });

  it("lists sessions and signs another one out", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...routes, "DELETE /auth/sessions/:id": noContent, "GET /audit": ok({ items: [] }) });
    renderApp("/account");
    const row = (await screen.findByText("Firefox on Windows")).closest("tr") as HTMLElement;
    expect(screen.getByText("This browser")).toBeInTheDocument();
    await user.click(within(row).getByRole("button", { name: "Sign out" }));
    expect(await screen.findByText("That session was signed out.")).toBeInTheDocument();
    expect(server.call("DELETE /auth/sessions/:id").params.id).toBe("s-old");
  });
});
