import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { BusinessHours, Contact, Place } from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { contact, org, place, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const location = () => screen.getByTestId("location").textContent;
const dialog = (name: string) => screen.findByRole("dialog", { name });

const DOC = ["org.view", "org.manage", "site.view", "site.manage", "doc.view", "doc.manage"] as const;

const WEEKDAYS: BusinessHours = {
  monday: [{ start: "09:00", end: "17:00" }],
  tuesday: [{ start: "09:00", end: "17:00" }],
  wednesday: [{ start: "09:00", end: "17:00" }],
  thursday: [{ start: "09:00", end: "17:00" }],
  friday: [{ start: "09:00", end: "17:00" }],
  saturday: [],
  sunday: [],
};

const NORTHWIND = org("o1", "Northwind Traders", {
  siteCount: 1,
  mainPhone: "+1 555 0100",
  mainEmail: "help@example.com",
  website: "https://example.com",
  businessHours: WEEKDAYS,
  afterHoursNote: "Call the mobile of the emergency contact.",
  openNow: true,
});

const HEAD_OFFICE = site("s1", "o1", "Head office", {
  addressLine1: "1 Example Road",
  city: "Springfield",
  postalCode: "00000",
  countryCode: "GB",
  address: "Ignored while the fields are set",
  openNow: false,
  hoursFromOrganization: true,
});

describe("the organization's record", () => {
  it("shows the contact information and saves edited hours", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: [...DOC] })),
      "GET /organizations/:id": ok(NORTHWIND),
      "GET /organizations/:id/sites": ok({ items: [HEAD_OFFICE] }),
      "GET /organizations/:id/contacts": ok({ items: [] }),
      "PUT /organizations/:id/details": (r) => ok({ ...NORTHWIND, ...(r.body as object) }),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/organizations/o1");
    const card = (await screen.findByRole("heading", { name: /Contact information/ })).closest("section")!;
    expect(within(card).getByText("Open now")).toBeInTheDocument();
    expect(within(card).getByRole("link", { name: "+1 555 0100" })).toHaveAttribute("href", "tel:+15550100");
    expect(within(card).getByRole("link", { name: "help@example.com" })).toHaveAttribute("href", "mailto:help@example.com");
    expect(within(card).getByRole("link", { name: "https://example.com" })).toHaveAttribute("href", "https://example.com/");
    expect(within(card).getByText("Mon–Fri")).toBeInTheDocument();
    expect(within(card).getByText("Sat–Sun")).toBeInTheDocument();
    // The site's address in the list comes from its fields, not the free text.
    expect(screen.getByText(/1 Example Road, Springfield, 00000/)).toBeInTheDocument();

    await user.click(within(card).getByRole("button", { name: "Edit" }));
    const form = await dialog("Edit contact information");
    await user.click(within(form).getByRole("button", { name: "Add a period on Saturday" }));
    await user.clear(within(form).getByLabelText("Saturday period 1 closes"));
    await user.type(within(form).getByLabelText("Saturday period 1 closes"), "12:00");
    await user.click(within(form).getByRole("button", { name: "Remove Friday period 1" }));
    await user.click(within(form).getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Contact information saved.")).toBeInTheDocument();
    const body = server.call("PUT /organizations/:id/details").body as { businessHours: BusinessHours; mainPhone: string };
    expect(body.mainPhone).toBe("+1 555 0100");
    expect(body.businessHours.saturday).toEqual([{ start: "09:00", end: "12:00" }]);
    expect(body.businessHours.friday).toEqual([]);
  });

  it("shows the primary and emergency contacts, and whether each site is open, on the overview", async () => {
    const server = installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: [...DOC] })),
      "GET /organizations/:id": ok(NORTHWIND),
      "GET /organizations/:id/sites": ok({ items: [HEAD_OFFICE, site("s2", "o1", "Warehouse", { openNow: true })] }),
      "GET /organizations/:id/contacts": ok({
        items: [
          contact("c1", "Pat Example", { priority: "primary", email: "pat+it@example.com", jobTitle: "Office manager" }),
          contact("c2", "Sam Example", { siteId: "s1", siteName: "Head office", emergency: true, mobilePhone: "555 0199" }),
        ],
      }),
    });
    renderApp("/organizations/o1");
    const key = (await screen.findByRole("heading", { name: "Primary and emergency contacts" })).closest("section")!;
    const people = await within(key).findAllByRole("listitem");
    expect(people.map((p) => p.textContent)).toEqual([
      expect.stringMatching(/^Pat Example.*Organization.*Primary.*Office manager.*pat\+it@example\.com$/),
      expect.stringMatching(/^Sam Example.*Head office.*Emergency.*Mobile: 555 0199$/),
    ]);
    // An address in a mailto: link is encoded part by part.
    expect(within(key).getByRole("link", { name: "pat+it@example.com" })).toHaveAttribute("href", "mailto:pat%2Bit@example.com");
    expect(server.call("GET /organizations/:id/contacts").query.get("key")).toBe("true");

    const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1);
    expect(within(rows[0]!).getByText("Closed now")).toBeInTheDocument();
    expect(within(rows[0]!).getByText(/^1 Example Road, Springfield, 00000, /)).toBeInTheDocument();
    expect(within(rows[1]!).getByText("Open now")).toBeInTheDocument();
  });

  it("links a website only over http or https", async () => {
    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: [...DOC] })),
      "GET /organizations/:id": ok({ ...NORTHWIND, website: "javascript:alert(1)" }),
      "GET /organizations/:id/sites": ok({ items: [] }),
      "GET /organizations/:id/contacts": ok({ items: [] }),
    });
    renderApp("/organizations/o1");
    const card = (await screen.findByRole("heading", { name: /Contact information/ })).closest("section")!;
    expect(within(card).getByText("javascript:alert(1)").closest("a")).toBeNull();
  });

  it("puts the server's problem with the hours under them", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: [...DOC] })),
      "GET /organizations/:id": ok(NORTHWIND),
      "GET /organizations/:id/sites": ok({ items: [] }),
      "GET /organizations/:id/contacts": ok({ items: [] }),
      "PUT /organizations/:id/details": fail(422, "validation_failed", "Check the details.", {
        businessHours: "Periods of opening overlap. Make each end before the next begins.",
      }),
    });
    renderApp("/organizations/o1");
    const card = (await screen.findByRole("heading", { name: /Contact information/ })).closest("section")!;
    await user.click(within(card).getByRole("button", { name: "Edit" }));
    const form = await dialog("Edit contact information");
    const hours = within(form).getByRole("group", { name: "Business hours" });
    expect(hours).toHaveAccessibleDescription("Up to four periods a day. A period that ends at or before it starts runs past midnight.");
    await user.click(within(form).getByRole("button", { name: "Save" }));
    expect(await within(form).findByText("Periods of opening overlap. Make each end before the next begins.")).toBeInTheDocument();
    // The problem is read out with the hours.
    expect(hours).toHaveAccessibleDescription("Periods of opening overlap. Make each end before the next begins.");
  });

  it("lists contacts a page at a time and adds one to a site", async () => {
    const user = userEvent.setup();
    let added: Contact | null = null;
    const first = [
      contact("c1", "Pat Example", { priority: "primary", email: "pat@example.com", jobTitle: "Office manager" }),
      contact("c2", "Sam Example", { siteId: "s1", siteName: "Head office", emergency: true, mobilePhone: "555 0199" }),
    ];
    const server = installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: [...DOC] })),
      "GET /organizations/:id": ok(NORTHWIND),
      "GET /organizations/:id/sites": ok({ items: [HEAD_OFFICE] }),
      "GET /organizations/:id/contacts": (r: FakeRequest) =>
        r.query.get("after") === "page-2"
          ? ok({ items: [contact("c3", "Lee Example", { siteId: "s1", siteName: "Head office" })] })
          : ok({ items: added ? [...first, added] : first, next: "page-2" }),
      "POST /organizations/:id/contacts": (r) => {
        const body = r.body as Contact;
        added = contact("c9", body.name, { siteId: body.siteId, siteName: "Head office" });
        return { status: 201, body: added };
      },
      "PATCH /contacts/:id": (r) => ok({ ...first[0]!, ...(r.body as object) }),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/organizations/o1?tab=contacts");
    const table = await screen.findByRole("table");
    expect(within(table).getByText("Pat Example")).toBeInTheDocument();
    expect(within(table).getByText("Primary")).toBeInTheDocument();
    expect(within(table).getByText("Emergency")).toBeInTheDocument();
    expect(within(table).getByText("Mobile: 555 0199")).toBeInTheDocument();
    expect(within(table).getByText("Organization")).toBeInTheDocument();
    expect(server.call("GET /organizations/:id/contacts").query.get("limit")).toBe("100");

    await user.click(screen.getByRole("button", { name: "Next page" }));
    expect(await screen.findByText("Lee Example")).toBeInTheDocument();
    expect(location()).toBe("/organizations/o1?tab=contacts&after=page-2");
    await user.click(screen.getByRole("button", { name: "First page" }));
    await screen.findByText("Pat Example");

    await user.click(screen.getByRole("button", { name: "Add contact" }));
    const form = await dialog("New contact");
    await user.selectOptions(within(form).getByLabelText("Contact of"), "Head office");
    await user.type(within(form).getByLabelText(/^Name/), "Kim Example");
    await user.selectOptions(within(form).getByLabelText("Priority"), "secondary");
    await user.click(within(form).getByLabelText("Emergency contact"));
    await user.click(within(form).getByRole("button", { name: "Add contact" }));
    expect(await screen.findByText("Contact “Kim Example” added.")).toBeInTheDocument();
    expect(server.call("POST /organizations/:id/contacts").body).toEqual({
      siteId: "s1",
      name: "Kim Example",
      jobTitle: "",
      email: "",
      officePhone: "",
      mobilePhone: "",
      note: "",
      priority: "secondary",
      emergency: true,
    });

    // An edit sends what it changed and nothing else, so that it leaves alone what others changed since.
    await user.click(screen.getByRole("button", { name: "Edit Pat Example" }));
    const edit = await dialog("Edit contact");
    await user.clear(within(edit).getByLabelText("Mobile phone"));
    await user.type(within(edit).getByLabelText("Mobile phone"), "555 0123");
    await user.click(within(edit).getByRole("button", { name: "Save changes" }));
    expect(await screen.findByText("Contact updated.")).toBeInTheDocument();
    expect(server.call("PATCH /contacts/:id").body).toEqual({ mobilePhone: "555 0123" });
  });

  it("deletes an organization's contacts with it only once their count is confirmed", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /organizations/:id": ok(NORTHWIND),
      "GET /organizations/:id/sites": ok({ items: [] }),
      "GET /organizations/:id/contacts": ok({ items: [] }),
      "DELETE /organizations/:id": (r) =>
        r.query.get("contacts") === "2"
          ? noContent
          : { status: 409, body: { error: { code: "documentation_exists", message: "This organization holds 2 contacts, which would be deleted with it. Confirm to delete them too.", counts: { contacts: 2, places: 0 } } } },
      "GET /organizations": ok({ items: [] }),
    });
    renderApp("/organizations/o1");
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    const confirm = await dialog("Delete organization");
    await user.type(within(confirm).getByLabelText(/Type .* to confirm/), "Northwind Traders");
    await user.click(within(confirm).getByRole("button", { name: "Delete organization" }));
    expect(await within(confirm).findByText(/holds 2 contacts/)).toBeInTheDocument();
    await user.click(within(confirm).getByRole("button", { name: "Delete organization and contacts" }));
    await waitFor(() => expect(location()).toBe("/organizations"));
    expect(server.call("DELETE /organizations/:id", 0).query.toString()).toBe("");
    expect(server.call("DELETE /organizations/:id", 1).query.toString()).toBe("contacts=2&places=0");
  });

  it("shows neither the record nor its tab without doc.view, and no editing without doc.manage", async () => {
    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view"] })),
      "GET /organizations/:id": ok(org("o1", "Northwind Traders", { canManage: false, canManageDocumentation: false })),
      "GET /organizations/:id/sites": ok({ items: [] }),
    });
    const view = renderApp("/organizations/o1?tab=contacts");
    expect(await screen.findByRole("heading", { name: "Northwind Traders" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /Contact information/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Contacts" })).not.toBeInTheDocument();
    view.unmount();

    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "doc.view"] })),
      "GET /organizations/:id": ok({ ...NORTHWIND, canManage: false, canManageDocumentation: false }),
      "GET /organizations/:id/sites": ok({ items: [{ ...HEAD_OFFICE, canManageDocumentation: false }] }),
      "GET /organizations/:id/contacts": ok({ items: [contact("c1", "Pat Example", { canManage: false })] }),
    });
    renderApp("/organizations/o1?tab=contacts");
    expect(await screen.findByText("Pat Example")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add contact" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit Pat Example" })).not.toBeInTheDocument();
  });
});

describe("the site's record", () => {
  const routes = (places: () => Place[]) => ({
    ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: [...DOC] })),
    "GET /sites/:id": ok(HEAD_OFFICE),
    "GET /organizations/:id": ok(NORTHWIND),
    "GET /sites/:id/device-groups": ok({ items: [] }),
    "GET /sites/:id/places": () => ok({ items: places() }),
    "GET /organizations/:id/contacts": ok({ items: [] }),
    "GET /audit": ok({ items: [] }),
  });

  it("shows the address, the organization's hours and whether it is open", async () => {
    installFakeApi(routes(() => []));
    renderApp("/sites/s1");
    const card = (await screen.findByRole("heading", { name: /Address and hours/ })).closest("section")!;
    expect(within(card).getByText("Closed now")).toBeInTheDocument();
    expect(within(card).getByText("1 Example Road")).toBeInTheDocument();
    expect(within(card).getByText("Springfield, 00000")).toBeInTheDocument();
    expect(within(card).queryByText("Ignored while the fields are set")).not.toBeInTheDocument();
    expect(await within(card).findByText("The organization's hours, in the site's time zone.")).toBeInTheDocument();
    expect(within(card).getByText("Mon–Fri")).toBeInTheDocument();
  });

  it("saves the address with hours of its own, and without them again", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes(() => []),
      "PUT /sites/:id/details": (r) => ok({ ...HEAD_OFFICE, ...(r.body as object) }),
    });
    renderApp("/sites/s1");
    const card = (await screen.findByRole("heading", { name: /Address and hours/ })).closest("section")!;
    await user.click(within(card).getByRole("button", { name: "Edit" }));
    let form = await dialog("Edit address and hours");
    await user.clear(within(form).getByLabelText("City or town"));
    await user.type(within(form).getByLabelText("City or town"), "Shelbyville");
    await user.selectOptions(within(form).getByLabelText("Country"), "US");
    await user.click(within(form).getByLabelText("This site keeps hours of its own"));
    await user.click(within(form).getByRole("button", { name: "Add a period on Sunday" }));
    await user.click(within(form).getByRole("button", { name: "Save" }));
    expect(await screen.findByText("Address and hours saved.")).toBeInTheDocument();
    const body = server.call("PUT /sites/:id/details").body as { city: string; countryCode: string; businessHours: BusinessHours | null };
    expect(body.city).toBe("Shelbyville");
    expect(body.countryCode).toBe("US");
    expect(body.businessHours?.sunday).toEqual([{ start: "09:00", end: "17:00" }]);
    expect(body.businessHours?.monday).toEqual([]);

    // A week with nothing open is no hours of its own.
    await user.click(within(card).getByRole("button", { name: "Edit" }));
    form = await dialog("Edit address and hours");
    await user.click(within(form).getByLabelText("This site keeps hours of its own"));
    await user.click(within(form).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(server.callsTo("PUT /sites/:id/details")).toHaveLength(2));
    expect((server.call("PUT /sites/:id/details", 1).body as { businessHours: unknown }).businessHours).toBeNull();
  });

  it("adds a place inside another and offers only parents that keep it within four levels", async () => {
    const user = userEvent.setup();
    let places = [
      place("p1", "s1", "Main"),
      place("p2", "s1", "Ground", { parentId: "p1", kind: "floor", depth: 2 }),
      place("p3", "s1", "Server room", { parentId: "p2", kind: "room", depth: 3 }),
      place("p4", "s1", "Rack A", { parentId: "p3", kind: "rack", depth: 4 }),
    ];
    const server = installFakeApi({
      ...routes(() => places),
      "POST /sites/:id/places": (r) => {
        const body = r.body as Place;
        const p = place("p9", "s1", body.name, { parentId: body.parentId, kind: body.kind, depth: 2 });
        places = [...places.slice(0, 2), p, ...places.slice(2)];
        return { status: 201, body: p };
      },
      "PATCH /places/:id": (r) => ok({ ...places[1]!, ...(r.body as object) }),
    });
    renderApp("/sites/s1");
    const list = await screen.findByRole("list", { name: "Places at Head office" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(4);
    // Each place is a list item in the list of the place it is inside, so a screen reader says how deep it is.
    const nesting = (name: string) => {
      let lists = 0;
      for (let el = within(list).getByText(name).parentElement; el && el !== list.parentElement; el = el.parentElement) if (el.tagName === "UL") lists++;
      return lists;
    };
    expect(["Main", "Ground", "Server room", "Rack A"].map(nesting)).toEqual([1, 2, 3, 4]);
    // Nothing goes inside a rack four deep.
    expect(within(list).queryByRole("button", { name: "Add a place inside Rack A" })).not.toBeInTheDocument();

    await user.click(within(list).getByRole("button", { name: "Add a place inside Main" }));
    let form = await dialog("New place");
    expect(within(form).getByLabelText("Inside")).toHaveValue("p1");
    await user.selectOptions(within(form).getByLabelText("Kind"), "floor");
    await user.type(within(form).getByLabelText(/^Name/), "First");
    await user.click(within(form).getByRole("button", { name: "Add place" }));
    expect(await screen.findByText("Floor “First” added.")).toBeInTheDocument();
    expect(server.call("POST /sites/:id/places").body).toEqual({ parentId: "p1", kind: "floor", name: "First" });

    // Moving Ground, three levels tall, leaves only the site itself and Main as parents.
    await user.click(screen.getByRole("button", { name: "Edit Ground" }));
    form = await dialog("Edit place");
    const options = () => within(within(form).getByLabelText("Inside")).getAllByRole("option").map((o) => o.textContent);
    expect(options()).toEqual(["The site itself", "Main (Building)"]);
    await user.selectOptions(within(form).getByLabelText("Inside"), "");
    await user.click(within(form).getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(server.callsTo("PATCH /places/:id")).toHaveLength(1));
    // Only the move is sent: the kind and the name are as they were.
    expect(server.call("PATCH /places/:id").body).toEqual({ parentId: null });

    // Each parent is named by its path, so that two rooms of one name on different floors can be told apart.
    await user.click(screen.getByRole("button", { name: "Edit First" }));
    form = await dialog("Edit place");
    expect(options()).toEqual(["The site itself", "Main (Building)", "Main › Ground (Floor)", "Main › Ground › Server room (Room)"]);
  });

  it("says why a place with places inside cannot be deleted", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...routes(() => [place("p1", "s1", "Main"), place("p2", "s1", "Ground", { parentId: "p1", kind: "floor", depth: 2 })]),
      "DELETE /places/:id": fail(409, "place_not_empty", "Move or delete the places inside this one first."),
    });
    renderApp("/sites/s1");
    await user.click(await screen.findByRole("button", { name: "Delete Main" }));
    const confirm = await dialog("Delete place");
    await user.click(within(confirm).getByRole("button", { name: "Delete place" }));
    expect(await within(confirm).findByText("Move or delete the places inside this one first.")).toBeInTheDocument();
  });

  it("deletes a site with its documentation once confirmed, and asks again when it changed", async () => {
    const user = userEvent.setup();
    const counts = [
      { code: "documentation_exists", counts: { contacts: 1, places: 2 } },
      { code: "documentation_changed", counts: { contacts: 2, places: 2 } },
    ];
    const server = installFakeApi({
      ...routes(() => []),
      "DELETE /sites/:id": (r) => {
        if (r.query.get("contacts") === "2") return noContent;
        const next = counts.shift()!;
        return { status: 409, body: { error: { code: next.code, message: `Holds ${next.counts.contacts} contacts.`, counts: next.counts } } };
      },
      "GET /organizations/:id/sites": ok({ items: [] }),
    });
    renderApp("/sites/s1");
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    const confirm = await dialog("Delete site");
    await user.type(within(confirm).getByLabelText(/Type .* to confirm/), "Head office");
    await user.click(within(confirm).getByRole("button", { name: "Delete site" }));
    expect(await within(confirm).findByText("Holds 1 contacts.")).toBeInTheDocument();
    await user.click(within(confirm).getByRole("button", { name: "Delete site and its documentation" }));
    expect(await within(confirm).findByText("Holds 2 contacts.")).toBeInTheDocument();
    await user.click(within(confirm).getByRole("button", { name: "Delete site and its documentation" }));
    await waitFor(() => expect(location()).toBe("/organizations/o1"));
    expect(server.callsTo("DELETE /sites/:id").map((c) => c.query.toString())).toEqual(["", "contacts=1&places=2", "contacts=2&places=2"]);
  });
});
