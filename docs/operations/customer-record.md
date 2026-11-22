# The customer record

Each organization and site keeps what a technician needs to reach the
customer: the organization's main phone, email, website and business
hours; each site's address and its own hours; the people to call; and the
places within a site, from buildings down to racks. The design is in
[ADR-0066](../architecture/adr/0066-customer-documentation-and-assets.md#the-customer-record);
pages, search and the asset record come in later releases.

## The organization

An organization's **Overview** shows:

* **Contact information**: the main phone, email and website, the
  business hours with *Open now* or *Closed now*, and after-hours
  instructions. **Edit** (with `doc.manage` at the organization) changes
  them.
* **Primary and emergency contacts**: the organization's primary contact,
  each site's, and every emergency contact, with how to reach them; the
  first 50, and the rest on the **Contacts** tab.
* **Sites**, each with its address and *Open now* or *Closed now*.

The fields:

* **Phone numbers** are kept as typed, up to 50 characters, and need at
  least one digit. EasyRMM does not reformat or dial them; the console
  links them for a phone or softphone on the technician's computer.
* **Email** is one plain address, up to 254 characters: before the `@`,
  letters, digits and `. _ + - '` only; after it, a domain such as
  `example.com`. Characters the standard allows besides, such as `?`, `&`
  and `=`, are refused, because in a `mailto:` link they start headers
  such as `bcc`.
* **Website** is an `https` or `http` address; `example.com` is saved as
  `https://example.com`. The console links nothing else.
* **After-hours instructions** are plain text, up to 2,000 characters.

## Business hours

Hours are a weekly schedule: up to four periods a day, each a start and an
end in local time, such as 09:00–12:00 and 13:00–17:00. A day without any
period is closed. A period whose end is at or before its start runs past
midnight and belongs to the day it starts: Friday 22:00–02:00 is open until
2 a.m. on Saturday. **Copy Monday to Tuesday–Friday** fills the working week
from Monday.

The organization's hours are in its time zone. A site either keeps hours of
its own, in the site's time zone, or uses the organization's, read in the
site's time zone: a 09:00 opening is 09:00 wherever the site is.

A time zone is a name from the IANA time zone database, written as the
database writes it, such as `Europe/London` or `US/Eastern`; the console
offers the list. The server takes the names in the copy of the database
it is built with and refuses other spellings, such as `Europe//London`.

*Open now* and *Closed now* are worked out when the page loads. Around a
change to or from daylight saving time, a period that starts in the skipped
hour begins when the hour ends, and one that starts in a repeated hour
begins at its first occurrence. Closures on given dates, such as public
holidays, are not kept yet.

## The site

A site's **Overview** shows **Address and hours**, with *Open now* or
*Closed now*, **Places** and **Contacts**. **Edit** in **Address and hours**
(with `doc.manage` at the site) changes:

* **The address as fields**: two lines, a city or town, a state, county or
  province, a postal code and a country from the ISO 3166-1 list.
* **The address as free text**, up to 1,000 characters, for an address the
  fields do not fit. The site shows the fields when any is filled in, else
  the free text. Nothing is read from the free text into the fields.
* **Hours of its own**, or the organization's, and after-hours
  instructions.

A site's name, time zone and notes stay under the site's own **Edit**
(`site.manage`). Before this release the address was part of it:
`PUT /api/v1/sites/{id}` no longer takes `address`, and
`PUT /api/v1/sites/{id}/details` does.

## Contacts

A contact is a record of one of the customer's staff, not an EasyRMM
account: it does not sign in, and EasyRMM never emails or messages it.
Someone who also uses the console, such as a customer's IT person with a
site-scoped role, has an account of their own, separate from the contact.
Each contact has a name (required), a job title, an email, an office and a
mobile phone, and a note of up to 2,000 characters.

* **At the organization or a site.** The organization's **Contacts** tab
  lists every contact you can see, the organization's first and then each
  site's, 100 at a time. A site's page lists its own.
* **Primary and secondary.** There is at most one primary contact for the
  organization and one for each site. Making someone primary makes the
  current primary secondary, and the audit log records both changes: the
  new primary's record names the one before (`previousPrimaryId`), and
  that contact's own record names the new one (`primaryId`).
* **Emergency** is a flag of its own, so a primary contact can also be the
  one to call in an emergency.
* At most 1,000 contacts for the organization itself and 1,000 for each
  site.
* **Two people editing at once.** An edit sends only the fields it
  changed, and the server applies them to the contact as it is when the
  edit arrives: one person changing a phone number does not undo another
  making a different contact primary.

## Places

Places are where things are within a site: a **building**, **floor**,
**room**, **rack** or **other**, either at the top of the site or inside
another place of the same site, at most four deep. Names are unique among
the places with the same parent, ignoring case. A site holds at most 500
places.

**Edit** on a place moves it, with the places inside it, as long as none
ends up more than four deep; a place cannot go inside itself or a place
inside it. The **Inside** list names each place by where it is, such as
*Main › Floor 1 (Floor)*, and a move made by someone else in the meantime
is built on, not undone. A place with places inside it is deleted only
once they have been moved or deleted.

## Who can see and change what

| Permission | Held by | Opens |
|---|---|---|
| `doc.view` | Every built-in role | The record at the organization or site where the role is |
| `doc.manage` | Technician and above | Changing it there |

* **A role at the organization** sees and changes the organization's
  contact information, its own contacts and every site's record.
* **A role at a site** sees and changes that site's address, hours, places
  and contacts, and sees the organization's contact information and hours
  (the organization's row, which site-scoped people have always seen). It
  does not see the organization's own contacts or other sites' records.
* Row-level security in PostgreSQL applies the same rule to `contacts` and
  `site_places`, whatever the server asks.

## Deleting a site or an organization

A site or an organization that holds contacts or places is deleted with
them, but only after you confirm what goes. The first **Delete** says, for
example, *This site holds 2 contacts and 1 place, which would be deleted
with it*; **Delete site and its documentation** confirms those counts. If
someone adds or removes one in between, EasyRMM asks again with the new
counts. The audit record of the deletion keeps the counts; the contacts
and places deleted with it get no records of their own.

Through the API, the confirmation is the counts as query parameters:
`DELETE /api/v1/sites/{id}?contacts=2&places=1`. Without them, a site or
organization holding any answers `409 documentation_exists`, with the
counts in the error's `counts`; with counts that no longer hold, `409
documentation_changed`. A site with devices is refused before
either, as before.

## Audit

Every change is recorded: *Changed contact information*, *Changed address
and hours*, *Added contact*, *Changed contact*, *Deleted contact*, *Added
place*, *Changed place* and *Deleted place*, under the **Contacts** and
**Places** areas of the audit log. Besides who made the change, when, and
at which organization and site, a record keeps only:

* **Contact information, address and hours**: the names of the fields that
  changed, not their values.
* **A contact**: the names of the fields that were set or changed (none
  for a deletion), and the contact's priority (primary, secondary or none)
  and emergency flag as they are after the change, or were before a
  deletion. A new primary contact's record names the one before
  (`previousPrimaryId`), which gets a *Changed contact* record of its own
  with `priority` changed to secondary and the new primary's ID
  (`primaryId`). Never the contact's name, job title, email address, phone
  numbers or note.
* **A place**: its kind (building, floor, room, rack or other) and the ID
  of the place it is inside (`parentId`, left out at the top of the site),
  as they are after the change, or were before a deletion, and for a
  change the names of the fields that changed. Never the place's name.
* **Deleting a site or an organization**: the number of contacts and
  places deleted with it, which get no records of their own.

The audit log is kept for `EASYRMM_AUDIT_RETENTION` and cannot be edited,
so personal data is kept out of it.

## Export and backup

The **Contacts** report under **Reports** lists every contact you can see,
with its organization and site, and downloads as CSV. Each download is
recorded in the audit log, with `searched` when it was searched but not
the search itself, which may be a name or an email address. The record is
in the database, so the database dump in
[Backup and restore](backup-restore.md) holds it: a contact deleted in
EasyRMM stays in the dumps made before, until those are deleted.

## API

| Method and path | Needs |
|---|---|
| `PUT /api/v1/organizations/{id}/details` | `doc.manage` at the organization |
| `PUT /api/v1/sites/{id}/details` | `doc.manage` at the site |
| `GET /api/v1/organizations/{id}/contacts` (`siteId`, `key=true` for the primary and emergency contacts only, `limit` 1–1,000 (200 by default), `after`) | `doc.view`; rows the caller cannot see are left out |
| `POST /api/v1/organizations/{id}/contacts` (`siteId` in the body, or none for the organization) | `doc.manage` where the contact goes |
| `PATCH`, `DELETE /api/v1/contacts/{id}` | `doc.manage` where the contact is |
| `GET`, `POST /api/v1/sites/{id}/places` | `doc.view`, `doc.manage` at the site |
| `PATCH`, `DELETE /api/v1/places/{id}` | `doc.manage` at the site |

The organization's and site's answers carry the record's fields, empty for
a caller without `doc.view`, with `openNow` (null without hours) and
`canManageDocumentation`.

`PATCH` changes the fields the body names and leaves the others. EasyRMM
takes its changes to one organization's or site's record one at a time.
A change that meets one written to the database directly, outside
EasyRMM, such as a second primary contact or a removed parent place,
answers `409 primary_changed` or `409 places_changed`: read the record
again and retry.
