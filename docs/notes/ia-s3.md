# ia-s3: the group page (ADR-0072, slice S3)

Changelog lines:

* Added a page for each device group (`/groups/:id`) with its devices and, for people who may edit devices, a Settings tab. The old `/sites/:id?groupId=` link opens it.
* Added `GET /device-groups/{id}`, which returns the group with its organization, site, device count and whether group-wide verbose agent logging is on.
* Moved group-wide verbose agent logging from the device's Logs tab to the group's Settings tab. The Logs tab now says a group setting is on and links to the group.

Implementation-status rows: group page (done, tested in the browser and against PostgreSQL); verbose logging on a group (moved, same endpoints).

Privacy notes: none. No new data is stored; the group page reads existing rows.

Not covered by the plan: the endpoint also returns `canManage` and `canEditDevices` so the page can hide what the caller may not do.
