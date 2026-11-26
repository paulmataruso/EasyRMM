# ia-s56: ADR-0072 slices S5 (Install tab) and S6 (People tab)

Changelog lines:

* Organization and site pages gain an Install tab (the Add devices screen with its scope fixed: that organization's or site's sites and tokens). `/devices/add?siteId=` opens the site's Install tab.
* Organization pages gain a People tab (the Settings > Users list for that organization). `/settings?tab=users&organizationId=` opens it.
* The session view gains `scopedPermissions` (where each permission that is not platform-wide holds), so tabs are shown by the permission held at the page's own organization or site.

Implementation-status rows: ADR-0072 S5, S6 and the scoped tab check: built, unit and browser tested.

Privacy: `scopedPermissions` lists organization and site IDs the signed-in user already holds roles in; it is sent only to that user.

Notes: approval tokens stay on Devices > Add devices (they belong to no organization). The token list is filtered in the console by organization or site; `GET /enrollment-tokens` has no scope parameter and already returns only what the caller may see.
