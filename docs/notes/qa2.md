# qa2: Quick Assist, one-click link and default expiry (ADR-0080 amendment)

Changelog:
* Quick Assist: a **New link** button at the top of the page makes a one-time link in one click, with no name to type (the link is named from the time and its maker), and shows it with Copy and its expiry.
* Settings: a new **General** part, for super administrators, sets how long a new Quick Assist link lasts (1 minute to 7 days; 24 hours by default).

Implementation status: Quick Assist, "one-click link and default expiry": built, tested (integration, vitest, e2e spec updated). No migration (setting `quickassist.default_life_minutes` in `settings`).

Privacy: the generated link name carries the maker's display name and is shown to the user who opens the link.
