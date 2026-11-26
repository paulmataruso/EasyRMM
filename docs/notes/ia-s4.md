# ia-s4: the tab registry (ADR-0072, slice S4)

Changelog lines:

* The organization and site pages now build their tab strip from one registry (`web/src/pages/organizations/levelTabs.tsx`). No change in what shows; tab URLs (`?tab=contacts`, `?tab=patch-policy`) work as before.

Implementation-status rows: organization and site tab registry (done, vitest and browser tested). The group page keeps its own two-tab strip.

Privacy notes: none.

Note: `LevelContext.can` is today the any-scope `useAuth().can`, the same check the pages made. A per-selection check slots in at that one place when the server reports a node's permissions.
