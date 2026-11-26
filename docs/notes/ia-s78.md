# ia-s78 (ADR-0072 S7 and S8)

## Changelog lines

* Alert policies moved to the level they belong to: shared policies are Settings > Alert policies, an organization's and a site's are the Alert policies tab on their pages. The Alerts section links to the policies of its scope, and `/alerts?tab=policies` redirects.
* Patching settings moved to the organization and site pages (Patching tab, `patch.configure`): patch policy, tags, monthly report schedule and automatic agent install. Settings > Patching keeps the server-wide items and gains the Engine view; the old URLs redirect.
* `PATCH /api/v1/settings/easypatch/organizations/{id}` accepts `patch.configure` on the organization; new `GET /api/v1/patching/organizations/{id}/agent-install`.

## Implementation status rows

* ADR-0072 S7 (alert policies at three levels): built, vitest and Playwright (`web/e2e/ia-s78.spec.ts`).
* ADR-0072 S8 (patching settings on the organization and site): built, same tests.

## Privacy

None: no new personal data.
