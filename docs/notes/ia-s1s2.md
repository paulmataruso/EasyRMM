# ia-s1s2 (ADR-0072 S1 and S2)

Changelog lines:

* Patching: choosing a device in the Patching tree opens that device's own patching page (`/patching/devices/:id`); a group or organization narrows the Patching page; `/patching?deviceId=` redirects.
* Add devices: the show-again button is labelled "Show install command"; tokens made before secrets were kept say plainly they cannot be shown again.
* Users: the invitation dialog says whether the invitation is emailed or a link is shown, and the button reads "Create invitation link" when no mail server is set up.

Implementation status rows: none (web only).

Privacy notes: none.
