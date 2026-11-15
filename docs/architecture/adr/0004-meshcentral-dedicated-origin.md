# ADR-0004: MeshCentral behind our edge on a dedicated hostname

* Status: Accepted (2026-11-15)

## Context
MeshCentral can be served on a sub-path of our hostname or on its own
hostname. Its CSP allows `'unsafe-inline'` and its session cookies use path
`/`. A compromised endpoint controls strings (hostname, user names) that
MeshCentral renders. On the same origin, any XSS in MeshCentral would run with
full access to the EasyRMM API.

## Decision
* MeshCentral is served on a **dedicated hostname** (default `mesh.` + the
  application hostname, configurable), from the same IP and port 443.
* The edge forwards MeshCentral **agent** routes unconditionally
  (MeshCentral authenticates agents itself) and **browser** routes only when
  the request carries a valid, unexpired EasyRMM remote-session grant cookie
  bound to a live EasyRMM session. MeshCentral's own login page,
  `meshsettings`, invite and sharing routes are not reachable from the
  internet.
* The MeshCentral iframe is framed only by the application origin
  (`allowedFramingOrigins`).

## Consequences
* Deployments need two DNS names (or a wildcard) instead of one. This is the
  one place we trade a little simplicity for isolation; it is still fewer
  names than Tactical RMM's three.
* Lab installs on a bare IP need hosts-file entries or a local DNS name.
* Revoking an EasyRMM session immediately stops further MeshCentral browser
  requests through the edge.
