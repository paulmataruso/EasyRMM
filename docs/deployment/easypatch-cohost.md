# EasyPatch on the same server as EasyRMM

This guide puts EasyRMM and EasyPatch on one Linux server, with one public
IP address and the usual two ports, 80 and 443. Each keeps its own name:

* `https://rmm.example.com`: the EasyRMM console.
* `https://patch.example.com`: EasyPatch's own console, which people open
  by its URL as before. EasyPatch's agents connect to it here too.

Design: [ADR-0035](../architecture/adr/0035-cohosting-easypatch.md).

## How it works

EasyRMM owns ports 80 and 443. EasyPatch's Caddy moves to two ports on
loopback, which only the server itself can reach. EasyRMM's edge hands it
EasyPatch's traffic:

```
                               ┌─────────────────────────── one server ───────────────────────────┐
 browsers, EasyRMM agents  ──► │ :443  EasyRMM edge ── rmm.example.com, mesh.rmm.example.com ──► EasyRMM
 EasyPatch agents          ──► │   │                                                              │
                               │   └─ patch.example.com: passed through, still encrypted,         │
                               │      with a PROXY header naming the client                       │
                               │        ──► 127.0.0.1:19443 ──► EasyPatch's Caddy ──► EasyPatch   │
                               │ :80   EasyRMM edge ── patch.example.com/.well-known/acme-challenge │
                               │        ──► 127.0.0.1:19080 ──► EasyPatch's Caddy                 │
                               └──────────────────────────────────────────────────────────────────┘
```

* **EasyRMM never decrypts EasyPatch's traffic.** It reads only the name a
  client asks for at the start of the TLS handshake (SNI), then relays the
  connection unchanged.
* **EasyPatch keeps its own certificates.** Caddy still gets and renews
  them from Let's Encrypt, with either challenge: HTTP-01 through EasyRMM's
  port 80, or TLS-ALPN-01 through the relayed port 443.
* **EasyPatch keeps everything else it set before:** its headers (HSTS,
  CSP), its cookies, its single sign-on, its agent signatures. Agents
  already enrolled with `https://patch.example.com` notice no change.
* **EasyPatch still sees each client's real address**, for its rate limits,
  check-ins and audit log. EasyRMM puts a PROXY protocol v2 header in front
  of each connection, and Caddy believes it only from EasyPatch's own Docker
  network.
* **EasyRMM's connector to EasyPatch stays on the server.** It goes straight
  to `127.0.0.1:19443`, so it works even where the server cannot reach its
  own public address.

## Requirements

* **Versions.** EasyRMM with co-hosting (this release or later). EasyPatch
  1.9.0 or later, with its published images; nothing in EasyPatch has to be
  rebuilt. Docker Compose 2.24.4 or later, for `!override` (`docker compose
  version`).
* **Ports.** Inbound TCP 443 and 80, as for either product alone. TCP 4443
  too, if you use EasyRMM by IP address. Ports 19443 and 19080 are on
  loopback: do not open them.
* **Nothing else on the server may use** 80, 443, 19080 or 19443, or
  EasyRMM's own ports (see [docker.md](docker.md#requirements)).

## DNS records

All three names point at the same server:

| Type | Name | Value | For |
|---|---|---|---|
| A | `rmm.example.com` | The server's public IPv4 address | EasyRMM's console, API, agents and installers |
| A | `mesh.rmm.example.com` | The same address | EasyRMM's remote access (MeshCentral) |
| A | `patch.example.com` | The same address | EasyPatch's console, API, agent check-ins and downloads |
| AAAA | each of the three | The server's public IPv6 address | Only if the server answers on IPv6. Certificate authorities try IPv6 first, so a wrong AAAA record breaks certificates |
| CAA | `example.com` | `0 issue "letsencrypt.org"` (EasyRMM and EasyPatch), and `0 issue "zerossl.com"` (EasyPatch's second CA) | Only if the domain already has CAA records |

* **Names you can use.**
  * `mesh.rmm.example.com` must share a domain with `rmm.example.com` (see
    [network.md](../architecture/network.md#host-names)).
  * EasyPatch's name can be anything, even another domain such as
    `patch.example.net`. Another domain also keeps the two consoles on
    different sites as far as browsers are concerned. It is not required:
    each console's cookies stay on its own name.
  * A wildcard (`*.example.com`) covers all three names.
* **Cloudflare:** set the records to *DNS only*. Its proxy would show its
  own certificates to agents.
* **Pick names you will keep.** Agents of both products store the address
  they were installed with.

## Step 1: EasyRMM

Install EasyRMM as in [docker.md](docker.md#install), and also set
EasyPatch's name in `deploy/.env`:

```bash
EASYRMM_EASYPATCH_HOSTNAME=patch.example.com
```

```bash
cd easyrmm/deploy
sudo docker compose up -d
sudo docker compose logs server | grep "passing EasyPatch through"
```

That log line, with the name and `127.0.0.1:19443`, means the edge is
ready. Until EasyPatch is running, connections for its name are closed, and
the server logs `EasyPatch is not answering on its loopback port`.
EasyRMM's own names work as usual.

## Step 2: EasyPatch

Follow EasyPatch's installation guide (`docs/installation.md` in its
repository) up to **3. Start**, without starting it: get the files, run
`./scripts/init-secrets.sh`, and set `EASYPATCH_DOMAIN=patch.example.com`
and `ACME_EMAIL` in its `.env`. Leave `EASYPATCH_PUBLIC_URL` unset: its
default, `https://patch.example.com`, is right.

Copy EasyRMM's two files for EasyPatch into EasyPatch's directory, next to
its `docker-compose.yml`:

```bash
cp easyrmm/deploy/easypatch/docker-compose.easyrmm.yml easyrmm/deploy/easypatch/Caddyfile.easyrmm easypatch/
```

* `docker-compose.easyrmm.yml`, a Compose override for the `caddy`
  service:
  * publishes Caddy on `127.0.0.1:19080` and `127.0.0.1:19443` instead of
    80 and 443;
  * runs Caddy with `Caddyfile.easyrmm`;
  * passes it `EASYPATCH_EDGE_SUBNET`.
* `Caddyfile.easyrmm`, EasyPatch's own `Caddyfile` with one addition: on
  port 443, Caddy reads the PROXY header first, but only from EasyPatch's
  edge network (`EASYPATCH_EDGE_SUBNET`, default `172.30.0.0/24`), where
  Docker delivers EasyRMM's connections. The site itself is still EasyPatch's
  own `easypatch.caddy`, from its image.

Make every `docker compose` command in that directory use the override, by
adding this line to EasyPatch's `.env`:

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.easyrmm.yml
```

This matters. EasyPatch's guide and scripts (`restore.sh`, upgrades) run a
plain `docker compose`. Without the line, they would start Caddy on 80 and
443, which fails while EasyRMM holds them.

Then start EasyPatch as its guide says:

```bash
cd easypatch
docker compose pull
docker compose up -d
docker compose ps                 # caddy shows 127.0.0.1:19080->80/tcp, 127.0.0.1:19443->443/tcp
docker compose logs -f caddy      # wait for "certificate obtained successfully"
```

Create EasyPatch's first administrator as its guide says (**4. Create the
first administrator**), and carry on with it from there.

## Step 3: Connect EasyRMM to EasyPatch

1. In EasyPatch: **Settings → API tokens**. Create a token for the
   organizations EasyRMM should patch. An Operator token lets EasyRMM scan
   and install; a Read only token lets it only look.
2. In EasyRMM: **Settings → EasyPatch**. Set **Address** to
   `https://patch.example.com` and paste the token. Leave **CA certificate**
   empty, because EasyPatch has a public certificate.
3. Link organizations, as in [the EasyPatch integration](../integrations/easypatch.md).

EasyRMM uses the loopback route for that exact address, `https://` +
EasyPatch's name on port 443, so it needs no hairpin NAT. EasyPatch records
EasyRMM's requests as coming from `127.0.0.1`.

**Open EasyPatch**, on EasyRMM's Patching page and in Settings → EasyPatch,
opens EasyPatch's own console in a new tab. It is a link rather than a
frame, because EasyPatch refuses to be framed (`frame-ancestors 'none'`).

## Check it

From a machine outside the server:

```bash
# EasyPatch's own certificate, issued for its name, not EasyRMM's:
echo | openssl s_client -connect patch.example.com:443 -servername patch.example.com 2>/dev/null | openssl x509 -noout -subject -issuer
# EasyPatch answers, with its own headers:
curl -sSI https://patch.example.com/health/ready | grep -iE "^HTTP|strict-transport|content-security"
# Port 80 redirects to HTTPS:
curl -sSI http://patch.example.com/ | grep -iE "^HTTP|^location"
# EasyRMM is unchanged:
curl -sSI https://rmm.example.com/login | head -1
```

Then sign in to EasyPatch and open its audit log. Your sign-in should show
your own public address, not `172.30.0.1`.

## Adding EasyRMM to a server that already runs EasyPatch

EasyPatch currently holds 80 and 443, so it goes behind EasyRMM first.
EasyPatch is unreachable for the minute or two this takes. Its agents retry
at their next poll. Caddy's certificates are kept in its `caddy_data`
volume, so it reuses them rather than requesting new ones.

1. Install EasyRMM's files and `.env` (**Step 1**), but do not start it
   yet.
2. In EasyPatch's directory, copy the two files and add `COMPOSE_FILE` to
   `.env` (**Step 2**). Then recreate Caddy on loopback:
   `docker compose up -d caddy`.
3. Start EasyRMM: `cd easyrmm/deploy && sudo docker compose up -d`.
4. Check it (above).

To undo it: stop EasyRMM, remove the `COMPOSE_FILE` line from EasyPatch's
`.env`, and run `docker compose up -d caddy` in EasyPatch's directory.

## Settings

EasyRMM's `deploy/.env`. Only the first is usually needed.

| Variable | Default | Meaning |
|---|---|---|
| `EASYRMM_EASYPATCH_HOSTNAME` | empty (off) | EasyPatch's public name. Must be a DNS name other than EasyRMM's own. Not allowed with `EASYRMM_TLS_MODE=offload`: a reverse proxy in front of EasyRMM owns 443 and should route EasyPatch's name itself |
| `EASYRMM_EASYPATCH_TLS_UPSTREAM` | `127.0.0.1:19443` | EasyPatch's Caddy HTTPS port. Must be a loopback address |
| `EASYRMM_EASYPATCH_HTTP_UPSTREAM` | `127.0.0.1:19080` | Its HTTP port, for HTTP-01 challenges. Must be loopback. Set it empty to send no challenges there, leaving Caddy TLS-ALPN-01 |
| `EASYRMM_EASYPATCH_PROXY_PROTOCOL` | `true` | Send the PROXY header. Turn it off only for a Caddy without `Caddyfile.easyrmm`: EasyPatch then sees every client as Docker's gateway, and they all share one rate limit |

If you change Caddy's loopback ports, change them in both places:
`docker-compose.easyrmm.yml` and the two `_UPSTREAM` settings. If you set
`EASYPATCH_EDGE_SUBNET`, the override already passes it to Caddy.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| A browser shows a certificate error, EasyRMM's certificate, or HTTP 421 for `patch.example.com` | EasyRMM does not know the name. Check `EASYRMM_EASYPATCH_HOSTNAME` in `deploy/.env`, then run `sudo docker compose up -d server` and look for `passing EasyPatch through` in its log |
| The connection closes at once; EasyRMM logs `EasyPatch is not answering on its loopback port` | EasyPatch's Caddy is not on `127.0.0.1:19443`. Run `docker compose ps` in EasyPatch's directory: is `caddy` up, with the loopback ports? If it shows `0.0.0.0:443`, the override was not used. Check `COMPOSE_FILE` |
| `docker compose up` in EasyPatch fails with `address already in use` on 80 or 443 | Same: the override was not used |
| `docker compose` rejects `!override` | Compose is older than 2.24.4. Update the Docker Compose plugin |
| Every TLS handshake for EasyPatch fails; Caddy logs handshake errors | Caddy is running EasyPatch's stock `Caddyfile` and is reading EasyRMM's PROXY header as TLS. Use the override, which runs `Caddyfile.easyrmm` |
| EasyPatch's audit log shows `172.30.0.1` for everyone | The PROXY header is not getting through. Either `EASYRMM_EASYPATCH_PROXY_PROTOCOL` is `false`, or `EASYPATCH_EDGE_SUBNET` does not match the subnet Caddy's network really has (`docker network inspect <project>_edge`) |
| Caddy cannot get a certificate | Check that `patch.example.com` resolves to this server (and its AAAA record, if any) and that 80 and 443 are open from the internet. A certificate authority reaches Caddy only through EasyRMM, so EasyRMM must be running |

## Security notes

* Caddy listens only on loopback. Nothing on the network reaches EasyPatch
  except through EasyRMM's edge.
* **The PROXY header cannot be forged from outside.** The edge passes
  through only connections that start with a TLS handshake, and puts its own
  header in front of each one. A client that sends its own header gets
  EasyRMM's TLS server, which drops it.
* **Only EasyPatch's edge network may send PROXY headers to Caddy**, and
  only local processes can reach its ports. A connection without a header is
  served with its real source address.
* EasyRMM holds no EasyPatch key or certificate and cannot read its
  traffic. Restarting EasyRMM drops EasyPatch connections that are open at
  the time. Agents retry, and browsers reconnect.
* **Neither product sets a cookie for the parent domain.** Their sign-in
  cookies are `__Host-` cookies, bound to each product's own name.

## For EasyPatch's maintainers

EasyPatch 1.9.0 needs no change for this. Optional improvements:

* Ship `Caddyfile.easyrmm` in the `easypatch-proxy` image, next to
  `Caddyfile` and `Caddyfile.dev`. Ship `docker-compose.easyrmm.yml` in the
  repository. Users would then copy nothing, and the override would not
  need its `volumes` line.
* Mention co-hosting in EasyPatch's installation guide, including the
  `COMPOSE_FILE` line.
