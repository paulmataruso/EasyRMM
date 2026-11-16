# Running behind NGINX (TLS offload)

The built-in TLS edge is the simplest and recommended setup. If you already
run NGINX on the host (or a load balancer in front of it), EasyRMM can sit
behind it instead. NGINX is supported, never required.

## EasyRMM settings

In `deploy/.env`:

```bash
EASYRMM_TLS_MODE=offload
EASYRMM_LISTEN_HTTP=
EASYRMM_TRUSTED_PROXIES=127.0.0.1/32,::1/128
```

The server then listens only on `127.0.0.1:18080` (plain HTTP on loopback;
any non-loopback address is refused at start-up). `X-Forwarded-For` is
honored only when the connection comes from a trusted proxy, and the
right-most untrusted address is taken as the client, so clients cannot spoof
their address. EasyRMM never trusts `X-Forwarded-Proto`: in offload mode it
assumes the public side is HTTPS, as `EASYRMM_PUBLIC_URL` says.

## NGINX configuration

Both host names go to the same upstream; EasyRMM routes by `Host`, host
and port.

```nginx
upstream easyrmm {
    server 127.0.0.1:18080;
    keepalive 32;
}

map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      '';
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name rmm.example.com mesh.rmm.example.com;

    ssl_certificate     /etc/letsencrypt/live/rmm.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/rmm.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Agents upload inventory and script output; browsers upload files for
    # remote sessions.
    client_max_body_size 64m;

    location / {
        proxy_pass http://easyrmm;
        proxy_http_version 1.1;
        # $http_host keeps the port, which tells the console and MeshCentral
        # apart on an IP address (ADR-0016).
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # Agent and remote-session WebSockets.
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_buffering off;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name rmm.example.com mesh.rmm.example.com;
    return 308 https://$host$request_uri;
}
```

Notes:

* Keep `proxy_set_header Host $http_host`: EasyRMM rejects requests for
  addresses it does not serve (HTTP 421), and on an IP address only the port
  separates the console from MeshCentral.
* Do not add caching for `/api/`; responses are marked `no-store`.
* EasyRMM sets its own security headers (CSP, HSTS, frame and referrer
  policy). Do not add conflicting ones in NGINX.
* NGINX on the host uses host networking naturally; if NGINX runs in a
  container, give it `network_mode: host` as well.
* The certificate for the MeshCentral name must be one browsers trust:
  remote sessions are embedded from it.
* MeshCentral reads the certificate its agents pin from
  `https://127.0.0.1:443` (this NGINX), asking for the MeshCentral host name.
  If NGINX does not listen on loopback port 443, set `EASYRMM_MESH_CERT_URL`
  to an address where it presents that certificate. After a renewal,
  MeshCentral reloads the certificate the first time an agent reports a
  mismatch, and the agents reconnect.

## IP access behind NGINX

In offload mode NGINX owns the ports and the certificates, so EasyRMM does
not detect addresses or serve its own certificate authority (ADR-0016).
To reach the server by IP address as well, list the addresses and give
NGINX a certificate that names them (from your own CA):

```bash
EASYRMM_IP_ADDRESSES=203.0.113.10
```

```nginx
server {
    listen 443 ssl;           # the console: https://203.0.113.10
    listen 4443 ssl;          # remote sessions: https://203.0.113.10:4443
    server_name 203.0.113.10;
    ssl_certificate     /etc/nginx/tls/ip-fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/ip-privkey.pem;
    # ...the same location block as above, with Host $http_host.
}
```

The install command the console shows for such an address has no key pin
(the pin belongs to EasyRMM's own authority), so the machines you install
must trust NGINX's certificate. The built-in edge in `internal` mode avoids
that step.
