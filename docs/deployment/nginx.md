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

Both host names go to the same upstream; EasyRMM routes by `Host`.

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
        proxy_set_header Host $host;
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

* Keep `proxy_set_header Host $host`: EasyRMM rejects requests for host names
  it does not serve (HTTP 421).
* Do not add caching for `/api/`; responses are marked `no-store`.
* EasyRMM sets its own security headers (CSP, HSTS, frame and referrer
  policy). Do not add conflicting ones in NGINX.
* NGINX on the host uses host networking naturally; if NGINX runs in a
  container, give it `network_mode: host` as well.
