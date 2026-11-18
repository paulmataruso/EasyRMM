# syntax=docker/dockerfile:1
# EasyPatch proxy image: Caddy (TLS, security headers, reverse proxy) plus the built admin console.
# Build context: repository root.  docker build -f deployment/caddy/Dockerfile -t easypatch-proxy .

FROM node:24.22.3-alpine3.24 AS spa
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json frontend/.npmrc ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM caddy:2.11.9-alpine
COPY deployment/caddy/easypatch.caddy deployment/caddy/Caddyfile deployment/caddy/Caddyfile.dev /etc/caddy/
COPY --from=spa /src/dist /srv
