# syntax=docker/dockerfile:1
#
# EasyRMM server image. Build from the repository root:
#   docker build -f docker/server/Dockerfile -t easyrmm-server .
#
# The server runs as an unprivileged user. The binary carries the
# cap_net_bind_service file capability so it can bind 443/80 with host
# networking; the Compose file drops every other capability.

ARG NODE_IMAGE=node:24-alpine3.24@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
ARG GO_IMAGE=golang:1.27.3-alpine3.24@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

# --- Web interface -----------------------------------------------------------
FROM ${NODE_IMAGE} AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund --ignore-scripts
COPY web/ ./
RUN npm run build

# --- Server ------------------------------------------------------------------
FROM ${GO_IMAGE} AS server
RUN apk add --no-cache libcap
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY server/ server/
COPY --from=web /src/web/dist/ server/internal/webui/dist/
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X github.com/paulmataruso/easyrmm/server/internal/app.Version=${VERSION}" \
      -o /out/easyrmm-server ./server/cmd/easyrmm-server \
 && setcap cap_net_bind_service=+ep /out/easyrmm-server

# --- Runtime -----------------------------------------------------------------
FROM ${RUNTIME_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="EasyRMM server" \
      org.opencontainers.image.description="Open-source RMM for Windows and Linux" \
      org.opencontainers.image.source="https://github.com/paulmataruso/easyrmm" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=server /out/easyrmm-server /usr/local/bin/easyrmm-server
USER 65532:65532
ENV EASYRMM_DATA_DIR=/var/lib/easyrmm
HEALTHCHECK --interval=30s --timeout=6s --start-period=90s --retries=3 \
  CMD ["/usr/local/bin/easyrmm-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/easyrmm-server"]
CMD ["serve"]
