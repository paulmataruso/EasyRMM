# syntax=docker/dockerfile:1
#
# EasyRMM server image. Build from the repository root:
#   docker build -f docker/server/Dockerfile -t easyrmm-server .
#
# The server runs as an unprivileged user. The binary carries the
# cap_net_bind_service file capability so it can bind 443/80 with host
# networking; the Compose file drops every other capability.

ARG NODE_IMAGE=node:24-alpine3.24@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
ARG GO_IMAGE=golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
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
COPY internal/ internal/
COPY server/ server/
COPY --from=web /src/web/dist/ server/internal/webui/dist/
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X github.com/paulmataruso/easyrmm/server/internal/app.Version=${VERSION}" \
      -o /out/easyrmm-server ./server/cmd/easyrmm-server \
 && setcap cap_net_bind_service=+ep /out/easyrmm-server

# --- Agents ------------------------------------------------------------------
# The EasyRMM agent for every platform the installers support. The server
# hands these out (ADR-0015) and updates enrolled agents to them (ADR-0027);
# they are static and the same for every server. VERSION names their
# version for the console. Built on the build machine's platform, so that
# every image's agents are the same bytes, cross-compiled by one toolchain as
# scripts/release/agents.sh builds a release's (check-agents.sh, ADR-0049).
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS agents
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY internal/ internal/
COPY agent/ agent/
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -e; mkdir -p /out/agents; \
    for arch in amd64 arm64; do \
      CGO_ENABLED=0 GOOS=windows GOARCH=$arch go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.Version=${VERSION}" \
        -o /out/agents/easyrmm-agent-windows-$arch.exe ./agent/cmd/easyrmm-agent; \
    done; \
    for arch in amd64 arm64 arm 386; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOARM=7 go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.Version=${VERSION}" \
        -o /out/agents/easyrmm-agent-linux-$arch ./agent/cmd/easyrmm-agent; \
    done; \
    echo "${VERSION}" > /out/agents/VERSION

# --- Runtime -----------------------------------------------------------------
FROM ${RUNTIME_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="EasyRMM server" \
      org.opencontainers.image.description="Self-hosted RMM and patch management for Windows and Linux" \
      org.opencontainers.image.source="https://github.com/paulmataruso/easyrmm" \
      org.opencontainers.image.licenses="FSL-1.1-ALv2" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=server /out/easyrmm-server /usr/local/bin/easyrmm-server
COPY --from=agents /out/agents/ /usr/share/easyrmm/agents/
USER 65532:65532
ENV EASYRMM_DATA_DIR=/var/lib/easyrmm
HEALTHCHECK --interval=30s --timeout=6s --start-period=90s --retries=3 \
  CMD ["/usr/local/bin/easyrmm-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/easyrmm-server"]
CMD ["serve"]
