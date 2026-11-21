# EasyRMM developer tasks. Run `make help` for a list.

SHELL := /bin/bash
GO ?= go
TEST_DB_CONTAINER ?= easyrmm-testdb
TEST_DB_PORT ?= 55432
TEST_DB_URL ?= postgres://postgres:easyrmm-test-only@127.0.0.1:$(TEST_DB_PORT)/postgres?sslmode=disable
POSTGRES_IMAGE ?= postgres:18.6-alpine3.24
# The MeshCentral release EasyRMM is tested with (keep in step with
# deploy/docker-compose.yml), and a glibc image the test MeshAgent runs in.
MESHCENTRAL_IMAGE ?= ghcr.io/ylianst/meshcentral:1.3.1@sha256:266b01942545829f11d53e6cecd5c2e48033d9edb48bbd3a9a569482ff1d050d
TEST_AGENT_IMAGE ?= debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
# Containers the hardening script's check runs in (ADR-0051), one of each
# family, each a fully supported release.
TEST_HARDENING_IMAGES ?= debian:12@sha256:268fb24c39bca92d326dd83ea3abebe4a3f7751c804ffef23bb6d857dd343ff8 \
	ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289 \
	rockylinux/rockylinux:9@sha256:bb5755f96bec05ff26165e779ec843d7167544be9e50770508f307019a6d05c4 \
	fedora:44@sha256:15da97ed9aa94dd3d92c3925eb89520f6c80e07ea7ee24cba848d1f8b6912b3e
TEST_MESH_DIR ?= $(or $(TMPDIR),/tmp)/easyrmm-testmesh
TEST_MESH_URL ?= http://127.0.0.1:24430
# The OpenID Connect provider single sign-on is tested against.
DEX_IMAGE ?= ghcr.io/dexidp/dex:v2.46.1@sha256:65b72ca0f4b0bf6d4ada84ec21da8851782563404ac7b8f926923d27ceced9ab
TEST_OIDC_DIR ?= $(or $(TMPDIR),/tmp)/easyrmm-testoidc
# Machine tests (internal/vmtest; ADR-0051): where the cloud images and the
# running machines' disks go (gigabytes, so not a small /tmp), the packages
# with vm-tagged tests, how many machines boot at once, and how long the
# whole run may take (without KVM each boot takes minutes).
VM_CACHE ?= /var/tmp/easyrmm-vmtest
VM_PACKAGES ?= ./internal/vmtest/
VM_PARALLEL ?= 2
VM_TEST_TIMEOUT ?= 3h

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-22s %s\n", $$1, $$2}'

.PHONY: fmt
fmt: ## Format Go code
	gofmt -w $$(git ls-files --cached --others --exclude-standard '*.go')

.PHONY: fmt-check
fmt-check: ## Fail if Go code is not formatted
	@out=$$(gofmt -l $$(git ls-files --cached --others --exclude-standard '*.go')); \
		if [ -n "$$out" ]; then echo "Unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet (including integration-, contract-, bundle- and vm-tagged files, and the agent built for Windows)
	$(GO) vet ./...
	$(GO) vet -tags integration ./...
	$(GO) vet -tags contract ./server/internal/easypatch/
	$(GO) vet -tags bundle ./server/internal/easypatch/
	$(GO) vet -tags vm $(VM_PACKAGES)
	GOOS=windows $(GO) vet ./agent/... ./internal/...

.PHONY: lint
lint: ## golangci-lint, also over the agent built for Windows
	golangci-lint run ./...
	GOOS=windows golangci-lint run ./agent/... ./internal/...

.PHONY: test-unit
test-unit: ## Go unit tests with the race detector
	$(GO) test -race -count=1 ./...

.PHONY: test-db
test-db: ## Start a disposable PostgreSQL for integration tests (host networking)
	-@docker container stop $(TEST_DB_CONTAINER) >/dev/null 2>&1
	docker run -d --rm --name $(TEST_DB_CONTAINER) --network host \
		-e POSTGRES_PASSWORD=easyrmm-test-only $(POSTGRES_IMAGE) \
		-c port=$(TEST_DB_PORT) -c listen_addresses=127.0.0.1 -c fsync=off >/dev/null
	@for i in $$(seq 1 30); do docker exec $(TEST_DB_CONTAINER) pg_isready -h 127.0.0.1 -p $(TEST_DB_PORT) -q && break; sleep 1; done
	@echo "export EASYRMM_TEST_DATABASE_URL='$(TEST_DB_URL)'"

.PHONY: test-db-stop
test-db-stop: ## Stop (and thereby remove) the test database container
	docker container stop $(TEST_DB_CONTAINER)

.PHONY: test-mesh
test-mesh: ## Start a disposable MeshCentral for integration tests (host networking)
	MESHCENTRAL_IMAGE=$(MESHCENTRAL_IMAGE) EASYRMM_TEST_MESH_DIR=$(TEST_MESH_DIR) ./scripts/test-meshcentral.sh

.PHONY: test-mesh-stop
test-mesh-stop: ## Stop the test MeshCentral
	MESHCENTRAL_IMAGE=$(MESHCENTRAL_IMAGE) ./scripts/test-meshcentral.sh stop

.PHONY: test-oidc
test-oidc: ## Start a disposable Dex (OpenID Connect provider) for single sign-on tests (host networking)
	DEX_IMAGE=$(DEX_IMAGE) EASYRMM_TEST_OIDC_DIR=$(TEST_OIDC_DIR) ./scripts/test-oidc.sh

.PHONY: test-oidc-stop
test-oidc-stop: ## Stop the test Dex
	DEX_IMAGE=$(DEX_IMAGE) ./scripts/test-oidc.sh stop

.PHONY: print-test-agent-image
print-test-agent-image:
	@echo $(TEST_AGENT_IMAGE)

.PHONY: print-test-hardening-images
print-test-hardening-images:
	@echo $(TEST_HARDENING_IMAGES)

.PHONY: test-integration
test-integration: ## Go unit + integration tests against PostgreSQL, MeshCentral and Dex, with coverage gates
	EASYRMM_TEST_DATABASE_URL="$${EASYRMM_TEST_DATABASE_URL:-$(TEST_DB_URL)}" \
	EASYRMM_TEST_MESH_DIR="$${EASYRMM_TEST_MESH_DIR:-$(TEST_MESH_DIR)/config}" \
	EASYRMM_TEST_MESH_URL="$${EASYRMM_TEST_MESH_URL:-$(TEST_MESH_URL)}" \
	EASYRMM_TEST_AGENT_IMAGE="$${EASYRMM_TEST_AGENT_IMAGE:-$(TEST_AGENT_IMAGE)}" \
	EASYRMM_TEST_HARDENING_IMAGES="$${EASYRMM_TEST_HARDENING_IMAGES:-$(TEST_HARDENING_IMAGES)}" \
	EASYRMM_TEST_OIDC_DIR="$${EASYRMM_TEST_OIDC_DIR:-$(TEST_OIDC_DIR)}" \
		$(GO) test -race -count=1 -tags integration -covermode=atomic -coverpkg=./... -coverprofile=coverage.txt ./...
	./scripts/ci/check-coverage.sh coverage.txt

.PHONY: test-contract
test-contract: ## EasyRMM's calls to the patching engine against a real one built from easypatch/ (needs Docker)
	GO=$(GO) ./scripts/contract/easypatch.sh

.PHONY: test-vm
test-vm: ## Boot each distribution's cloud image under QEMU and drive it (EASYRMM_VM_IMAGE=debian-12 for one; needs qemu-system-x86_64, qemu-img, and xorriso for rocky-8)
	EASYRMM_VM_CACHE="$${EASYRMM_VM_CACHE:-$(VM_CACHE)}" \
		$(GO) test -tags vm -count=1 -v -timeout $(VM_TEST_TIMEOUT) -parallel $(VM_PARALLEL) $(VM_PACKAGES)

.PHONY: check
check: fmt-check vet lint test-integration ## Everything CI runs for Go code

.PHONY: build-agents
build-agents: ## Build the Windows and Linux agents into bin/agents (serve them with EASYRMM_AGENT_DIR=bin/agents)
	@mkdir -p bin/agents
	@v=$$(git describe --tags --match 'easyrmm-v*' --always --dirty 2>/dev/null || echo dev); v=$${v#easyrmm-}; \
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=windows GOARCH=$$arch $(GO) build -trimpath -ldflags "-s -w -X main.Version=$$v" \
			-o bin/agents/easyrmm-agent-windows-$$arch.exe ./agent/cmd/easyrmm-agent || exit 1; \
	done; \
	for arch in amd64 arm64 arm 386; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch GOARM=7 $(GO) build -trimpath -ldflags "-s -w -X main.Version=$$v" \
			-o bin/agents/easyrmm-agent-linux-$$arch ./agent/cmd/easyrmm-agent || exit 1; \
	done; \
	echo "$$v" > bin/agents/VERSION
	@ls -l bin/agents

.PHONY: build
build: ## Build the server binary into bin/
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/easyrmm-server ./server/cmd/easyrmm-server

# --- Web console --------------------------------------------------------------

web/node_modules/.package-lock.json: web/package-lock.json
	cd web && npm ci --no-audit --no-fund

.PHONY: web-deps
web-deps: web/node_modules/.package-lock.json ## Install the web console's locked dependencies

.PHONY: web
web: web-deps ## Build the web console and stage it for embedding in the server binary
	cd web && npm run build
	find server/internal/webui/dist -mindepth 1 ! -name .gitkeep -delete
	cp -R web/dist/. server/internal/webui/dist/

.PHONY: web-test
web-test: web-deps ## Typecheck and unit-test the web console, with coverage floors
	cd web && npm run typecheck && npm run test:coverage

.PHONY: e2e
e2e: web build build-agents ## Browser end-to-end tests against a real server (needs `make test-db`)
	cd web && EASYRMM_E2E_ADMIN_URL="$${EASYRMM_E2E_ADMIN_URL:-$(TEST_DB_URL)}" npx playwright test

.PHONY: e2e-bundle
e2e-bundle: ## The deployment with its patching engine, end to end: install, enroll, scan and patch a Linux machine (needs Docker, the .NET SDK and root or sudo)
	./scripts/e2e/bundle.sh

.PHONY: e2e-import
e2e-import: ## Import a standalone EasyPatch 1.10 server, with a real agent, into the deployment (needs Docker, the .NET SDK and root or sudo)
	./scripts/e2e/import.sh

.PHONY: e2e-authentik
e2e-authentik: ## The deployment with Authentik as its sign-in, end to end: invitation, second factor, refusal, recovery (needs Docker and root or sudo)
	./scripts/e2e/authentik.sh
