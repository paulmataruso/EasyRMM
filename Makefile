# EasyRMM developer tasks. Run `make help` for a list.

SHELL := /bin/bash
GO ?= go
TEST_DB_CONTAINER ?= easyrmm-testdb
TEST_DB_PORT ?= 55432
TEST_DB_URL ?= postgres://postgres:easyrmm-test-only@127.0.0.1:$(TEST_DB_PORT)/postgres?sslmode=disable
POSTGRES_IMAGE ?= postgres:18.6-alpine3.24

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
vet: ## go vet (including integration-tagged files)
	$(GO) vet ./...
	$(GO) vet -tags integration ./...

.PHONY: lint
lint: ## golangci-lint
	golangci-lint run ./...

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

.PHONY: test-integration
test-integration: ## Go unit + integration tests against PostgreSQL, with coverage gates
	EASYRMM_TEST_DATABASE_URL="$${EASYRMM_TEST_DATABASE_URL:-$(TEST_DB_URL)}" \
		$(GO) test -race -count=1 -tags integration -covermode=atomic -coverprofile=coverage.txt ./...
	./scripts/ci/check-coverage.sh coverage.txt

.PHONY: check
check: fmt-check vet lint test-integration ## Everything CI runs for Go code

.PHONY: build
build: ## Build the server binary into bin/
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/easyrmm-server ./server/cmd/easyrmm-server
