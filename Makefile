## ─── CVEra Makefile ────────────────────────────────────────────────────────
##
## Usage:
##   make build          – compile the binary
##   make test           – run unit tests
##   make test-int       – run integration tests (requires running Postgres)
##   make lint           – run golangci-lint
##   make docker-build   – build the production Docker image
##   make migrate-up     – apply all pending migrations (uses .env for DSN)
##   make migrate-down   – roll back the last migration
##   make migrate-status – print migration status
##   make seed           – load configs/catalog.example.yaml + clients.example.yaml
##   make run            – run the daemon locally (docker-compose must be up)
##   make up             – start docker-compose dev stack
##   make down           – stop docker-compose dev stack
##   make clean          – remove build artefacts

# ── Variables ─────────────────────────────────────────────────────────────────

BINARY      := cvera
CMD_PKG     := ./cmd/cvera
OUT_DIR     := bin
DIST_DIR    := dist

IMAGE_NAME  ?= cvera
IMAGE_TAG   ?= dev
REGISTRY    ?=

# Load .env if it exists (never fail if absent)
-include .env
export

GO          := go
GOFLAGS     ?=
LDFLAGS     := -s -w \
               -X 'main.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)' \
               -X 'main.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)' \
               -X 'main.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'

DOCKER_COMPOSE := docker compose
COMPOSE_FILE   := deploy/docker-compose.yml

GOLANGCI_LINT_VERSION ?= v1.57.2

# ── Default target ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := build

# ── Build ──────────────────────────────────────────────────────────────────────

.PHONY: build
build: ## Compile the binary into ./bin/cvera
	@mkdir -p $(OUT_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY) $(CMD_PKG)
	@echo "→ $(OUT_DIR)/$(BINARY)"

.PHONY: build-linux
build-linux: ## Cross-compile a static linux/amd64 binary (for Docker)
	@mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-linux-amd64 $(CMD_PKG)

.PHONY: install
install: ## Install binary to $GOPATH/bin
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" $(CMD_PKG)

# ── Test ───────────────────────────────────────────────────────────────────────

.PHONY: test
test: ## Run unit tests (no external dependencies)
	$(GO) test $(GOFLAGS) -race -count=1 ./... -short

.PHONY: test-int
test-int: ## Run integration tests (requires CVERA_DATABASE_DSN or running Compose stack)
	$(GO) test $(GOFLAGS) -race -count=1 -run Integration ./...

.PHONY: test-cover
test-cover: ## Run tests with coverage report
	@mkdir -p $(DIST_DIR)
	$(GO) test $(GOFLAGS) -race -coverprofile=$(DIST_DIR)/coverage.out ./...
	$(GO) tool cover -html=$(DIST_DIR)/coverage.out -o $(DIST_DIR)/coverage.html
	@echo "→ $(DIST_DIR)/coverage.html"

# ── Lint ───────────────────────────────────────────────────────────────────────

.PHONY: lint
lint: ## Run golangci-lint
	@which golangci-lint >/dev/null 2>&1 || \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
		| sh -s -- -b $(shell go env GOPATH)/bin $(GOLANGCI_LINT_VERSION)
	golangci-lint run ./...

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Run gofmt and goimports
	$(GO) fmt ./...
	@which goimports >/dev/null 2>&1 && goimports -w . || true

# ── Docker ─────────────────────────────────────────────────────────────────────

.PHONY: docker-build
docker-build: ## Build the production Docker image
	docker build \
		-f deploy/Dockerfile \
		--build-arg LDFLAGS="$(LDFLAGS)" \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		.
	@echo "→ $(IMAGE_NAME):$(IMAGE_TAG)"

.PHONY: docker-push
docker-push: docker-build ## Push image to registry (set REGISTRY=your.registry.io)
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

# ── Docker Compose (local dev) ─────────────────────────────────────────────────

.PHONY: up
up: ## Start the local dev stack (Postgres + cverad)
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) up -d
	@echo "→ Postgres on localhost:5432, cverad on localhost:8080"

.PHONY: down
down: ## Stop the local dev stack
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) down

.PHONY: logs
logs: ## Tail logs from the dev stack
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) logs -f

.PHONY: ps
ps: ## Show running services
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) ps

# ── Database migrations ────────────────────────────────────────────────────────

MIGRATE_DSN ?= $(CVERA_DATABASE_DSN)

.PHONY: migrate-up
migrate-up: build ## Apply all pending migrations
	$(OUT_DIR)/$(BINARY) --config configs/config.yaml migrate up

.PHONY: migrate-down
migrate-down: build ## Roll back the last migration
	$(OUT_DIR)/$(BINARY) --config configs/config.yaml migrate down

.PHONY: migrate-status
migrate-status: build ## Show migration status
	$(OUT_DIR)/$(BINARY) --config configs/config.yaml migrate status

# ── Seeding ────────────────────────────────────────────────────────────────────

.PHONY: seed
seed: build ## Import example catalog and clients (idempotent)
	$(OUT_DIR)/$(BINARY) --config configs/config.yaml catalog import configs/catalog.example.yaml
	$(OUT_DIR)/$(BINARY) --config configs/config.yaml client  import configs/clients.example.yaml

# ── Run ────────────────────────────────────────────────────────────────────────

.PHONY: run
run: build ## Run the daemon with the local config (Compose DB must be up)
	$(OUT_DIR)/$(BINARY) --config configs/config.yaml serve

.PHONY: ingest
ingest: build ## Trigger a manual NVD ingestion run
	$(OUT_DIR)/$(BINARY) --config configs/config.yaml ingest run

# ── Tidy / Clean ───────────────────────────────────────────────────────────────

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf $(OUT_DIR) $(DIST_DIR)

# ── Help ───────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Display this help text
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
