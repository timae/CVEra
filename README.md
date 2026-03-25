# CVEra — Vulnerability Monitoring for Managed Services

> **Core assumption:** You control all service versions. Every client runs exactly what you deploy.
> Version is a property of your managed catalog, not of each client.
> This eliminates per-client version tracking and simplifies the entire pipeline.

CVEra is an internal vulnerability-monitoring platform for managed service providers. It maintains a catalog of the services you deploy, tracks which clients run which catalog entries, ingests structured vulnerability intelligence from authoritative feeds, matches vulnerabilities against your managed catalog, creates alert records, and exposes health and status endpoints for operating the daemon.

> **Current state:** build, migration, seeding, daemon startup, NVD ingestion, matching orchestration, and alert-record creation are working and verified. Slack delivery works only when explicitly enabled and configured. KEV, EPSS, and OSV ingestion are still not implemented.

---

## How It Works

A CVE hits **HAProxy 2.8.3** once in the catalog → one match is created → one alert fires → the alert lists all clients running that service. When you patch to 2.8.5 and update the catalog, the match is automatically invalidated for everyone.

```
┌──────────────────────────────────────────────────────────────────┐
│                       Single Binary (cverad)                    │
│                                                                    │
│  ┌──────────┐   ┌───────────┐   ┌────────────┐   ┌───────────┐  │
│  │Scheduler │──▶│ Ingestion │──▶│ Normalizer │──▶│  Matcher  │  │
│  │ (cron)   │   │  Jobs     │   │            │   │           │  │
│  └──────────┘   └───────────┘   └────────────┘   └─────┬─────┘  │
│                                                          │         │
│  ┌──────────┐   ┌───────────┐   ┌────────────┐         │         │
│  │ HTTP API │   │   Audit   │   │  Alerting  │◀────────┘         │
│  │ (health) │   │   Log     │   │  (Slack)   │                   │
│  └──────────┘   └───────────┘   └────────────┘                   │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │                    PostgreSQL (pgx/v5)                        │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘

External Sources:
  NVD API v2    → CVEs, CPE, CVSS v3/v4
  CISA KEV      → Known exploited vulnerabilities
  OSV.dev       → Package ecosystem advisories (Go, npm, etc.)
  FIRST EPSS    → Exploitability probability scores
```

**Why a modular monolith:** The pipeline stages are naturally sequential with shared database state. No distributed systems overhead. One binary to deploy, monitor, and debug. PostgreSQL handles scheduling locks, state, and audit.

---

## Vulnerability Sources

CVEra uses structured APIs — not HTML scraping. The NVD API v2 gives you structured CPE matches, CVSS v3.1 + v4.0 vectors, CWE IDs, version ranges, and lifecycle status, with `lastModStartDate` incremental polling.

| Source | Protocol | Frequency | Value |
|--------|----------|-----------|-------|
| NVD API v2 | REST/JSON | Hourly incremental | CVEs, CPE, CVSS, status |
| CISA KEV | JSON file | Daily | Actively exploited CVEs |
| OSV.dev | REST/JSON | On-demand per service | Package ecosystem advisories |
| FIRST EPSS | REST/JSON | Daily | Exploitability probability |

---

## Repository Layout

```
cvera/
├── cmd/cvera/            # main() — cobra CLI entrypoint
│   └── main.go
├── internal/
│   ├── alerting/           # Alert engine + Slack notifier
│   │   └── slack/
│   ├── api/                # HTTP server (/healthz, /readyz, /metrics)
│   ├── config/             # Config struct + Viper loading
│   ├── db/                 # database/sql abstraction (SQLite + Postgres) + goose
│   ├── ingestion/          # Source abstraction, runner, NVD source
│   │   └── nvd/
│   ├── matching/           # CPE matcher, package matcher, engine
│   ├── models/             # Domain types (CatalogService, Alert, Match, …)
│   ├── normalize/          # Version normalization, CPE parsing, product aliases
│   ├── repository/         # PostgreSQL repository implementations + interfaces
│   └── scheduler/          # cron wrapper with pg_try_advisory_lock
├── migrations/
│   ├── postgres/           # PostgreSQL schema (goose)
│   └── sqlite/             # SQLite schema (goose)
├── configs/
│   ├── config.example.yaml
│   ├── catalog.example.yaml   # Argo CD, HAProxy, Loki, Grafana, …
│   └── clients.example.yaml
├── deploy/
│   ├── Dockerfile             # Distroless multi-stage, non-root
│   └── docker-compose.yml     # Postgres + cverad for local dev
├── pkg/retry/              # Exponential backoff with full jitter
├── testdata/
├── go.mod
└── Makefile
```

---

## Data Model

### Entities

**`catalog_services`** — One entry per managed service you offer (e.g. `haproxy`, `argo-cd`, `loki`). The `current_version` field is the single source of truth for all clients. Updating it triggers automatic match re-evaluation.

**`clients`** — A tenant organisation. Thin record: name, slug, contact email.

**`client_enrollments`** — Which catalog services a client runs. Thin join table with optional per-client overrides for `criticality` and `exposure` (e.g. a client where HAProxy is public-facing).

**`vulnerabilities`** — Normalized advisory record (CVE-ID, CVSS score/vector, EPSS, KEV status, CPE matches as JSONB).

**`matches`** — A `(catalog_service, vulnerability)` pair with confidence level and match evidence. One match covers all enrolled clients. Invalidated when the catalog version changes.

**`alerts`** — Notification state for a `(catalog_service, vulnerability)` pair. Dedup key: `{catalog_slug}:{vuln_id}`. Carries a JSONB snapshot of affected clients at alert time.

**`suppressions`** — Manual rules preventing alerts, scoped by CVE, catalog service, or both.

**`ingestion_checkpoints`** — Per-source cursor (e.g. ISO timestamp for NVD incremental polling).

### Key Design Decisions

- **Version is a catalog property, not a client property.** Matching runs once against the catalog entry. One match → one alert → all clients listed.
- **ClientEnrollment allows overrides.** A client can have a higher criticality or different exposure context without duplicating version state.
- **Matches are immutable; alerts are stateful.** A match records the fact of vulnerability; an alert records what you did about it.
- **Dedup key** `{catalog_slug}:{vuln_id}` ensures exactly one alert per CVE per service type, regardless of enrolled client count.
- **PostgreSQL advisory locks** (`pg_try_advisory_lock`) prevent concurrent ingestion runs across replicas.

---

## Matching Engine

### Confidence Levels

| Level | Meaning |
|-------|---------|
| `exact` | CPE 2.3 verbatim match on vendor, product, and version |
| `strong` | Version confirmed inside a `versionStartIncluding`/`versionEndExcluding` range |
| `weak` | Product name fuzzy match only, version unconfirmed |
| `unknown` | Version unparseable or `latest` |

### CPE Product Aliases

Some projects use inconsistent CPE vendor/product strings. Known mappings handled in `normalize/product.go`:

| Display Name | CPE Vendor:Product |
|---|---|
| Argo CD | `argoproj:argo_cd` |
| Grafana Loki | `grafana:loki` |
| Fluent Bit | `treasuredata:fluent_bit` |
| HAProxy | `haproxy:haproxy` |

### Version Normalization

Handles semver, calver, Debian suffixes (`-4+deb11u3`), Alpine suffixes, OpenSSH-style (`7.4p1`), and maps `latest` → `unknown`.

---

## Alert Lifecycle

```
pending → sent → acknowledged
                  suppressed
                  resolved
                  re_triggered   ← CVE re-scored or KEV status changed
```

Slack alerts use Block Kit with severity colour-coding, CVSS + EPSS scores, KEV badge, and a collapsible client list (10-item cap with overflow count).

---

## Getting Started

> **New here?** Read the full step-by-step [TUTORIAL.md](TUTORIAL.md) — it covers everything from installing Go to receiving your first Slack alert.

### Quick Start (SQLite — no database server required)

```bash
git clone https://github.com/timae/CVEra.git && cd CVEra

# Build
make build

# Copy config (SQLite is the default)
cp configs/config.example.yaml configs/config.yaml
# Optional:
#   - set ingestion.nvd.api_key for higher NVD rate limits
#   - set alerting.slack.enabled=true and alerting.slack.webhook_url to send Slack notifications

# Create schema and seed example data
make migrate-up
make seed

# Run one manual NVD ingestion pass
make ingest

# Start the daemon
make run
```

### PostgreSQL mode

Change one block in `configs/config.yaml`:

```yaml
database:
  backend:   postgres
  host:      localhost
  port:      5432
  user:      cvera
  password:  your-password
  name:      cvera
  ssl_mode:  require
```

Then `make migrate-up && make run`. For local Docker-based Postgres, see `deploy/docker-compose.yml`.

### Docker

```bash
# SQLite (default)
docker compose -f deploy/docker-compose.yml up -d cverad-sqlite

# PostgreSQL
docker compose -f deploy/docker-compose.yml --profile postgres up -d
```

### Available Make Targets

```
make build           Compile ./bin/cvera
make test            Unit tests
make test-int        Integration tests (requires running Postgres; no test files yet)
make lint            golangci-lint
make docker-build    Build production Docker image
make migrate-up      Apply pending migrations
make migrate-down    Roll back last migration
make seed            Import catalog.example.yaml + clients.example.yaml
make run             Start daemon locally
make ingest          Trigger one manual NVD ingestion run
make up / down       Start/stop full Compose stack
make help            Show all targets
```

---

## Configuration

Configuration is loaded from a YAML file (default: `configs/config.yaml`). Every value can be overridden with an environment variable using the `CVERA_` prefix.

```yaml
# SQLite (default — zero infrastructure)
database:
  backend:     sqlite
  sqlite_path: cvera.db

# PostgreSQL (multi-replica / production)
# database:
#   backend:   postgres
#   host:      localhost
#   port:      5432
#   user:      cvera
#   password:  ""         # CVERA_DATABASE_PASSWORD

ingestion:
  nvd:
    enabled: true
    api_key: ""               # CVERA_INGESTION_NVD_API_KEY
    api_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    schedule: "0 * * * *"
    initial_lookback: 720h
    results_per_page: 2000
  cisa_kev:
    enabled: true
    schedule: "0 6 * * *"
  epss:
    enabled: true
    schedule: "30 6 * * *"

alerting:
  slack:
    enabled: false
    webhook_url: ""      # CVERA_ALERTING_SLACK_WEBHOOK_URL
    channel: "#security-alerts"
  min_cvss_score: 7.0

matching:
  min_confidence: weak
  min_alert_confidence: strong
```

See [`configs/config.example.yaml`](configs/config.example.yaml) for the full annotated reference.

---

## CLI Reference

```
cvera serve                              Start the daemon
cvera migrate up|down|status             Database migrations
cvera catalog import <catalog.yaml>      Import service catalog
cvera catalog list                       List catalog services
cvera client import <clients.yaml>       Import clients + enrollments
cvera client list                        List clients
cvera ingest run                         Trigger manual NVD ingestion
```

`alert` subcommands and catalog version update flows are not implemented yet.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `jackc/pgx/v5` | PostgreSQL driver (via `database/sql` stdlib adapter) |
| `modernc.org/sqlite` | SQLite driver, pure Go — no CGO required |
| `pressly/goose/v3` | SQL migrations |
| `robfig/cron/v3` | Cron scheduler |
| `spf13/cobra` + `viper` | CLI + config loading |
| `uber-go/zap` | Structured JSON logging |
| `prometheus/client_golang` | Metrics |
| `Masterminds/semver/v3` | Version comparison and range checking |
| `google/uuid` | UUID generation |

---

## Verified State

The following paths were exercised successfully against the current tree:

- `make build`
- `make test`
- `make migrate-up`
- `make seed`
- `./bin/cvera --config configs/config.example.yaml ingest run`
- `./bin/cvera --config configs/config.example.yaml serve`
- `GET /healthz`
- `GET /readyz`
- `GET /api/v1/status`
- deterministic SQLite orchestration test for match + alert creation

The live NVD smoke test completed successfully and updated the ingestion checkpoint. A deterministic SQLite test also verified that one synthetic vulnerability produces one match and one pending alert.

## Remaining Gaps

- CISA KEV, EPSS, and OSV ingestion sources are not implemented
- OSV package-range matching is not implemented yet
- Alert lifecycle is still basic: no full re-trigger, resolve, or operator workflow
- Catalog version update and alert-management CLI flows are not implemented
- There is no real integration test suite yet

---

## Deployment Pipeline Example

One practical way to use CVEra in a managed-service deployment pipeline is to treat the service catalog as the source of truth for what version is currently deployed to customers.

Example flow:

1. Build and test the service you are deploying.
2. Roll the new version out through your normal deployment system.
3. Update the matching catalog entry in CVEra to the version you actually shipped.
4. Run CVEra ingestion and matching immediately after the deployment update.
5. Review any newly created alerts before closing the rollout.

In a simple CI/CD pipeline, that can look like this:

```bash
# Deploy your managed service first
./deploy-haproxy.sh --version 2.8.6

# Update the CVEra catalog entry
./bin/cvera --config configs/config.yaml catalog import configs/catalog.example.yaml

# Pull the latest NVD changes and recompute matches/alerts
./bin/cvera --config configs/config.yaml ingest run
```

In a more complete production setup, the intended logic is:

- Store the catalog YAML in the same repo as your deployment manifests.
- Change `current_version` in the catalog in the same PR that changes the shipped version.
- After rollout, import the catalog into CVEra.
- Trigger `ingest run` as a post-deploy job, or rely on the scheduler for steady-state updates.
- If new alerts appear for the just-deployed version, fail the post-deploy verification stage or route the result to Slack/Jira.

For Kubernetes or GitOps-style delivery, a typical sequence would be:

1. Merge a PR that bumps both the Helm chart/image tag and the CVEra catalog version.
2. Argo CD or Flux applies the workload change.
3. A post-sync job calls `cvera catalog import ...` and `cvera ingest run`.
4. CVEra refreshes matches against the deployed version and creates any new alert records.
5. Your pipeline reads the resulting alert state or monitors Slack for critical findings.

The important rule is simple: only update CVEra after the deployed version is real. CVEra should reflect the version customers are actually running, not the version someone hopes to ship later.

---

## Architecture Decisions

**False positives are the primary enemy.** Every matching and alerting decision is made with this in mind — hence the four-tier confidence system and the `min_confidence` config gate.

**No microservices.** The pipeline is sequential with shared database state. One binary, one deployment unit, one log stream. Split only when you have a measured reason.

**No per-client version tracking.** You control the stack. Version lives in the catalog. Matching and alerting complexity drops by an order of magnitude.

**Import cycles prevented by function types.** `MatchTrigger` and `AlertTrigger` are defined as function values in their consumer packages (ingestion and matching respectively), not as interface imports, preventing circular dependencies.

---

## License

Internal tool — not for public distribution.
