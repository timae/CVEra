# CVEra — Vulnerability Monitoring for Managed Services

> **Core assumption:** You control all service versions. Every client runs exactly what you deploy.
> Version is a property of your managed catalog, not of each client.
> This eliminates per-client version tracking and simplifies the entire pipeline.

CVEra is a production-grade internal vulnerability monitoring platform for managed service providers. It maintains a catalog of the services you deploy, tracks which clients run which catalog entries, ingests structured vulnerability intelligence from authoritative feeds, matches affected catalog entries with a confidence-scored engine, and delivers Slack alerts scoped to the managed offering — listing all affected clients in a single notification.

---

## How It Works

A CVE hits **HAProxy 2.8.3** once in the catalog → one match is created → one alert fires → the alert lists all clients running that service. When you patch to 2.8.5 and update the catalog, the match is automatically invalidated for everyone.

```
┌──────────────────────────────────────────────────────────────────┐
│                       Single Binary (vulnmond)                    │
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
vulnmon/
├── cmd/vulnmon/            # main() — cobra CLI entrypoint
│   └── main.go
├── internal/
│   ├── alerting/           # Alert engine + Slack notifier
│   │   └── slack/
│   ├── api/                # HTTP server (/healthz, /readyz, /metrics)
│   ├── config/             # Config struct + Viper loading
│   ├── db/                 # pgxpool connect + goose migrations
│   ├── ingestion/          # Source abstraction, runner, NVD source
│   │   └── nvd/
│   ├── matching/           # CPE matcher, package matcher, engine
│   ├── models/             # Domain types (CatalogService, Alert, Match, …)
│   ├── normalize/          # Version normalization, CPE parsing, product aliases
│   ├── repository/         # PostgreSQL repository implementations + interfaces
│   └── scheduler/          # cron wrapper with pg_try_advisory_lock
├── migrations/             # goose SQL migrations
│   └── 00001_initial_schema.sql
├── configs/
│   ├── config.example.yaml
│   ├── catalog.example.yaml   # Argo CD, HAProxy, Loki, Grafana, …
│   └── clients.example.yaml
├── deploy/
│   ├── Dockerfile             # Distroless multi-stage, non-root
│   └── docker-compose.yml     # Postgres + vulnmond for local dev
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

### Prerequisites

- Go 1.22+
- Docker + Docker Compose
- PostgreSQL 16 (or use the compose stack)
- NVD API key (free — get at https://nvd.nist.gov/developers/request-an-api-key)

### Local Development

```bash
# Start Postgres
docker compose -f deploy/docker-compose.yml up -d postgres

# Build the binary
make build

# Copy and edit config
cp configs/config.example.yaml configs/config.yaml
# → set database.password, ingestion.nvd.api_key, alerting.slack.webhook_url

# Run migrations
make migrate-up

# Load example catalog and clients
make seed

# Start the daemon
make run
```

### Available Make Targets

```
make build           Compile ./bin/vulnmon
make test            Unit tests
make test-int        Integration tests (requires running Postgres)
make lint            golangci-lint
make docker-build    Build production Docker image
make migrate-up      Apply pending migrations
make migrate-down    Roll back last migration
make seed            Import catalog.example.yaml + clients.example.yaml
make run             Start daemon locally
make up / down       Start/stop full Compose stack
make help            Show all targets
```

---

## Configuration

Configuration is loaded from a YAML file (default: `configs/config.yaml`). Every value can be overridden with an environment variable using the `VULNMON_` prefix.

```yaml
database:
  host:     localhost
  port:     5432
  user:     vulnmon
  password: ""           # VULNMON_DATABASE_PASSWORD

ingestion:
  nvd:
    api_key:  ""         # VULNMON_INGESTION_NVD_API_KEY
    schedule: "0 * * * *"   # hourly
  cisa_kev:
    schedule: "0 6 * * *"   # daily
  epss:
    schedule: "30 6 * * *"  # daily

alerting:
  slack:
    webhook_url: ""      # VULNMON_ALERTING_SLACK_WEBHOOK_URL
    channel: "#security-alerts"
  min_severity:   high
  min_confidence: strong
```

See [`configs/config.example.yaml`](configs/config.example.yaml) for the full annotated reference.

---

## CLI Reference

```
vulnmon serve                               Start the daemon
vulnmon migrate [up|down|status]            Database migrations
vulnmon catalog import --file=catalog.yaml  Import service catalog
vulnmon catalog list                        List catalog services
vulnmon catalog update --service=haproxy \
         --version=2.8.5                   Update deployed version
vulnmon client import --file=clients.yaml   Import client enrollments
vulnmon client list                         List clients
vulnmon alert list                          List active alerts
vulnmon alert ack <id> --note="..."        Acknowledge alert
vulnmon alert suppress \
  --cve=CVE-2024-1234 \
  --service=haproxy \
  --reason="Not affected"                  Suppress alert
vulnmon ingest run [--source=nvd]           Trigger manual ingestion
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `jackc/pgx/v5` | PostgreSQL driver + connection pool |
| `pressly/goose/v3` | SQL migrations |
| `robfig/cron/v3` | Cron scheduler |
| `spf13/cobra` + `viper` | CLI + config loading |
| `uber-go/zap` | Structured JSON logging |
| `prometheus/client_golang` | Metrics |
| `Masterminds/semver/v3` | Version comparison and range checking |
| `google/uuid` | UUID generation |

---

## Implementation Status

### Scaffold Complete ✅

| Layer | Status | Notes |
|-------|--------|-------|
| Models | ✅ | All domain types defined |
| Config | ✅ | Viper loading + validation |
| DB connect + migrate | ✅ | pgxpool + goose |
| Repository interfaces | ✅ | All 8 interfaces defined |
| Repository stubs | ✅ | pgx implementations stubbed (panics) |
| Ingestion abstraction | ✅ | `VulnerabilitySource` interface + runner |
| NVD source | ✅ | Pagination, retry, checkpointing skeleton |
| Version normalizer | ✅ | Semver, calver, distro suffix stripping |
| CPE parser | ✅ | CPE 2.3 parsing + matching helpers |
| CPE matcher | ✅ | Exact + version range confidence |
| Package matcher | ✅ | Skeleton (OSV range parsing TODO) |
| Matching engine | ✅ | Wiring skeleton |
| Alerting engine | ✅ | Dedup + suppression check skeleton |
| Slack notifier | ✅ | Block Kit payload + retry |
| Scheduler | ✅ | Advisory lock + cron wiring |
| HTTP API | ✅ | `/healthz`, `/readyz`, `/metrics` |
| CLI entrypoint | ✅ | cobra `serve`, `migrate`, `catalog`, `client`, `alert`, `ingest` |
| Migration | ✅ | Full schema (goose up/down) |
| Dockerfile | ✅ | Distroless, non-root |
| docker-compose | ✅ | Postgres + daemon, local dev |
| Makefile | ✅ | build, test, lint, migrate, seed, docker |
| Config examples | ✅ | config, catalog (7 services), clients (3 tenants) |

### Pending Implementation 🔧

| Ticket | Description |
|--------|-------------|
| `VM-01` | Wire up all repository `panic("not implemented")` stubs with real pgx queries |
| `VM-02` | Complete NVD pagination and checkpoint persistence |
| `VM-03` | Implement CISA KEV source (`ingestion/kev/source.go`) |
| `VM-04` | Implement EPSS enrichment source (`ingestion/epss/source.go`) |
| `VM-05` | Implement OSV.dev source + package range matching |
| `VM-06` | Complete `matching/engine.go` — RunForVulnerability + RunForCatalogService |
| `VM-07` | Complete `alerting/engine.go` — alert creation, dedup, send, re-trigger |
| `VM-08` | Implement `catalog import` + `client import` CLI commands |
| `VM-09` | Integration test suite with testcontainers-go |
| `VM-10` | Audit logger (`internal/audit/logger.go`) |

---

## Architecture Decisions

**False positives are the primary enemy.** Every matching and alerting decision is made with this in mind — hence the four-tier confidence system and the `min_confidence` config gate.

**No microservices.** The pipeline is sequential with shared database state. One binary, one deployment unit, one log stream. Split only when you have a measured reason.

**No per-client version tracking.** You control the stack. Version lives in the catalog. Matching and alerting complexity drops by an order of magnitude.

**Import cycles prevented by function types.** `MatchTrigger` and `AlertTrigger` are defined as function values in their consumer packages (ingestion and matching respectively), not as interface imports, preventing circular dependencies.

---

## License

Internal tool — not for public distribution.
