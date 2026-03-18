# CVEra — Setup Tutorial

This guide walks you through getting CVEra running from zero. No prior Go or database knowledge required.

---

## What CVEra Does

CVEra watches the services you deploy to clients (HAProxy, Argo CD, Loki, etc.) and alerts you on Slack when a CVE affects one of them. You define your services and clients in YAML files. CVEra polls the NVD (National Vulnerability Database), CISA KEV, and other sources automatically on a schedule.

---

## Prerequisites

You need the following tools installed. Click each link to download.

| Tool | Why | Download |
|------|-----|----------|
| **Go 1.22+** | Compiles and runs CVEra | https://go.dev/dl |
| **Git** | Clone the repo | https://git-scm.com |
| **Make** | Run project commands | Pre-installed on macOS/Linux; Windows: https://gnuwin32.sf.net/packages/make.htm |

That's it for the default SQLite mode. You do **not** need Docker or a database server to get started.

### Check your versions

Open a terminal and run:

```bash
go version    # should print go1.22 or higher
git --version
make --version
```

---

## Step 1 — Clone the repository

```bash
git clone https://github.com/timae/CVEra.git
cd CVEra
```

---

## Step 2 — Create your config file

Copy the example config and open it in any text editor:

```bash
cp configs/config.example.yaml configs/config.yaml
```

The default config uses **SQLite** — a single file on disk. No database server needed. If you open `configs/config.yaml` you'll see:

```yaml
database:
  backend:     sqlite
  sqlite_path: cvera.db   # this file is created automatically
```

Leave this as-is for now. You only need to fill in two things:

### 2a — NVD API key (free, takes 2 minutes)

CVEra fetches CVEs from the NVD API. Without a key you're rate-limited to 5 requests per 30 seconds, which is usually fine for a small catalog.

1. Go to https://nvd.nist.gov/developers/request-an-api-key
2. Enter your email and submit
3. You'll receive the key by email within a minute
4. Open `configs/config.yaml` and set:

```yaml
ingestion:
  nvd:
    api_key: "your-key-here"
```

Or set it as an environment variable instead:

```bash
export CVERA_INGESTION_NVD_API_KEY="your-key-here"
```

### 2b — Slack webhook URL (optional but recommended)

This is where CVEra sends alerts. Skip this step if you just want to see matching results in the database first.

1. Go to https://api.slack.com/apps → **Create New App** → **From scratch**
2. Name it `CVEra`, pick your workspace, click **Create App**
3. In the sidebar: **Incoming Webhooks** → toggle **Activate** → **Add New Webhook to Workspace**
4. Pick the channel (e.g. `#security-alerts`) → **Allow**
5. Copy the webhook URL (starts with `https://hooks.slack.com/services/...`)
6. Open `configs/config.yaml` and set:

```yaml
alerting:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    channel: "#security-alerts"
```

---

## Step 3 — Define your services

Open `configs/catalog.example.yaml`. This file defines which services you deploy. Copy it to a working file:

```bash
cp configs/catalog.example.yaml configs/catalog.yaml
```

Edit `configs/catalog.yaml` to match your actual deployments. Each entry looks like this:

```yaml
services:
  - slug:            haproxy
    name:            HAProxy
    cpe23:           "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"
    current_version: "2.8.5"          # ← the version YOU currently deploy
    default_criticality: critical
    default_exposure:    public
```

**The most important field is `current_version`** — this is the version you currently deploy to all clients. When a CVE affects this version, CVEra fires an alert.

### Finding the right CPE string

CPE (Common Platform Enumeration) is how the NVD identifies products. To find the right CPE for your service:

1. Go to https://nvd.nist.gov/products/cpe/search
2. Search for your product name (e.g. `haproxy`)
3. Copy the CPE 2.3 string from the result (it looks like `cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*`)
4. Use that string in your `catalog.yaml`, with `*` in the version field (CVEra fills in your actual version)

The example catalog already has correct CPE strings for Argo CD, HAProxy, Loki, Grafana, Fluent Bit, cert-manager, and NGINX Ingress.

---

## Step 4 — Define your clients

Open `configs/clients.example.yaml` and copy it:

```bash
cp configs/clients.example.yaml configs/clients.yaml
```

Add your clients and which services they run:

```yaml
clients:
  - slug:  acme-corp
    name:  Acme Corp
    contact_email: ops@acme.example.com
    enrollments:
      - service: haproxy
      - service: argo-cd
      - service: loki
```

Client names and emails are used in Slack alerts to show who is affected. If a CVE hits HAProxy, the alert lists every client running it.

---

## Step 5 — Build CVEra

```bash
make build
```

This compiles the binary to `./bin/cvera`. It takes about 30 seconds the first time (downloading dependencies). Subsequent builds are instant.

---

## Step 6 — Run migrations

This creates the database schema. With SQLite it creates `cvera.db` in the current directory:

```bash
make migrate-up
```

You should see output like:

```
OK   00001_initial_schema.sql (12.34ms)
goose: no migrations to run. current version: 1
```

---

## Step 7 — Import your catalog and clients

```bash
./bin/cvera catalog import configs/catalog.yaml
./bin/cvera client  import configs/clients.yaml
```

Verify they were imported:

```bash
./bin/cvera catalog list
./bin/cvera client  list
```

---

## Step 8 — Start the daemon

```bash
make run
```

Or directly:

```bash
./bin/cvera serve --config configs/config.yaml
```

You should see log output like:

```json
{"level":"info","msg":"cvera started"}
{"level":"info","msg":"scheduler started","jobs":["nvd_ingestion","cisa_kev","epss"]}
{"level":"info","msg":"job starting","job":"nvd_ingestion"}
```

CVEra will now:
- Poll NVD every hour for new/updated CVEs
- Match them against your catalog
- Send Slack alerts for any matches above your configured severity threshold

---

## Step 9 — Trigger a manual ingestion run

Don't want to wait an hour? Run an ingestion immediately:

```bash
./bin/cvera ingest run
```

Or just for NVD:

```bash
./bin/cvera ingest run --source=nvd
```

---

## Step 10 — Check alerts

```bash
./bin/cvera alert list
```

To acknowledge an alert (mark it as seen):

```bash
./bin/cvera alert ack <alert-id> --note="Patching in next release"
```

To suppress a CVE you've decided isn't relevant:

```bash
./bin/cvera alert suppress \
  --cve=CVE-2024-1234 \
  --service=haproxy \
  --reason="Not affected — using mitigating configuration"
```

---

## Updating a service version

When you upgrade a service (e.g. you patched HAProxy from 2.8.3 to 2.8.5):

```bash
./bin/cvera catalog update --service=haproxy --version=2.8.5
```

CVEra will automatically:
1. Record the version change in history
2. Invalidate all existing matches for HAProxy
3. Re-run matching on the next ingestion cycle
4. Resolve alerts that are no longer applicable

---

## Running with Docker (no Go required)

If you don't want to install Go, you can run CVEra with Docker:

```bash
# SQLite mode (default — no Postgres needed)
docker compose -f deploy/docker-compose.yml up -d cverad-sqlite
docker compose -f deploy/docker-compose.yml logs -f cverad-sqlite
```

Your database file is stored in a Docker volume and persists across restarts.

---

## Switching to PostgreSQL (production)

SQLite is fine for a single server. If you want to run multiple CVEra instances (e.g. in Kubernetes), switch to PostgreSQL.

1. Edit `configs/config.yaml`:

```yaml
database:
  backend:   postgres
  host:      your-postgres-host
  port:      5432
  user:      cvera
  password:  your-password
  name:      cvera
  ssl_mode:  require
```

2. Create the database (one-time):

```sql
CREATE USER cvera WITH PASSWORD 'your-password';
CREATE DATABASE cvera OWNER cvera;
```

3. Run migrations:

```bash
make migrate-up
```

Everything else stays the same.

---

## Common Problems

**`./bin/cvera: no such file or directory`**
→ Run `make build` first.

**`database is locked`** (SQLite)
→ You're running two copies of CVEra against the same `cvera.db`. Stop the other instance first. SQLite only supports one writer at a time.

**No CVEs matching after ingestion**
→ Check that your `current_version` in `catalog.yaml` matches the exact version string NVD uses. Try running `./bin/cvera ingest run` and look at the logs. If confidence is `weak`, the CPE string may need adjustment — search for your product at https://nvd.nist.gov/products/cpe/search.

**Slack alerts not arriving**
→ Check the webhook URL is correct and `alerting.slack.enabled: true` is set. Confirm `alerting.min_severity` isn't set higher than the CVE's severity (e.g. if set to `critical`, high-severity CVEs are stored but not alerted).

**`go: command not found`**
→ Go isn't on your PATH. Follow the installation guide at https://go.dev/doc/install and restart your terminal.

---

## File Reference

```
CVEra/
├── configs/
│   ├── config.yaml          ← your main config (create from config.example.yaml)
│   ├── catalog.yaml         ← your service catalog (create from catalog.example.yaml)
│   └── clients.yaml         ← your clients (create from clients.example.yaml)
├── cvera.db                 ← SQLite database (auto-created on first run)
├── bin/
│   └── cvera               ← compiled binary (after make build)
└── migrations/
    ├── postgres/            ← PostgreSQL schema
    └── sqlite/              ← SQLite schema
```

---

## Quick Reference Card

```bash
# Build
make build

# First-time setup
make migrate-up
./bin/cvera catalog import configs/catalog.yaml
./bin/cvera client  import configs/clients.yaml

# Run
make run

# Trigger ingestion now
./bin/cvera ingest run

# Check alerts
./bin/cvera alert list

# Acknowledge alert
./bin/cvera alert ack <id> --note="..."

# Update a service version after patching
./bin/cvera catalog update --service=haproxy --version=2.8.5

# Migration management
make migrate-up
make migrate-down
make migrate-status

# Help
./bin/cvera --help
./bin/cvera catalog --help
./bin/cvera alert --help
```
