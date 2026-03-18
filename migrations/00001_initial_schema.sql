-- +goose Up
-- +goose StatementBegin

-- ──────────────────────────────────────────────────────────────────────────────
-- Extensions
-- ──────────────────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- future fuzzy search on product names

-- ──────────────────────────────────────────────────────────────────────────────
-- catalog_services
-- One row per managed-service type (e.g. "argo-cd", "haproxy", "loki").
-- The version here is the version WE currently deploy to ALL clients.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE catalog_services (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT        NOT NULL UNIQUE,          -- e.g. "argo-cd"
    name            TEXT        NOT NULL,                 -- e.g. "Argo CD"
    description     TEXT        NOT NULL DEFAULT '',
    cpe23           TEXT,                                 -- e.g. "cpe:2.3:a:argoproj:argo_cd:*:*:*:*:*:*:*:*"
    current_version TEXT        NOT NULL,                 -- e.g. "2.9.3"
    package_name    TEXT,                                 -- apt/apk package name if applicable
    package_type    TEXT,                                 -- "deb" | "apk" | "rpm" | "helm" | NULL
    default_criticality TEXT    NOT NULL DEFAULT 'medium' CHECK (default_criticality IN ('critical','high','medium','low')),
    default_exposure    TEXT    NOT NULL DEFAULT 'internal' CHECK (default_exposure IN ('public','internal')),
    metadata        JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_catalog_services_slug ON catalog_services (slug);
CREATE INDEX idx_catalog_services_cpe23 ON catalog_services (cpe23) WHERE cpe23 IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────────────
-- catalog_version_history
-- Immutable audit trail every time current_version changes.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE catalog_version_history (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    catalog_service_id  UUID        NOT NULL REFERENCES catalog_services (id) ON DELETE CASCADE,
    previous_version    TEXT        NOT NULL,
    new_version         TEXT        NOT NULL,
    changed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by          TEXT        NOT NULL DEFAULT 'system'
);

CREATE INDEX idx_cvh_catalog_service_id ON catalog_version_history (catalog_service_id, changed_at DESC);

-- ──────────────────────────────────────────────────────────────────────────────
-- clients
-- A client organisation we manage infrastructure for.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE clients (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT        NOT NULL UNIQUE,           -- e.g. "acme-corp"
    name            TEXT        NOT NULL,
    contact_email   TEXT        NOT NULL DEFAULT '',
    metadata        JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_clients_slug ON clients (slug);

-- ──────────────────────────────────────────────────────────────────────────────
-- client_enrollments
-- Thin join: which clients run which catalog services.
-- Per-client overrides (criticality, exposure) are optional.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE client_enrollments (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           UUID        NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    catalog_service_id  UUID        NOT NULL REFERENCES catalog_services (id) ON DELETE CASCADE,

    -- Optional per-client overrides; NULL means "use catalog default"
    criticality_override TEXT       CHECK (criticality_override IN ('critical','high','medium','low')),
    exposure_override    TEXT       CHECK (exposure_override IN ('public','internal')),

    -- Per-enrollment suppression: set end_date = NULL for permanent
    suppressed          BOOLEAN     NOT NULL DEFAULT FALSE,
    suppression_reason  TEXT,
    suppression_end_date TIMESTAMPTZ,

    enrolled_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (client_id, catalog_service_id)
);

CREATE INDEX idx_enrollments_catalog_service_id ON client_enrollments (catalog_service_id);
CREATE INDEX idx_enrollments_client_id           ON client_enrollments (client_id);

-- ──────────────────────────────────────────────────────────────────────────────
-- vulnerabilities
-- Normalised CVE/vulnerability records. One row per vuln_id.
-- Raw source payloads stored in vulnerability_source_records.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE vulnerabilities (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id         TEXT        NOT NULL UNIQUE,            -- "CVE-2024-XXXXX"
    source_type     TEXT        NOT NULL,                   -- "nvd" | "osv" | "kev"
    title           TEXT        NOT NULL DEFAULT '',
    description     TEXT        NOT NULL DEFAULT '',

    cvss_score      NUMERIC(4,1),
    cvss_vector     TEXT,
    severity_label  TEXT        NOT NULL DEFAULT 'unknown'
                    CHECK (severity_label IN ('critical','high','medium','low','none','unknown')),

    epss_score      NUMERIC(7,4),                          -- 0.0000–1.0000
    epss_percentile NUMERIC(7,4),

    in_cisa_kev     BOOLEAN     NOT NULL DEFAULT FALSE,
    published_at    TIMESTAMPTZ,
    modified_at     TIMESTAMPTZ,

    -- JSONB arrays from NVD CPE match data
    -- Schema: [{cpe23: "...", versionStartIncluding: "...", versionEndExcluding: "...", ...}]
    cpe_matches     JSONB       NOT NULL DEFAULT '[]',
    affected_ranges JSONB       NOT NULL DEFAULT '[]',      -- OSV ranges

    raw_nvd         JSONB,                                  -- full NVD CVE item snapshot
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vulnerabilities_vuln_id         ON vulnerabilities (vuln_id);
CREATE INDEX idx_vulnerabilities_severity        ON vulnerabilities (severity_label);
CREATE INDEX idx_vulnerabilities_in_cisa_kev     ON vulnerabilities (in_cisa_kev) WHERE in_cisa_kev = TRUE;
CREATE INDEX idx_vulnerabilities_published_at    ON vulnerabilities (published_at DESC);
CREATE INDEX idx_vulnerabilities_cpe_matches_gin ON vulnerabilities USING GIN (cpe_matches);

-- ──────────────────────────────────────────────────────────────────────────────
-- vulnerability_source_records
-- Raw, deduplicated source payloads keyed by (vuln_id, source, hash).
-- payload_hash allows "insert only on change" semantics.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE vulnerability_source_records (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id         TEXT        NOT NULL,
    source_type     TEXT        NOT NULL,
    payload_hash    TEXT        NOT NULL,                   -- SHA-256 hex
    payload         JSONB       NOT NULL,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (vuln_id, source_type, payload_hash)
);

CREATE INDEX idx_vsr_vuln_id     ON vulnerability_source_records (vuln_id);
CREATE INDEX idx_vsr_source_type ON vulnerability_source_records (source_type, fetched_at DESC);

-- ──────────────────────────────────────────────────────────────────────────────
-- ingestion_checkpoints
-- One row per source_type, updated after each successful ingestion run.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE ingestion_checkpoints (
    source_type     TEXT        PRIMARY KEY,
    last_success_at TIMESTAMPTZ NOT NULL,
    last_cursor     TEXT,                                   -- e.g. ISO timestamp for NVD pagination
    metadata        JSONB       NOT NULL DEFAULT '{}'
);

-- ──────────────────────────────────────────────────────────────────────────────
-- matches
-- Result of the matching engine: (catalog_service, vulnerability) pairs.
-- Invalidated when catalog_service version changes; re-evaluated on next run.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TYPE match_confidence AS ENUM ('exact', 'strong', 'weak', 'unknown');
CREATE TYPE match_method AS ENUM ('cpe_exact', 'cpe_range', 'package_range', 'product_fuzzy');

CREATE TABLE matches (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    catalog_service_id  UUID            NOT NULL REFERENCES catalog_services (id) ON DELETE CASCADE,
    vuln_id             TEXT            NOT NULL REFERENCES vulnerabilities (vuln_id) ON DELETE CASCADE,
    confidence          match_confidence NOT NULL,
    match_method        match_method    NOT NULL,
    matched_version     TEXT            NOT NULL,           -- version that was matched
    matched_cpe         TEXT,                               -- CPE that triggered the match
    notes               TEXT            NOT NULL DEFAULT '',
    is_valid            BOOLEAN         NOT NULL DEFAULT TRUE,
    matched_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    invalidated_at      TIMESTAMPTZ,

    UNIQUE (catalog_service_id, vuln_id)
);

CREATE INDEX idx_matches_catalog_service_id ON matches (catalog_service_id);
CREATE INDEX idx_matches_vuln_id            ON matches (vuln_id);
CREATE INDEX idx_matches_is_valid           ON matches (is_valid) WHERE is_valid = TRUE;
CREATE INDEX idx_matches_confidence         ON matches (confidence);

-- ──────────────────────────────────────────────────────────────────────────────
-- alerts
-- One alert per (catalog_service, vulnerability) — dedup key.
-- Tracks lifecycle: pending → sent → acknowledged | suppressed | resolved.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TYPE alert_status AS ENUM (
    'pending', 'sent', 'acknowledged', 'suppressed', 'resolved', 're_triggered'
);

CREATE TABLE alerts (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    dedup_key           TEXT        NOT NULL UNIQUE,        -- "{catalog_slug}:{vuln_id}"
    catalog_service_id  UUID        NOT NULL REFERENCES catalog_services (id) ON DELETE CASCADE,
    vuln_id             TEXT        NOT NULL,
    status              alert_status NOT NULL DEFAULT 'pending',

    -- Snapshot of affected clients at time of alert (JSONB array)
    -- [{client_id, client_name, client_slug, environment, criticality, exposure}]
    affected_clients    JSONB       NOT NULL DEFAULT '[]',

    -- Operational fields
    acknowledged_at     TIMESTAMPTZ,
    acknowledged_by     TEXT,
    ack_note            TEXT,
    resolved_at         TIMESTAMPTZ,
    suppressed_at       TIMESTAMPTZ,
    suppression_reason  TEXT,
    last_sent_at        TIMESTAMPTZ,
    send_count          INT         NOT NULL DEFAULT 0,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_dedup_key           ON alerts (dedup_key);
CREATE INDEX idx_alerts_catalog_service_id  ON alerts (catalog_service_id);
CREATE INDEX idx_alerts_vuln_id             ON alerts (vuln_id);
CREATE INDEX idx_alerts_status              ON alerts (status);
CREATE INDEX idx_alerts_created_at          ON alerts (created_at DESC);

-- ──────────────────────────────────────────────────────────────────────────────
-- suppressions
-- Named suppression rules.  Scope hierarchy:
--   vuln_id + catalog_service_id  → most specific
--   vuln_id only                  → all services for this CVE
--   catalog_service_id only       → all CVEs for this service
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE suppressions (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id             TEXT,                               -- NULL = match any CVE
    catalog_service_id  UUID        REFERENCES catalog_services (id) ON DELETE CASCADE,
    reason              TEXT        NOT NULL,
    created_by          TEXT        NOT NULL DEFAULT 'system',
    expires_at          TIMESTAMPTZ,                        -- NULL = permanent
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_suppressions_vuln_id            ON suppressions (vuln_id) WHERE vuln_id IS NOT NULL;
CREATE INDEX idx_suppressions_catalog_service_id ON suppressions (catalog_service_id) WHERE catalog_service_id IS NOT NULL;
CREATE INDEX idx_suppressions_expires_at         ON suppressions (expires_at) WHERE expires_at IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────────────
-- updated_at trigger helper
-- ──────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_catalog_services_updated_at
    BEFORE UPDATE ON catalog_services
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_clients_updated_at
    BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_enrollments_updated_at
    BEFORE UPDATE ON client_enrollments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_vulnerabilities_updated_at
    BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS trg_alerts_updated_at         ON alerts;
DROP TRIGGER IF EXISTS trg_vulnerabilities_updated_at ON vulnerabilities;
DROP TRIGGER IF EXISTS trg_enrollments_updated_at    ON client_enrollments;
DROP TRIGGER IF EXISTS trg_clients_updated_at        ON clients;
DROP TRIGGER IF EXISTS trg_catalog_services_updated_at ON catalog_services;
DROP FUNCTION IF EXISTS set_updated_at();

DROP TABLE IF EXISTS suppressions;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS matches;
DROP TABLE IF EXISTS ingestion_checkpoints;
DROP TABLE IF EXISTS vulnerability_source_records;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS client_enrollments;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS catalog_version_history;
DROP TABLE IF EXISTS catalog_services;

DROP TYPE IF EXISTS alert_status;
DROP TYPE IF EXISTS match_method;
DROP TYPE IF EXISTS match_confidence;

DROP EXTENSION IF EXISTS pg_trgm;
DROP EXTENSION IF EXISTS pgcrypto;

-- +goose StatementEnd
