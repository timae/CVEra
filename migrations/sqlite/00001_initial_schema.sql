-- +goose Up
-- +goose StatementBegin

-- ──────────────────────────────────────────────────────────────────────────────
-- SQLite schema for CVEra
--
-- Differences from the PostgreSQL schema:
--   • No extensions (pgcrypto, pg_trgm)
--   • UUIDs stored as TEXT — application generates them via uuid.New()
--   • JSONB → TEXT (JSON stored as a serialised string, queried in Go)
--   • TIMESTAMPTZ → TEXT (ISO 8601, e.g. "2024-01-15T10:30:00Z")
--   • NUMERIC → REAL
--   • ENUM types → TEXT + CHECK constraints
--   • DEFAULT gen_random_uuid() removed — caller must supply the UUID
--   • DEFAULT NOW() → DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
--   • GIN indexes → regular indexes (SQLite has no GIN)
--   • Triggers use SQLite syntax (AFTER UPDATE … BEGIN … END)
-- ──────────────────────────────────────────────────────────────────────────────

-- ── catalog_services ──────────────────────────────────────────────────────────
CREATE TABLE catalog_services (
    id                   TEXT PRIMARY KEY,
    slug                 TEXT NOT NULL UNIQUE,
    name                 TEXT NOT NULL,
    description          TEXT NOT NULL DEFAULT '',
    cpe23                TEXT,
    current_version      TEXT NOT NULL,
    package_name         TEXT,
    package_type         TEXT,
    default_criticality  TEXT NOT NULL DEFAULT 'medium'
                         CHECK (default_criticality IN ('critical','high','medium','low')),
    default_exposure     TEXT NOT NULL DEFAULT 'internal'
                         CHECK (default_exposure IN ('public','internal')),
    metadata             TEXT NOT NULL DEFAULT '{}',
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX idx_catalog_services_slug  ON catalog_services (slug);
CREATE INDEX idx_catalog_services_cpe23 ON catalog_services (cpe23) WHERE cpe23 IS NOT NULL;

CREATE TRIGGER trg_catalog_services_updated_at
    AFTER UPDATE ON catalog_services
    FOR EACH ROW
    BEGIN
        UPDATE catalog_services SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
        WHERE id = OLD.id;
    END;

-- ── catalog_version_history ───────────────────────────────────────────────────
CREATE TABLE catalog_version_history (
    id                  TEXT PRIMARY KEY,
    catalog_service_id  TEXT NOT NULL REFERENCES catalog_services (id) ON DELETE CASCADE,
    previous_version    TEXT NOT NULL,
    new_version         TEXT NOT NULL,
    changed_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    changed_by          TEXT NOT NULL DEFAULT 'system'
);

CREATE INDEX idx_cvh_catalog_service_id ON catalog_version_history (catalog_service_id, changed_at DESC);

-- ── clients ───────────────────────────────────────────────────────────────────
CREATE TABLE clients (
    id             TEXT PRIMARY KEY,
    slug           TEXT NOT NULL UNIQUE,
    name           TEXT NOT NULL,
    contact_email  TEXT NOT NULL DEFAULT '',
    metadata       TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX idx_clients_slug ON clients (slug);

CREATE TRIGGER trg_clients_updated_at
    AFTER UPDATE ON clients
    FOR EACH ROW
    BEGIN
        UPDATE clients SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
        WHERE id = OLD.id;
    END;

-- ── client_enrollments ────────────────────────────────────────────────────────
CREATE TABLE client_enrollments (
    id                   TEXT PRIMARY KEY,
    client_id            TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    catalog_service_id   TEXT NOT NULL REFERENCES catalog_services (id) ON DELETE CASCADE,
    criticality_override TEXT CHECK (criticality_override IN ('critical','high','medium','low')),
    exposure_override    TEXT CHECK (exposure_override IN ('public','internal')),
    suppressed           INTEGER NOT NULL DEFAULT 0,   -- SQLite has no BOOLEAN; 0/1
    suppression_reason   TEXT,
    suppression_end_date TEXT,
    enrolled_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (client_id, catalog_service_id)
);

CREATE INDEX idx_enrollments_catalog_service_id ON client_enrollments (catalog_service_id);
CREATE INDEX idx_enrollments_client_id          ON client_enrollments (client_id);

CREATE TRIGGER trg_enrollments_updated_at
    AFTER UPDATE ON client_enrollments
    FOR EACH ROW
    BEGIN
        UPDATE client_enrollments SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
        WHERE id = OLD.id;
    END;

-- ── vulnerabilities ───────────────────────────────────────────────────────────
CREATE TABLE vulnerabilities (
    id              TEXT PRIMARY KEY,
    vuln_id         TEXT NOT NULL UNIQUE,
    source_type     TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    cvss_score      REAL,
    cvss_vector     TEXT,
    severity_label  TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (severity_label IN ('critical','high','medium','low','none','unknown')),
    epss_score      REAL,
    epss_percentile REAL,
    in_cisa_kev     INTEGER NOT NULL DEFAULT 0,
    published_at    TEXT,
    modified_at     TEXT,
    cpe_matches     TEXT NOT NULL DEFAULT '[]',
    affected_ranges TEXT NOT NULL DEFAULT '[]',
    raw_nvd         TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX idx_vulnerabilities_vuln_id      ON vulnerabilities (vuln_id);
CREATE INDEX idx_vulnerabilities_severity     ON vulnerabilities (severity_label);
CREATE INDEX idx_vulnerabilities_in_cisa_kev  ON vulnerabilities (in_cisa_kev) WHERE in_cisa_kev = 1;
CREATE INDEX idx_vulnerabilities_published_at ON vulnerabilities (published_at DESC);

CREATE TRIGGER trg_vulnerabilities_updated_at
    AFTER UPDATE ON vulnerabilities
    FOR EACH ROW
    BEGIN
        UPDATE vulnerabilities SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
        WHERE id = OLD.id;
    END;

-- ── vulnerability_source_records ──────────────────────────────────────────────
CREATE TABLE vulnerability_source_records (
    id           TEXT PRIMARY KEY,
    vuln_id      TEXT NOT NULL,
    source_type  TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload      TEXT NOT NULL,
    fetched_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (vuln_id, source_type, payload_hash)
);

CREATE INDEX idx_vsr_vuln_id     ON vulnerability_source_records (vuln_id);
CREATE INDEX idx_vsr_source_type ON vulnerability_source_records (source_type, fetched_at DESC);

-- ── ingestion_checkpoints ─────────────────────────────────────────────────────
CREATE TABLE ingestion_checkpoints (
    source_type     TEXT PRIMARY KEY,
    last_success_at TEXT NOT NULL,
    last_cursor     TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}'
);

-- ── matches ───────────────────────────────────────────────────────────────────
CREATE TABLE matches (
    id                  TEXT PRIMARY KEY,
    catalog_service_id  TEXT NOT NULL REFERENCES catalog_services (id) ON DELETE CASCADE,
    vuln_id             TEXT NOT NULL REFERENCES vulnerabilities (vuln_id) ON DELETE CASCADE,
    confidence          TEXT NOT NULL CHECK (confidence IN ('exact','strong','weak','unknown')),
    match_method        TEXT NOT NULL CHECK (match_method IN ('cpe_exact','cpe_range','package_range','product_fuzzy')),
    matched_version     TEXT NOT NULL,
    matched_cpe         TEXT,
    notes               TEXT NOT NULL DEFAULT '',
    is_valid            INTEGER NOT NULL DEFAULT 1,
    matched_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    invalidated_at      TEXT,
    UNIQUE (catalog_service_id, vuln_id)
);

CREATE INDEX idx_matches_catalog_service_id ON matches (catalog_service_id);
CREATE INDEX idx_matches_vuln_id            ON matches (vuln_id);
CREATE INDEX idx_matches_is_valid           ON matches (is_valid) WHERE is_valid = 1;
CREATE INDEX idx_matches_confidence         ON matches (confidence);

-- ── alerts ────────────────────────────────────────────────────────────────────
CREATE TABLE alerts (
    id                  TEXT PRIMARY KEY,
    dedup_key           TEXT NOT NULL UNIQUE,
    catalog_service_id  TEXT NOT NULL REFERENCES catalog_services (id) ON DELETE CASCADE,
    vuln_id             TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','sent','acknowledged','suppressed','resolved','re_triggered')),
    affected_clients    TEXT NOT NULL DEFAULT '[]',
    acknowledged_at     TEXT,
    acknowledged_by     TEXT,
    ack_note            TEXT,
    resolved_at         TEXT,
    suppressed_at       TEXT,
    suppression_reason  TEXT,
    last_sent_at        TEXT,
    send_count          INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX idx_alerts_dedup_key           ON alerts (dedup_key);
CREATE INDEX idx_alerts_catalog_service_id  ON alerts (catalog_service_id);
CREATE INDEX idx_alerts_vuln_id             ON alerts (vuln_id);
CREATE INDEX idx_alerts_status              ON alerts (status);
CREATE INDEX idx_alerts_created_at          ON alerts (created_at DESC);

CREATE TRIGGER trg_alerts_updated_at
    AFTER UPDATE ON alerts
    FOR EACH ROW
    BEGIN
        UPDATE alerts SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
        WHERE id = OLD.id;
    END;

-- ── suppressions ──────────────────────────────────────────────────────────────
CREATE TABLE suppressions (
    id                  TEXT PRIMARY KEY,
    vuln_id             TEXT,
    catalog_service_id  TEXT REFERENCES catalog_services (id) ON DELETE CASCADE,
    reason              TEXT NOT NULL,
    created_by          TEXT NOT NULL DEFAULT 'system',
    expires_at          TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX idx_suppressions_vuln_id            ON suppressions (vuln_id) WHERE vuln_id IS NOT NULL;
CREATE INDEX idx_suppressions_catalog_service_id ON suppressions (catalog_service_id) WHERE catalog_service_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TRIGGER IF EXISTS trg_alerts_updated_at;
DROP TRIGGER IF EXISTS trg_vulnerabilities_updated_at;
DROP TRIGGER IF EXISTS trg_enrollments_updated_at;
DROP TRIGGER IF EXISTS trg_clients_updated_at;
DROP TRIGGER IF EXISTS trg_catalog_services_updated_at;

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

-- +goose StatementEnd
