package models

import (
	"time"

	"github.com/google/uuid"
)

// AlertStatus is the state machine for an alert.
type AlertStatus string

const (
	AlertStatusPending      AlertStatus = "pending"
	AlertStatusSent         AlertStatus = "sent"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusSuppressed   AlertStatus = "suppressed"
	AlertStatusResolved     AlertStatus = "resolved"
	AlertStatusReTriggered  AlertStatus = "re_triggered"
)

// Alert represents the notification state for a (CatalogService, Vulnerability) pair.
// One alert covers all enrolled clients. The dedup key prevents duplicate Slack messages.
//
// Lifecycle:
//   pending → sent → acknowledged → (re_triggered on significant CVE change)
//          ↘ suppressed
//   sent   → resolved  (when catalog version updated and match invalidates)
type Alert struct {
	ID               uuid.UUID   `db:"id"`
	MatchID          uuid.UUID   `db:"match_id"`
	CatalogServiceID uuid.UUID   `db:"catalog_service_id"`
	VulnerabilityID  uuid.UUID   `db:"vulnerability_id"`

	// DedupKey format: "{catalog_service_slug}:{vuln_id}"
	// UNIQUE constraint ensures one active alert per (catalog_service, CVE).
	DedupKey string `db:"dedup_key"`

	// AffectedClients is a JSONB snapshot of enrolled clients at alert time.
	// Stored so history is accurate even if enrollments change later.
	// Schema: [{"id":"...","name":"...","slug":"...","contact":"...","criticality":"...","exposure":"..."}]
	AffectedClients      []byte `db:"affected_clients"`
	AffectedClientCount  int    `db:"affected_client_count"`

	Status AlertStatus `db:"status"`

	SlackTS      string    `db:"slack_ts"`      // Slack message timestamp for threading
	SlackPayload []byte    `db:"slack_payload"` // stored payload for reference
	SentAt       *time.Time `db:"sent_at"`

	AcknowledgedBy string     `db:"acknowledged_by"`
	AcknowledgedAt *time.Time `db:"acknowledged_at"`
	AckNote        string     `db:"ack_note"`

	NotificationCount int        `db:"notification_count"`
	LastNotifiedAt    *time.Time `db:"last_notified_at"`
	NextNotifyAt      *time.Time `db:"next_notify_at"`

	// Severity snapshot at alert time — preserved even if CVE is later re-scored.
	CVSSScoreAtAlert *float64 `db:"cvss_score_at_alert"`
	EPSSAtAlert      *float64 `db:"epss_at_alert"`
	InKEVAtAlert     bool     `db:"in_kev_at_alert"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// DedupKey generates the dedup key for a (catalog_service_slug, vuln_id) pair.
func MakeDedupKey(catalogServiceSlug, vulnID string) string {
	return catalogServiceSlug + ":" + vulnID
}
