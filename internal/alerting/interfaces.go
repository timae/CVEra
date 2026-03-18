package alerting

import "context"

// Notifier sends an alert through an external channel.
// The interface is narrow so the Slack implementation can be swapped
// for PagerDuty, email, or a no-op in tests without changing the engine.
type Notifier interface {
	// Send delivers the alert payload. Returns the external message ID if available
	// (e.g. Slack message timestamp for threading).
	Send(ctx context.Context, payload *AlertPayload) (string, error)

	// Name identifies the notifier, e.g. "slack", "noop".
	Name() string
}

// AlertPayload is the normalized alert representation passed to Notifier.
// It is independent of any specific notification format.
type AlertPayload struct {
	AlertID            string
	CatalogServiceName string
	CatalogServiceSlug string
	VulnID             string
	Title              string
	Description        string
	CVSSScore          *float64
	CVSSVector         *string
	SeverityLabel      string
	EPSSScore          *float64
	EPSSPercentile     *float64
	InCISAKEV          bool
	Confidence         string
	MatchMethod        string
	AffectedVersion    string // catalog entry's current version
	References         []string
	Criticality        string // catalog default (or highest among enrolled clients)
	Exposure           string
	OwningTeam         string

	// All currently enrolled clients (filtered: suppress_until respected, overrides applied).
	AffectedClients []AffectedClient
}

// AffectedClient holds the per-client context included in an alert.
type AffectedClient struct {
	Name        string
	Slug        string
	Contact     string
	Environment string
	Criticality string // effective: enrollment override or catalog default
	Exposure    string // effective: enrollment override or catalog default
}

// AlertEngine evaluates pending matches, applies suppression, and dispatches notifications.
type AlertEngine interface {
	// ProcessNewMatches is called after each matching run.
	// It finds matches without a corresponding alert and dispatches Slack notifications.
	ProcessNewMatches(ctx context.Context) error
}
