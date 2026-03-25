package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/yourorg/cvera/internal/config"
	"github.com/yourorg/cvera/internal/models"
	"github.com/yourorg/cvera/internal/repository"
)

// Engine is the default AlertEngine implementation.
type Engine struct {
	matchRepo    repository.MatchRepository
	alertRepo    repository.AlertRepository
	enrollRepo   repository.EnrollmentRepository
	vulnRepo     repository.VulnerabilityRepository
	catalogRepo  repository.CatalogRepository
	suppressRepo repository.SuppressionRepository
	notifier     Notifier
	cfg          config.AlertingConfig
	logger       *zap.Logger
}

func NewEngine(
	matchRepo repository.MatchRepository,
	alertRepo repository.AlertRepository,
	enrollRepo repository.EnrollmentRepository,
	vulnRepo repository.VulnerabilityRepository,
	catalogRepo repository.CatalogRepository,
	suppressRepo repository.SuppressionRepository,
	notifier Notifier,
	cfg config.AlertingConfig,
	logger *zap.Logger,
) AlertEngine {
	return &Engine{
		matchRepo:    matchRepo,
		alertRepo:    alertRepo,
		enrollRepo:   enrollRepo,
		vulnRepo:     vulnRepo,
		catalogRepo:  catalogRepo,
		suppressRepo: suppressRepo,
		notifier:     notifier,
		cfg:          cfg,
		logger:       logger,
	}
}

func (e *Engine) ProcessNewMatches(ctx context.Context) error {
	services, err := e.catalogRepo.ListActive(ctx)
	if err != nil {
		return fmt.Errorf("list catalog services: %w", err)
	}

	for _, svc := range services {
		matches, err := e.matchRepo.ListActiveForCatalogService(ctx, svc.ID)
		if err != nil {
			return fmt.Errorf("list matches for %s: %w", svc.Slug, err)
		}
		for _, match := range matches {
			if confidenceRank(match.Confidence) < confidenceRank(models.ConfidenceStrong) {
				continue
			}
			vuln, err := e.vulnRepo.GetByVulnID(ctx, match.VulnID)
			if err != nil {
				return fmt.Errorf("load vulnerability %s: %w", match.VulnID, err)
			}
			if vuln == nil {
				continue
			}
			if !e.meetsSeverityThreshold(vuln) {
				continue
			}

			if e.suppressRepo != nil {
				suppression, err := e.suppressRepo.Match(ctx, svc.ID, nil, vuln)
				if err != nil {
					return fmt.Errorf("check suppression for %s/%s: %w", svc.Slug, vuln.VulnID, err)
				}
				if suppression != nil {
					if err := e.ensureSuppressedAlert(ctx, svc, vuln, suppression); err != nil {
						return err
					}
					continue
				}
			}

			affectedClients, snapshot, err := e.affectedClientsForService(ctx, svc)
			if err != nil {
				return fmt.Errorf("compute affected clients for %s: %w", svc.Slug, err)
			}
			if len(affectedClients) == 0 {
				continue
			}

			key := models.MakeDedupKey(svc.Slug, vuln.VulnID)
			existing, err := e.alertRepo.GetByDedupKey(ctx, key)
			if err != nil {
				return fmt.Errorf("lookup alert %s: %w", key, err)
			}
			if existing != nil && existing.Status != models.AlertStatusPending && existing.Status != models.AlertStatusReTriggered {
				continue
			}

			payload := buildAlertPayload(existing, svc, vuln, match, affectedClients)
			status := models.AlertStatusPending
			var sentAt *time.Time
			sendCount := 0
			if e.cfg.Slack.Enabled && e.notifier != nil && e.cfg.Slack.WebhookURL != "" {
				if _, err := e.notifier.Send(ctx, payload); err != nil {
					e.logger.Error("send alert failed", zap.String("service", svc.Slug), zap.String("vuln_id", vuln.VulnID), zap.Error(err))
				} else {
					now := time.Now().UTC()
					sentAt = &now
					sendCount = 1
					status = models.AlertStatusSent
				}
			}

			if existing == nil {
				alert := &models.Alert{
					ID:               mustUUID(payload.AlertID),
					DedupKey:         key,
					CatalogServiceID: svc.ID,
					VulnID:           vuln.VulnID,
					Status:           status,
					AffectedClients:  snapshot,
					LastSentAt:       sentAt,
					SendCount:        sendCount,
				}
				if err := e.alertRepo.Create(ctx, alert); err != nil {
					return fmt.Errorf("create alert %s: %w", key, err)
				}
				continue
			}

			if status == models.AlertStatusSent {
				if err := e.alertRepo.UpdateStatus(ctx, existing.ID, status, map[string]any{"send_count": sendCount}); err != nil {
					return fmt.Errorf("update alert %s: %w", key, err)
				}
			}
		}
	}

	return nil
}

// shouldAlert checks dedup state and suppression for a match.
func (e *Engine) shouldAlert(ctx context.Context, match *models.Match, vuln *models.Vulnerability, catalogSlug string) (bool, string, error) {
	key := models.MakeDedupKey(catalogSlug, vuln.VulnID)
	existing, err := e.alertRepo.GetByDedupKey(ctx, key)
	if err != nil {
		return false, "", fmt.Errorf("checking dedup key: %w", err)
	}
	if existing == nil {
		return true, "new", nil
	}
	switch existing.Status {
	case models.AlertStatusSent, models.AlertStatusAcknowledged:
		// Re-alert only on significant change (KEV entry, major re-score).
		// TODO: implement significantChange check
		return false, "deduped", nil
	case models.AlertStatusSuppressed:
		return false, "suppressed", nil
	default:
		return true, "pending_retry", nil
	}
}

func (e *Engine) meetsSeverityThreshold(v *models.Vulnerability) bool {
	if v.InCISAKEV && e.cfg.AlertOnKEV {
		return true
	}
	if v.CVSSv3Score != nil && *v.CVSSv3Score >= e.cfg.MinCVSSScore {
		return true
	}
	if v.EPSSScore != nil && *v.EPSSScore >= e.cfg.AlertOnEPSSThreshold {
		return true
	}
	return false
}

func (e *Engine) affectedClientsForService(ctx context.Context, svc *models.CatalogService) ([]AffectedClient, []byte, error) {
	enrollments, err := e.enrollRepo.ListByService(ctx, svc.ID)
	if err != nil {
		return nil, nil, err
	}
	var (
		clients  []AffectedClient
		snapshot []map[string]any
	)
	for _, enrollment := range enrollments {
		if enrollment.IsSuppressed() {
			continue
		}
		client := AffectedClient{
			Name:        enrollment.ClientName,
			Slug:        enrollment.ClientSlug,
			Contact:     enrollment.Contact,
			Environment: fallback(enrollment.Environment, "default"),
			Criticality: enrollment.EffectiveCriticality(svc.Criticality),
			Exposure:    enrollment.EffectiveExposure(svc.Exposure),
		}
		clients = append(clients, client)
		snapshot = append(snapshot, map[string]any{
			"name":        client.Name,
			"slug":        client.Slug,
			"contact":     client.Contact,
			"environment": client.Environment,
			"criticality": client.Criticality,
			"exposure":    client.Exposure,
		})
	}
	raw, err := json.Marshal(snapshot)
	return clients, raw, err
}

func buildAlertPayload(existing *models.Alert, svc *models.CatalogService, vuln *models.Vulnerability, match *models.Match, clients []AffectedClient) *AlertPayload {
	alertID := uuid.NewString()
	if existing != nil {
		alertID = existing.ID.String()
	}
	return &AlertPayload{
		AlertID:            alertID,
		CatalogServiceName: svc.Name,
		CatalogServiceSlug: svc.Slug,
		VulnID:             vuln.VulnID,
		Title:              vuln.Title,
		Description:        vuln.Description,
		CVSSScore:          vuln.CVSSv3Score,
		CVSSVector:         stringPtr(vuln.CVSSv3Vector),
		SeverityLabel:      vuln.SeverityLabel,
		EPSSScore:          vuln.EPSSScore,
		EPSSPercentile:     vuln.EPSSPercentile,
		InCISAKEV:          vuln.InCISAKEV,
		Confidence:         string(match.Confidence),
		MatchMethod:        string(match.MatchMethod),
		AffectedVersion:    svc.Version,
		Criticality:        svc.Criticality,
		Exposure:           svc.Exposure,
		OwningTeam:         svc.OwningTeam,
		AffectedClients:    clients,
	}
}

func (e *Engine) ensureSuppressedAlert(ctx context.Context, svc *models.CatalogService, vuln *models.Vulnerability, suppression *models.Suppression) error {
	key := models.MakeDedupKey(svc.Slug, vuln.VulnID)
	existing, err := e.alertRepo.GetByDedupKey(ctx, key)
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}
	now := time.Now().UTC()
	return e.alertRepo.Create(ctx, &models.Alert{
		ID:                uuid.New(),
		DedupKey:          key,
		CatalogServiceID:  svc.ID,
		VulnID:            vuln.VulnID,
		Status:            models.AlertStatusSuppressed,
		AffectedClients:   []byte("[]"),
		SuppressedAt:      &now,
		SuppressionReason: suppression.Reason,
	})
}

func confidenceRank(value models.Confidence) int {
	switch value {
	case models.ConfidenceExact:
		return 4
	case models.ConfidenceStrong:
		return 3
	case models.ConfidenceWeak:
		return 2
	case models.ConfidenceUnknown:
		return 1
	default:
		return 0
	}
}

func fallback(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func mustUUID(value string) uuid.UUID {
	id, err := uuid.Parse(value)
	if err != nil {
		return uuid.New()
	}
	return id
}
