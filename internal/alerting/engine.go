package alerting

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/yourorg/vulnmon/internal/config"
	"github.com/yourorg/vulnmon/internal/models"
	"github.com/yourorg/vulnmon/internal/repository"
)

// Engine is the default AlertEngine implementation.
type Engine struct {
	matchRepo      repository.MatchRepository
	alertRepo      repository.AlertRepository
	enrollRepo     repository.EnrollmentRepository
	vulnRepo       repository.VulnerabilityRepository
	catalogRepo    repository.CatalogRepository
	suppressRepo   repository.SuppressionRepository
	notifier       Notifier
	cfg            config.AlertingConfig
	logger         *zap.Logger
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
	// TODO: implement
	//
	// For each pending match:
	//   1. Load vulnerability and catalog service
	//   2. Skip if confidence < cfg.MinAlertConfidence
	//   3. Skip if cvss < cfg.MinCVSSScore (unless in_cisa_kev && cfg.AlertOnKEV)
	//   4. Evaluate suppression rules via suppressRepo.Match()
	//   5. Compute dedup_key: models.MakeDedupKey(slug, vulnID)
	//   6. Check alertRepo.GetByDedupKey() — skip if sent/acknowledged
	//   7. Load enrolled clients via enrollRepo.ListByService()
	//      - Filter out suppressed enrollments (suppress_until in future)
	//      - Apply criticality/exposure overrides
	//   8. Build AlertPayload
	//   9. Send via notifier
	//  10. Create alert record with affected_clients snapshot and status=sent
	//  11. Write to audit_log
	//  12. Emit metrics

	return fmt.Errorf("alert engine ProcessNewMatches: not implemented")
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
