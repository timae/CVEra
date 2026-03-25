package matching

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"go.uber.org/zap"

	"github.com/google/uuid"
	"github.com/yourorg/cvera/internal/models"
	"github.com/yourorg/cvera/internal/repository"
)

// Engine is the default MatchEngine implementation.
// It runs each registered Matcher against candidate catalog services,
// upserts match records, and triggers the alert engine for new matches.
type Engine struct {
	matchers     []Matcher
	catalogRepo  repository.CatalogRepository
	vulnRepo     repository.VulnerabilityRepository
	matchRepo    repository.MatchRepository
	alertTrigger AlertTrigger
	logger       *zap.Logger
}

// AlertTrigger is called after new matches are persisted.
// Defined as a function type to avoid an import cycle between matching and alerting.
type AlertTrigger func(ctx context.Context) error

// NewEngine creates a matching engine with the given matchers, applied in order.
// Matchers run from most precise (CPE exact) to least precise (fuzzy).
func NewEngine(
	matchers []Matcher,
	catalogRepo repository.CatalogRepository,
	vulnRepo repository.VulnerabilityRepository,
	matchRepo repository.MatchRepository,
	alertTrigger AlertTrigger,
	logger *zap.Logger,
) MatchEngine {
	return &Engine{
		matchers:     matchers,
		catalogRepo:  catalogRepo,
		vulnRepo:     vulnRepo,
		matchRepo:    matchRepo,
		alertTrigger: alertTrigger,
		logger:       logger,
	}
}

func (e *Engine) RunForVulnerability(ctx context.Context, vulnID string) error {
	vuln, err := e.vulnRepo.GetByVulnID(ctx, vulnID)
	if err != nil {
		return fmt.Errorf("load vulnerability %s: %w", vulnID, err)
	}
	if vuln == nil {
		return fmt.Errorf("vulnerability %s not found", vulnID)
	}
	if vuln.VulnStatus == models.VulnStatusRejected {
		return e.matchRepo.InvalidateForVuln(ctx, vuln.VulnID, "vulnerability rejected")
	}

	services, err := e.catalogRepo.ListActive(ctx)
	if err != nil {
		return fmt.Errorf("list catalog services: %w", err)
	}

	for _, svc := range services {
		best, err := e.bestMatch(ctx, svc, vuln)
		if err != nil {
			return fmt.Errorf("match %s against %s: %w", svc.Slug, vuln.VulnID, err)
		}
		if best == nil || !best.VersionAffected {
			if existing, err := e.matchRepo.GetByCatalogAndVuln(ctx, svc.ID, vuln.VulnID); err == nil && existing != nil && existing.IsValid {
				existing.IsValid = false
				now := time.Now().UTC()
				existing.InvalidatedAt = &now
				if err := e.matchRepo.Upsert(ctx, existing); err != nil {
					e.logger.Warn("invalidate match failed", zap.String("service", svc.Slug), zap.String("vuln_id", vuln.VulnID), zap.Error(err))
				}
			}
			continue
		}
		detail, _ := json.Marshal(best.Detail)
		match := &models.Match{
			ID:               uuid.New(),
			CatalogServiceID: svc.ID,
			VulnID:           vuln.VulnID,
			Confidence:       best.Confidence,
			MatchMethod:      best.Method,
			MatchedCPE:       best.MatchedOn,
			MatchedVersion:   svc.Version,
			Notes:            detail,
			IsValid:          true,
		}
		if err := e.matchRepo.Upsert(ctx, match); err != nil {
			return fmt.Errorf("upsert match %s/%s: %w", svc.Slug, vuln.VulnID, err)
		}
	}

	if e.alertTrigger != nil {
		if err := e.alertTrigger(ctx); err != nil {
			return fmt.Errorf("alert trigger: %w", err)
		}
	}
	return nil
}

func (e *Engine) RunForCatalogService(ctx context.Context, catalogServiceID string) error {
	id, err := uuid.Parse(catalogServiceID)
	if err != nil {
		return fmt.Errorf("parse catalog service id: %w", err)
	}
	svc, err := e.catalogRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("load catalog service %s: %w", catalogServiceID, err)
	}
	if svc == nil {
		return fmt.Errorf("catalog service %s not found", catalogServiceID)
	}

	vulns, err := e.vulnRepo.ListModifiedSince(ctx, time.Now().UTC().Add(-365*24*time.Hour), 10000, 0)
	if err != nil {
		return fmt.Errorf("list vulnerabilities: %w", err)
	}
	for _, vuln := range vulns {
		best, err := e.bestMatch(ctx, svc, vuln)
		if err != nil {
			return fmt.Errorf("match %s against %s: %w", svc.Slug, vuln.VulnID, err)
		}
		if best == nil || !best.VersionAffected {
			continue
		}
		detail, _ := json.Marshal(best.Detail)
		match := &models.Match{
			ID:               uuid.New(),
			CatalogServiceID: svc.ID,
			VulnID:           vuln.VulnID,
			Confidence:       best.Confidence,
			MatchMethod:      best.Method,
			MatchedCPE:       best.MatchedOn,
			MatchedVersion:   svc.Version,
			Notes:            detail,
			IsValid:          true,
		}
		if err := e.matchRepo.Upsert(ctx, match); err != nil {
			return fmt.Errorf("upsert match %s/%s: %w", svc.Slug, vuln.VulnID, err)
		}
	}
	if e.alertTrigger != nil {
		if err := e.alertTrigger(ctx); err != nil {
			return fmt.Errorf("alert trigger: %w", err)
		}
	}
	return nil
}

func (e *Engine) bestMatch(ctx context.Context, svc *models.CatalogService, vuln *models.Vulnerability) (*MatchResult, error) {
	var candidates []*MatchResult
	for _, matcher := range e.matchers {
		result, err := matcher.Match(ctx, svc, vuln)
		if err != nil {
			return nil, fmt.Errorf("%s matcher: %w", matcher.Name(), err)
		}
		if result != nil {
			candidates = append(candidates, result)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return confidenceRank(candidates[i].Confidence) > confidenceRank(candidates[j].Confidence)
	})
	return candidates[0], nil
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
