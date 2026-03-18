package matching

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/yourorg/cvera/internal/repository"
)

// Engine is the default MatchEngine implementation.
// It runs each registered Matcher against candidate catalog services,
// upserts match records, and triggers the alert engine for new matches.
type Engine struct {
	matchers    []Matcher
	catalogRepo repository.CatalogRepository
	vulnRepo    repository.VulnerabilityRepository
	matchRepo   repository.MatchRepository
	alertTrigger AlertTrigger
	logger      *zap.Logger
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
	// TODO: implement
	// 1. Load vulnerability from DB
	// 2. If vuln_status == REJECTED: InvalidateForVuln, return
	// 3. Extract candidate lookup keys (CPE vendor:product pairs, package coordinates)
	// 4. For each key: query catalog services
	// 5. For each candidate: run all matchers, take highest-confidence result
	// 6. Upsert match records
	// 7. Call alertTrigger
	return fmt.Errorf("matching engine RunForVulnerability: not implemented")
}

func (e *Engine) RunForCatalogService(ctx context.Context, catalogServiceID string) error {
	// TODO: implement
	// 1. Load catalog service from DB
	// 2. Extract matching signals (CPE vendor:product, package coordinates)
	// 3. Query vulnerabilities modified in last N days that match those signals
	// 4. For each vulnerability: run all matchers
	// 5. Upsert match records
	// 6. Call alertTrigger
	return fmt.Errorf("matching engine RunForCatalogService: not implemented")
}
