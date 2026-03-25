package alerting

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/google/uuid"

	"github.com/yourorg/cvera/internal/config"
	"github.com/yourorg/cvera/internal/db"
	"github.com/yourorg/cvera/internal/matching"
	"github.com/yourorg/cvera/internal/models"
	"github.com/yourorg/cvera/internal/repository"
)

func TestMatchingAndAlertOrchestrationSQLite(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sqlitePath := filepath.Join(tmpDir, "cvera.db")
	repoRoot := filepath.Clean(filepath.Join("..", ".."))

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir repo root: %v", err)
	}
	defer os.Chdir(wd)

	sqlDB, backend, err := db.Open(ctx, config.DatabaseConfig{
		Backend:    "sqlite",
		SQLitePath: sqlitePath,
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer sqlDB.Close()

	if err := db.Migrate(ctx, sqlDB, backend); err != nil {
		t.Fatalf("migrate db: %v", err)
	}

	logger := zap.NewNop()
	catalogRepo := repository.NewCatalogRepository(sqlDB)
	clientRepo := repository.NewClientRepository(sqlDB)
	enrollmentRepo := repository.NewEnrollmentRepository(sqlDB)
	vulnRepo := repository.NewVulnerabilityRepository(sqlDB)
	matchRepo := repository.NewMatchRepository(sqlDB)
	alertRepo := repository.NewAlertRepository(sqlDB)
	suppressRepo := repository.NewSuppressionRepository(sqlDB)

	service := &models.CatalogService{
		ID:          uuid.New(),
		Slug:        "haproxy",
		Name:        "HAProxy",
		Version:     "2.8.5",
		CPE23:       "cpe:2.3:a:haproxy:haproxy:2.8.5:*:*:*:*:*:*:*",
		Criticality: "critical",
		Exposure:    "public",
		Active:      true,
	}
	if err := catalogRepo.Upsert(ctx, service); err != nil {
		t.Fatalf("upsert catalog service: %v", err)
	}

	client := &models.Client{
		ID:      uuid.New(),
		Slug:    "acme",
		Name:    "Acme",
		Contact: "ops@example.com",
		Active:  true,
	}
	if err := clientRepo.Upsert(ctx, client); err != nil {
		t.Fatalf("upsert client: %v", err)
	}
	client, err = clientRepo.GetBySlug(ctx, "acme")
	if err != nil || client == nil {
		t.Fatalf("reload client: %v", err)
	}

	if err := enrollmentRepo.Enroll(ctx, &models.ClientEnrollment{
		ID:               uuid.New(),
		ClientID:         client.ID,
		CatalogServiceID: service.ID,
		Environment:      "prod",
	}); err != nil {
		t.Fatalf("enroll client: %v", err)
	}

	vuln := &models.Vulnerability{
		ID:             uuid.New(),
		VulnID:         "CVE-2099-0001",
		SourceType:     "nvd",
		Title:          "Synthetic HAProxy CVE",
		Description:    "Synthetic test vulnerability",
		SeverityLabel:  "high",
		CPEMatches:     []byte(`[{"criteria":"cpe:2.3:a:haproxy:haproxy:2.8.5:*:*:*:*:*:*:*","vulnerable":true}]`),
		AffectedRanges: []byte("[]"),
		References:     []byte(`[]`),
	}
	score := 9.1
	vuln.CVSSv3Score = &score
	if err := vulnRepo.Upsert(ctx, vuln); err != nil {
		t.Fatalf("upsert vulnerability: %v", err)
	}

	alertEngine := NewEngine(
		matchRepo,
		alertRepo,
		enrollmentRepo,
		vulnRepo,
		catalogRepo,
		suppressRepo,
		nil,
		config.AlertingConfig{MinCVSSScore: 7.0},
		logger,
	)
	matchEngine := matching.NewEngine(
		[]matching.Matcher{
			matching.NewCPEMatcher(),
			matching.NewPackageMatcher(),
		},
		catalogRepo,
		vulnRepo,
		matchRepo,
		alertEngine.ProcessNewMatches,
		logger,
	)

	if err := matchEngine.RunForVulnerability(ctx, vuln.VulnID); err != nil {
		t.Fatalf("run matching engine: %v", err)
	}

	matches, err := matchRepo.ListActiveForCatalogService(ctx, service.ID)
	if err != nil {
		t.Fatalf("list matches: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 active match, got %d", len(matches))
	}

	alert, err := alertRepo.GetByDedupKey(ctx, models.MakeDedupKey(service.Slug, vuln.VulnID))
	if err != nil {
		t.Fatalf("load alert: %v", err)
	}
	if alert == nil {
		t.Fatal("expected alert to be created")
	}
	if alert.Status != models.AlertStatusPending {
		t.Fatalf("expected pending alert when slack disabled, got %s", alert.Status)
	}
	if len(alert.AffectedClients) == 0 {
		t.Fatal("expected affected clients snapshot")
	}

	_ = os.Remove(sqlitePath)
}
