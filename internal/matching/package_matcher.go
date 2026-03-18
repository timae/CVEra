package matching

import (
	"context"
	"fmt"

	"github.com/yourorg/cvera/internal/models"
	"github.com/yourorg/cvera/internal/normalize"
)

// PackageMatcher implements Matcher using package ecosystem + version ranges.
// It is particularly valuable for Go modules (Loki, ArgoCD, Prometheus)
// where NVD CPE coverage is thinner than OSV.dev.
//
// Confidence: strong (version confirmed in range) or unknown (version unparseable).
type PackageMatcher struct{}

func NewPackageMatcher() Matcher { return &PackageMatcher{} }

func (m *PackageMatcher) Name() string { return string(models.MatchMethodPackageRange) }

func (m *PackageMatcher) Match(ctx context.Context, svc *models.CatalogService, vuln *models.Vulnerability) (*MatchResult, error) {
	if svc.PackageName == "" || svc.PackageEcosystem == "" {
		return nil, nil // matcher not applicable — no package coordinates
	}
	if len(vuln.AffectedRanges) == 0 {
		return nil, nil // no package range data on vulnerability
	}

	// TODO: implement full OSV-format range parsing and version evaluation.
	// The affected_ranges JSONB follows the OSV schema:
	// [{"type":"ECOSYSTEM","package":{"name":"...","ecosystem":"..."},"ranges":[...]}]
	// Each range has "events": [{"introduced":"..."},{"fixed":"..."}]
	//
	// Steps:
	// 1. Unmarshal affected_ranges JSONB into OSV affected structs
	// 2. Find an entry matching svc.PackageEcosystem + svc.PackageName
	// 3. Evaluate svc.Version against each range event pair
	// 4. Return ConfidenceStrong if in range, nil if not, ConfidenceUnknown if version unparseable

	svcVersion := normalize.Normalize(svc.Version)
	if svcVersion.IsUnknown {
		// Cannot evaluate range without a parseable version.
		return &MatchResult{
			Confidence:      models.ConfidenceUnknown,
			Method:          models.MatchMethodPackageRange,
			MatchedOn:       fmt.Sprintf("%s:%s", svc.PackageEcosystem, svc.PackageName),
			VersionAffected: false,
			Detail:          map[string]any{"reason": "service version unknown"},
		}, nil
	}

	return nil, fmt.Errorf("package matcher: not implemented")
}
