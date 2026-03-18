package matching

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yourorg/vulnmon/internal/models"
	"github.com/yourorg/vulnmon/internal/normalize"
)

// CPEMatcher implements Matcher using CPE 2.3 applicability statements.
// It produces two confidence levels:
//   - exact:  service CPE is listed verbatim in the NVD CPE configuration
//   - strong: service CPE vendor+product match AND version is within an affected range
type CPEMatcher struct{}

func NewCPEMatcher() Matcher { return &CPEMatcher{} }

func (m *CPEMatcher) Name() string { return string(models.MatchMethodCPEExact) }

func (m *CPEMatcher) Match(ctx context.Context, svc *models.CatalogService, vuln *models.Vulnerability) (*MatchResult, error) {
	if svc.CPE23 == "" {
		return nil, nil // matcher not applicable
	}
	if len(vuln.CPEMatches) == 0 {
		return nil, nil // no CPE data on vulnerability
	}

	svcCPE, err := normalize.ParseCPE23(svc.CPE23)
	if err != nil {
		return nil, fmt.Errorf("parsing service CPE %q: %w", svc.CPE23, err)
	}

	// Parse CPE match list from vulnerability JSONB.
	var cpeMatches []cpeMatchEntry
	if err := json.Unmarshal(vuln.CPEMatches, &cpeMatches); err != nil {
		return nil, fmt.Errorf("parsing vuln CPE matches: %w", err)
	}

	svcVersion := normalize.Normalize(svc.Version)

	for _, entry := range cpeMatches {
		result := m.evaluateEntry(svcCPE, svcVersion, entry)
		if result != nil {
			return result, nil
		}
	}

	return nil, nil
}

// cpeMatchEntry mirrors the NVD CPE match object stored in JSONB.
type cpeMatchEntry struct {
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

func (m *CPEMatcher) evaluateEntry(
	svcCPE *normalize.CPE,
	svcVersion normalize.NormalizedVersion,
	entry cpeMatchEntry,
) *MatchResult {
	if !entry.Vulnerable {
		return nil
	}

	entryCPE, err := normalize.ParseCPE23(entry.Criteria)
	if err != nil {
		return nil
	}

	if !entryCPE.MatchesVendorProduct(svcCPE.Vendor, svcCPE.Product) {
		return nil
	}

	// Exact match: all CPE components including version match verbatim.
	if !entryCPE.IsWildcard() && entryCPE.Version == svcCPE.Version {
		return &MatchResult{
			Confidence:      models.ConfidenceExact,
			Method:          models.MatchMethodCPEExact,
			MatchedOn:       entry.Criteria,
			VersionAffected: true,
			Detail: map[string]any{
				"matched_criteria": entry.Criteria,
				"service_cpe":      svcCPE.String(),
			},
		}
	}

	// Version range match.
	constraint := buildConstraint(entry)
	if constraint == "" {
		// Wildcard version in CPE — vendor+product match, no version restriction.
		if svcVersion.IsUnknown {
			return &MatchResult{
				Confidence:      models.ConfidenceUnknown,
				Method:          models.MatchMethodCPERange,
				MatchedOn:       entry.Criteria,
				VersionAffected: false,
				Detail: map[string]any{"reason": "service version unknown"},
			}
		}
		return &MatchResult{
			Confidence:      models.ConfidenceStrong,
			Method:          models.MatchMethodCPERange,
			MatchedOn:       entry.Criteria,
			VersionAffected: true,
			Detail:          map[string]any{"matched_criteria": entry.Criteria},
		}
	}

	if svcVersion.IsUnknown {
		return &MatchResult{
			Confidence:      models.ConfidenceUnknown,
			Method:          models.MatchMethodCPERange,
			MatchedOn:       entry.Criteria,
			VersionAffected: false,
			Detail:          map[string]any{"reason": "service version unknown", "constraint": constraint},
		}
	}

	inRange, err := normalize.InRange(svcVersion, constraint)
	if err != nil || !inRange {
		return nil
	}

	return &MatchResult{
		Confidence:      models.ConfidenceStrong,
		Method:          models.MatchMethodCPERange,
		MatchedOn:       entry.Criteria,
		VersionAffected: true,
		Detail: map[string]any{
			"constraint":       constraint,
			"matched_criteria": entry.Criteria,
			"service_version":  svcVersion.Normalized,
		},
	}
}

func buildConstraint(entry cpeMatchEntry) string {
	var parts []string
	if entry.VersionStartIncluding != "" {
		parts = append(parts, ">= "+entry.VersionStartIncluding)
	}
	if entry.VersionStartExcluding != "" {
		parts = append(parts, "> "+entry.VersionStartExcluding)
	}
	if entry.VersionEndIncluding != "" {
		parts = append(parts, "<= "+entry.VersionEndIncluding)
	}
	if entry.VersionEndExcluding != "" {
		parts = append(parts, "< "+entry.VersionEndExcluding)
	}
	if len(parts) == 0 {
		return "" // no version constraint — wildcard match
	}
	result := parts[0]
	for _, p := range parts[1:] {
		result += ", " + p
	}
	return result
}
