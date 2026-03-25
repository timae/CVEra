package nvd

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/yourorg/cvera/internal/config"
	"github.com/yourorg/cvera/internal/ingestion"
	"github.com/yourorg/cvera/internal/models"
	"github.com/yourorg/cvera/internal/repository"
	"github.com/yourorg/cvera/pkg/retry"
)

const sourceName = "nvd"

// Source implements ingestion.VulnerabilitySource for the NVD API v2.
type Source struct {
	cfg    config.NVDConfig
	client *http.Client
	logger *zap.Logger
}

func NewSource(cfg config.NVDConfig, logger *zap.Logger) *Source {
	return &Source{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		logger: logger,
	}
}

func (s *Source) Name() string { return sourceName }

func (s *Source) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.APIURL+"?resultsPerPage=1", nil)
	if err != nil {
		return err
	}
	if s.cfg.APIKey != "" {
		req.Header.Set("apiKey", s.cfg.APIKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("nvd health check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("nvd health check: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Fetch streams CVEs modified since `since` via a result channel.
// Pagination is handled internally. Rate limiting is applied between pages.
func (s *Source) Fetch(ctx context.Context, since time.Time) (<-chan ingestion.FetchResult, error) {
	ch := make(chan ingestion.FetchResult, 100)

	go func() {
		defer close(ch)

		startIndex := 0
		for {
			if ctx.Err() != nil {
				return
			}

			page, err := s.fetchPage(ctx, since, startIndex)
			if err != nil {
				ch <- ingestion.FetchResult{Err: fmt.Errorf("page %d: %w", startIndex, err)}
				return
			}

			for _, item := range page.Vulnerabilities {
				vuln, raw, err := normalize(item)
				ch <- ingestion.FetchResult{
					Vulnerability: vuln,
					RawPayload:    raw,
					Err:           err,
				}
			}

			startIndex += len(page.Vulnerabilities)
			if startIndex >= page.TotalResults {
				break
			}

			// Respect NVD rate limits between pages.
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.cfg.RateLimitDelay):
			}
		}
	}()

	return ch, nil
}

// nvdResponse is the top-level NVD API v2 response shape.
type nvdResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []nvdCVEWrapper `json:"vulnerabilities"`
}

type nvdCVEWrapper struct {
	CVE json.RawMessage `json:"cve"`
}

func (s *Source) fetchPage(ctx context.Context, since time.Time, startIndex int) (*nvdResponse, error) {
	params := url.Values{}
	params.Set("lastModStartDate", since.UTC().Format("2006-01-02T15:04:05.000Z"))
	params.Set("lastModEndDate", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
	params.Set("resultsPerPage", strconv.Itoa(s.cfg.ResultsPerPage))
	params.Set("startIndex", strconv.Itoa(startIndex))

	reqURL := s.cfg.APIURL + "?" + params.Encode()

	var resp *nvdResponse
	err := retry.Do(ctx, s.cfg.MaxRetries, s.cfg.RetryBaseDelay, s.cfg.RetryMaxDelay, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return retry.Permanent(err)
		}
		if s.cfg.APIKey != "" {
			req.Header.Set("apiKey", s.cfg.APIKey)
		}

		httpResp, err := s.client.Do(req)
		if err != nil {
			return err // transient — retry
		}
		defer httpResp.Body.Close()

		if httpResp.StatusCode == http.StatusTooManyRequests {
			// NVD returns 429 when rate limited; retry after delay
			return fmt.Errorf("rate limited (429)")
		}
		if httpResp.StatusCode != http.StatusOK {
			return retry.Permanent(fmt.Errorf("unexpected status %d", httpResp.StatusCode))
		}

		if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
			return retry.Permanent(fmt.Errorf("decoding response: %w", err))
		}
		return nil
	})

	return resp, err
}

// normalize converts a raw NVD CVE JSON blob into a models.Vulnerability.
func normalize(wrapper nvdCVEWrapper) (*models.Vulnerability, []byte, error) {
	raw := wrapper.CVE
	var item struct {
		ID           string `json:"id"`
		Source       string `json:"sourceIdentifier"`
		Published    string `json:"published"`
		LastModified string `json:"lastModified"`
		VulnStatus   string `json:"vulnStatus"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Weaknesses []struct {
			Description []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description"`
		} `json:"weaknesses"`
		References []struct {
			URL    string `json:"url"`
			Source string `json:"source"`
		} `json:"references"`
		Metrics map[string][]struct {
			Type     string `json:"type"`
			CVSSData struct {
				Version      string  `json:"version"`
				VectorString string  `json:"vectorString"`
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"metrics"`
		Configurations []struct {
			Nodes []struct {
				CPEMatch []map[string]any `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return nil, raw, fmt.Errorf("unmarshal nvd cve: %w", err)
	}
	if item.ID == "" {
		return nil, raw, fmt.Errorf("missing CVE id")
	}

	description := firstLang(item.Descriptions)
	referencesJSON, _ := json.Marshal(item.References)
	cweIDs := extractCWEs(item.Weaknesses)
	cpeMatches := flattenCPEMatches(item.Configurations)
	cpeMatchesJSON, _ := json.Marshal(cpeMatches)

	var (
		publishedAt    *time.Time
		lastModifiedAt *time.Time
	)
	if item.Published != "" {
		if ts, err := time.Parse(time.RFC3339, item.Published); err == nil {
			publishedAt = &ts
		}
	}
	if item.LastModified != "" {
		if ts, err := time.Parse(time.RFC3339, item.LastModified); err == nil {
			lastModifiedAt = &ts
		}
	}

	score, vector, severity := extractPrimaryCVSS(item.Metrics)
	hash := sha256.Sum256(raw)
	vuln := &models.Vulnerability{
		ID:             uuidFromString(item.ID),
		VulnID:         item.ID,
		SourceType:     sourceName,
		Title:          item.ID,
		Description:    description,
		CVSSv3Vector:   vector,
		SeverityLabel:  severity,
		VulnStatus:     normalizeStatus(item.VulnStatus),
		PublishedAt:    publishedAt,
		LastModifiedAt: lastModifiedAt,
		CPEMatches:     cpeMatchesJSON,
		AffectedRanges: []byte("[]"),
		References:     referencesJSON,
		CWEIDs:         cweIDs,
		SourceHash:     fmt.Sprintf("%x", hash[:]),
	}
	if score != nil {
		vuln.CVSSv3Score = score
	}
	return vuln, raw, nil
}

// Job wires the NVD Source with the repository layer into an IngestionJob.
type Job struct {
	source      *Source
	vulnRepo    repository.VulnerabilityRepository
	checkpoints repository.CheckpointRepository
	matching    MatchTrigger
	logger      *zap.Logger
	cfg         config.NVDConfig
}

// MatchTrigger is called after each vulnerability is upserted, triggering the match engine.
// Defined as a function type to avoid an import cycle between ingestion and matching packages.
type MatchTrigger func(ctx context.Context, vulnID string) error

func NewJob(
	source *Source,
	vulnRepo repository.VulnerabilityRepository,
	checkpoints repository.CheckpointRepository,
	matching MatchTrigger,
	logger *zap.Logger,
	cfg config.NVDConfig,
) ingestion.IngestionJob {
	return &Job{
		source:      source,
		vulnRepo:    vulnRepo,
		checkpoints: checkpoints,
		matching:    matching,
		logger:      logger,
		cfg:         cfg,
	}
}

func (j *Job) Source() ingestion.VulnerabilitySource { return j.source }

func (j *Job) Run(ctx context.Context) error {
	if !j.cfg.Enabled {
		j.logger.Info("nvd ingestion disabled")
		return nil
	}

	since := time.Now().UTC().Add(-j.cfg.InitialLookback)
	cp, err := j.checkpoints.Get(ctx, j.source.Name())
	if err != nil {
		return fmt.Errorf("load checkpoint: %w", err)
	}
	if cp != nil && cp.LastSuccessAt != nil {
		since = cp.LastSuccessAt.UTC()
	}

	results, err := j.source.Fetch(ctx, since)
	if err != nil {
		return fmt.Errorf("fetch from source: %w", err)
	}

	var (
		firstErr error
		count    int
	)
	for result := range results {
		if result.Err != nil {
			j.logger.Error("nvd fetch item failed", zap.Error(result.Err))
			if firstErr == nil {
				firstErr = result.Err
			}
			continue
		}
		if result.Vulnerability == nil {
			continue
		}

		rec := &models.VulnerabilitySourceRecord{
			ID:          uuidFromString(result.Vulnerability.VulnID + ":" + j.source.Name() + ":" + result.Vulnerability.SourceHash),
			VulnID:      result.Vulnerability.VulnID,
			SourceType:  j.source.Name(),
			RawPayload:  result.RawPayload,
			PayloadHash: result.Vulnerability.SourceHash,
			IngestedAt:  time.Now().UTC(),
		}
		if err := j.vulnRepo.UpsertSourceRecord(ctx, rec); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("store source record for %s: %w", result.Vulnerability.VulnID, err)
			}
			continue
		}
		if err := j.vulnRepo.Upsert(ctx, result.Vulnerability); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("upsert vulnerability %s: %w", result.Vulnerability.VulnID, err)
			}
			continue
		}
		if j.matching != nil {
			if err := j.matching(ctx, result.Vulnerability.VulnID); err != nil {
				j.logger.Warn("matching trigger failed", zap.String("vuln_id", result.Vulnerability.VulnID), zap.Error(err))
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		count++
	}

	now := time.Now().UTC()
	saveErr := j.checkpoints.Save(ctx, &models.IngestionCheckpoint{
		SourceType:     j.source.Name(),
		LastSuccessAt:  &now,
		CheckpointData: []byte(now.Format(time.RFC3339)),
		Metadata:       []byte(fmt.Sprintf(`{"ingested_count":%d}`, count)),
	})
	if saveErr != nil && firstErr == nil {
		firstErr = fmt.Errorf("save checkpoint: %w", saveErr)
	}

	if firstErr == nil {
		j.logger.Info("nvd ingestion completed", zap.Int("ingested_count", count), zap.Time("since", since))
	}
	return firstErr
}

func firstLang(items []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, item := range items {
		if item.Lang == "en" && item.Value != "" {
			return item.Value
		}
	}
	if len(items) > 0 {
		return items[0].Value
	}
	return ""
}

func extractCWEs(weaknesses []struct {
	Description []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"description"`
}) []string {
	var cwes []string
	seen := map[string]bool{}
	for _, weakness := range weaknesses {
		for _, desc := range weakness.Description {
			if desc.Value == "" || desc.Value == "NVD-CWE-noinfo" || seen[desc.Value] {
				continue
			}
			seen[desc.Value] = true
			cwes = append(cwes, desc.Value)
		}
	}
	return cwes
}

func flattenCPEMatches(configs []struct {
	Nodes []struct {
		CPEMatch []map[string]any `json:"cpeMatch"`
	} `json:"nodes"`
}) []map[string]any {
	var matches []map[string]any
	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			matches = append(matches, node.CPEMatch...)
		}
	}
	return matches
}

func extractPrimaryCVSS(metrics map[string][]struct {
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}) (*float64, string, string) {
	order := []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}
	for _, key := range order {
		entries := metrics[key]
		if len(entries) == 0 {
			continue
		}
		score := entries[0].CVSSData.BaseScore
		vector := entries[0].CVSSData.VectorString
		severity := entries[0].CVSSData.BaseSeverity
		if severity == "" {
			severity = "unknown"
		}
		return &score, vector, normalizeSeverity(severity)
	}
	return nil, "", "unknown"
}

func normalizeSeverity(value string) string {
	switch value {
	case "CRITICAL", "critical":
		return "critical"
	case "HIGH", "high":
		return "high"
	case "MEDIUM", "medium", "MODERATE", "moderate":
		return "medium"
	case "LOW", "low":
		return "low"
	case "NONE", "none":
		return "none"
	default:
		return "unknown"
	}
}

func normalizeStatus(value string) string {
	switch value {
	case "Modified", "modified":
		return models.VulnStatusModified
	case "Rejected", "rejected":
		return models.VulnStatusRejected
	case "Disputed", "disputed":
		return models.VulnStatusDisputed
	default:
		return models.VulnStatusPublished
	}
}

func uuidFromString(value string) uuid.UUID {
	return uuid.NewSHA1(uuid.Nil, []byte(value))
}
