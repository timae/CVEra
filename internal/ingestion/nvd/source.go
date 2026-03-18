package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/yourorg/vulnmon/internal/config"
	"github.com/yourorg/vulnmon/internal/ingestion"
	"github.com/yourorg/vulnmon/internal/models"
	"github.com/yourorg/vulnmon/internal/repository"
	"github.com/yourorg/vulnmon/pkg/retry"
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
	ResultsPerPage int              `json:"resultsPerPage"`
	StartIndex     int              `json:"startIndex"`
	TotalResults   int              `json:"totalResults"`
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
	// TODO: implement full NVD → models.Vulnerability normalization.
	// Key fields: cveId, descriptions, metrics (cvssMetricV31, cvssMetricV40),
	// weaknesses (cweId), references, configurations (cpe matches),
	// vulnStatus, published, lastModified.
	raw := wrapper.CVE
	_ = raw
	return nil, nil, fmt.Errorf("nvd normalize: not implemented")
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
	// TODO: implement full ingestion loop:
	// 1. Load checkpoint to get `since` timestamp
	// 2. Call source.Fetch(ctx, since)
	// 3. For each result: UpsertSourceRecord, Upsert vulnerability
	// 4. If VulnStatus == REJECTED: InvalidateForVuln
	// 5. If matching trigger set: call matching(ctx, vulnID)
	// 6. Save updated checkpoint
	// 7. Emit metrics
	return fmt.Errorf("nvd job: not implemented")
}
