package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/yourorg/cvera/internal/config"
)

// Server is the HTTP API server.
// It exposes health, readiness, metrics, and a minimal status endpoint.
// No auth at MVP — use network controls (VPC, firewall) to restrict access.
type Server struct {
	cfg    config.ServerConfig
	mux    *http.ServeMux
	srv    *http.Server
	logger *zap.Logger

	// Dependencies injected for readiness checks and status reporting.
	lastNVDIngestion func() *time.Time // returns last successful NVD ingest time
}

func NewServer(cfg config.ServerConfig, metricsCfg config.MetricsConfig, logger *zap.Logger, lastNVDIngestion func() *time.Time) *Server {
	s := &Server{
		cfg:              cfg,
		mux:              http.NewServeMux(),
		logger:           logger,
		lastNVDIngestion: lastNVDIngestion,
	}

	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)
	s.mux.HandleFunc("/api/v1/status", s.handleStatus)

	if metricsCfg.Enabled {
		s.mux.Handle(metricsCfg.Path, promhttp.Handler())
	}

	s.srv = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:      s.mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return s
}

// Start begins serving. Blocks until ctx is cancelled or an error occurs.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
	}()

	s.logger.Info("HTTP server starting", zap.String("addr", s.srv.Addr))
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}

// handleHealthz always returns 200 if the process is running.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleReadyz returns 200 if the service is ready to serve traffic.
// Returns 503 if last NVD ingestion is stale (> 2 hours).
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	last := s.lastNVDIngestion()
	if last == nil || time.Since(*last) > 2*time.Hour {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("nvd ingestion stale"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// statusResponse is the /api/v1/status response body.
type statusResponse struct {
	Ingestion map[string]ingestionStatus `json:"ingestion"`
}

type ingestionStatus struct {
	LastSuccess *time.Time `json:"last_success"`
	AgeSeconds  *float64   `json:"age_seconds"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	// TODO: populate from real checkpoint data
	resp := statusResponse{
		Ingestion: map[string]ingestionStatus{
			"nvd": {LastSuccess: s.lastNVDIngestion()},
		},
	}
	if t := resp.Ingestion["nvd"].LastSuccess; t != nil {
		age := time.Since(*t).Seconds()
		entry := resp.Ingestion["nvd"]
		entry.AgeSeconds = &age
		resp.Ingestion["nvd"] = entry
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
