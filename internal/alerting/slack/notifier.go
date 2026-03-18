package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/yourorg/cvera/internal/alerting"
	"github.com/yourorg/cvera/internal/config"
	"github.com/yourorg/cvera/pkg/retry"
)

// Notifier implements alerting.Notifier using a Slack incoming webhook.
// Upgrade path: swap webhook URL for a bot token + chat.postMessage to
// enable message updates, threading, and interactive buttons.
type Notifier struct {
	cfg    config.SlackConfig
	client *http.Client
	logger *zap.Logger
}

func NewNotifier(cfg config.SlackConfig, logger *zap.Logger) alerting.Notifier {
	return &Notifier{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		logger: logger,
	}
}

func (n *Notifier) Name() string { return "slack" }

func (n *Notifier) Send(ctx context.Context, payload *alerting.AlertPayload) (string, error) {
	block := buildPayload(payload)

	body, err := json.Marshal(block)
	if err != nil {
		return "", fmt.Errorf("marshaling slack payload: %w", err)
	}

	var msgTS string
	err = retry.Do(ctx, n.cfg.MaxRetries, 2*time.Second, 30*time.Second, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.WebhookURL, bytes.NewReader(body))
		if err != nil {
			return retry.Permanent(err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := n.client.Do(req)
		if err != nil {
			return err // transient
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("slack rate limited")
		}
		if resp.StatusCode == http.StatusGone {
			return retry.Permanent(fmt.Errorf("slack webhook revoked (410) — update config"))
		}
		if resp.StatusCode != http.StatusOK {
			return retry.Permanent(fmt.Errorf("slack returned %d", resp.StatusCode))
		}
		// Webhook endpoints return "ok" in the body, not a message TS.
		// For a bot token + chat.postMessage, parse the JSON response for ts.
		msgTS = ""
		return nil
	})

	return msgTS, err
}
