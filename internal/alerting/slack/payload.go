package slack

import (
	"fmt"
	"strings"

	"github.com/yourorg/vulnmon/internal/alerting"
)

// slackMessage is the top-level Slack Block Kit message.
type slackMessage struct {
	Blocks      []map[string]any `json:"blocks"`
	Attachments []map[string]any `json:"attachments,omitempty"`
}

// buildPayload constructs a Slack Block Kit message from an AlertPayload.
// Using map[string]any for blocks gives full flexibility without
// encoding every Block Kit element type — the structure mirrors the JSON directly.
func buildPayload(p *alerting.AlertPayload) *slackMessage {
	headerText := fmt.Sprintf("%s %s — %s in %s %s",
		severityEmoji(p.SeverityLabel),
		strings.ToUpper(p.SeverityLabel),
		p.VulnID,
		p.CatalogServiceName,
		p.AffectedVersion,
	)

	desc := p.Description
	if p.InCISAKEV {
		desc = ":rotating_light: *ACTIVELY EXPLOITED (CISA KEV)*\n\n" + desc
	}

	cvssText := "N/A"
	if p.CVSSScore != nil {
		cvssText = fmt.Sprintf("%.1f %s", *p.CVSSScore, strings.ToUpper(p.SeverityLabel))
		if p.CVSSVector != nil {
			cvssText += "\n`" + *p.CVSSVector + "`"
		}
	}

	epssText := "N/A"
	if p.EPSSScore != nil {
		epssText = fmt.Sprintf("%.4f", *p.EPSSScore)
		if p.EPSSPercentile != nil {
			epssText += fmt.Sprintf(" (%dth percentile)", int(*p.EPSSPercentile*100))
		}
		if *p.EPSSScore >= 0.5 {
			epssText = ":warning: High Exploit Probability — " + epssText
		}
	}

	confidenceText := fmt.Sprintf("✅ %s (%s)", capitalize(p.Confidence), p.MatchMethod)
	if p.Confidence == "weak" || p.Confidence == "unknown" {
		confidenceText = fmt.Sprintf("⚠️ %s (%s) — manual review recommended", capitalize(p.Confidence), p.MatchMethod)
	}

	footer := fmt.Sprintf(
		"Resolve: `vulnmon catalog update --service=%s --version=<patched>` | "+
			"Ack: `vulnmon alert ack %s --note=\"...\"` | "+
			"Suppress: `vulnmon alert suppress --cve=%s --service=%s`\nVulnMon",
		p.CatalogServiceSlug, p.AlertID[:8], p.VulnID, p.CatalogServiceSlug,
	)

	nvdURL := "https://nvd.nist.gov/vuln/detail/" + p.VulnID

	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{"type": "plain_text", "text": headerText},
		},
		{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": desc},
		},
		{
			"type": "section",
			"fields": []map[string]any{
				{"type": "mrkdwn", "text": "*Catalog Service*\n" + p.CatalogServiceName},
				{"type": "mrkdwn", "text": "*Affected Version*\n" + p.AffectedVersion},
				{"type": "mrkdwn", "text": "*CVSS v3.1*\n" + cvssText},
				{"type": "mrkdwn", "text": "*EPSS*\n" + epssText},
				{"type": "mrkdwn", "text": "*Match Confidence*\n" + confidenceText},
				{"type": "mrkdwn", "text": "*Alert ID*\n`" + p.AlertID[:8] + "`"},
			},
		},
		{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": buildClientList(p.AffectedClients)},
		},
		{
			"type": "actions",
			"elements": []map[string]any{
				{
					"type":  "button",
					"style": "primary",
					"text":  map[string]any{"type": "plain_text", "text": "View on NVD"},
					"url":   nvdURL,
				},
			},
		},
		{
			"type": "context",
			"elements": []map[string]any{
				{"type": "mrkdwn", "text": footer},
			},
		},
	}

	return &slackMessage{
		Blocks: blocks,
		Attachments: []map[string]any{
			{"color": severityColor(p.SeverityLabel)},
		},
	}
}

func buildClientList(clients []alerting.AffectedClient) string {
	if len(clients) == 0 {
		return "*Affected Clients*\nNone currently enrolled"
	}
	const maxShown = 10
	var sb strings.Builder
	fmt.Fprintf(&sb, "*Affected Clients (%d)*\n", len(clients))
	shown := clients
	if len(clients) > maxShown {
		shown = clients[:maxShown]
	}
	for _, c := range shown {
		line := fmt.Sprintf("• %s — %s, %s", c.Name, c.Environment, c.Criticality)
		if c.Exposure == "public" {
			line += " _(exposure: public)_"
		}
		sb.WriteString(line + "\n")
	}
	if len(clients) > maxShown {
		fmt.Fprintf(&sb, "_...and %d more_", len(clients)-maxShown)
	}
	return strings.TrimRight(sb.String(), "\n")
}

func severityColor(label string) string {
	switch strings.ToLower(label) {
	case "critical":
		return "#FF0000"
	case "high":
		return "#FF6600"
	case "medium":
		return "#FFAA00"
	case "low":
		return "#00AA00"
	default:
		return "#AAAAAA"
	}
}

func severityEmoji(label string) string {
	switch strings.ToLower(label) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
