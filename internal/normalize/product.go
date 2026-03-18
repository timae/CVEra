package normalize

import "strings"

// productAliases maps common product name variations to a canonical form.
// This table grows as mismatches are discovered in practice.
// Treat it as a managed artifact — track changes in git.
var productAliases = map[string]string{
	"apache httpd":    "httpd",
	"apache http":     "httpd",
	"nginx":           "nginx",
	"openssl":         "openssl",
	"openssh":         "openssh",
	"haproxy":         "haproxy",
	"argo cd":         "argo_cd",
	"argocd":          "argo_cd",
	"loki":            "loki",
	"grafana loki":    "loki",
	"microsoft iis":   "iis",
	"fluent bit":      "fluent_bit",
	"fluentbit":       "fluent_bit",
	// Note: Fluent Bit CPE vendor in NVD is "treasuredata" despite CNCF ownership.
	// Add mapping here, not in the CPE parser.
}

// noiseWords are stripped from product names before alias lookup.
var noiseWords = []string{
	" server", " enterprise", " community", " edition",
	" open source", " professional", " standard",
}

// NormalizeProductName lowercases, strips noise, and applies known aliases.
// Used by the fuzzy product matcher.
func NormalizeProductName(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "-", " ")
	s = strings.ReplaceAll(s, "_", " ")

	for _, noise := range noiseWords {
		s = strings.ReplaceAll(s, noise, "")
	}
	s = strings.TrimSpace(s)

	if alias, ok := productAliases[s]; ok {
		return alias
	}
	return s
}
