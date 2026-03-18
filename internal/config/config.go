package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Ingestion IngestionConfig `mapstructure:"ingestion"`
	Matching  MatchingConfig  `mapstructure:"matching"`
	Alerting  AlertingConfig  `mapstructure:"alerting"`
	Logging   LoggingConfig   `mapstructure:"logging"`
	Metrics   MetricsConfig   `mapstructure:"metrics"`
}

type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type DatabaseConfig struct {
	// Backend selects the storage engine.
	//   "sqlite"   — zero-infrastructure, single file on disk (default)
	//   "postgres" — full PostgreSQL for multi-replica / production use
	Backend    string `mapstructure:"backend"`
	// SQLitePath is the path to the SQLite database file.
	// Only used when Backend = "sqlite". Defaults to "cvera.db".
	SQLitePath string `mapstructure:"sqlite_path"`

	// PostgreSQL fields — only used when Backend = "postgres".
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	Name         string        `mapstructure:"name"`
	User         string        `mapstructure:"user"`
	Password     string        `mapstructure:"password"`  // CVERA_DATABASE_PASSWORD
	SSLMode      string        `mapstructure:"ssl_mode"`
	MaxOpenConns int           `mapstructure:"max_open_conns"`
	MaxIdleConns int           `mapstructure:"max_idle_conns"`
	ConnTimeout  time.Duration `mapstructure:"conn_timeout"`
}

func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s connect_timeout=%d",
		d.Host, d.Port, d.Name, d.User, d.Password, d.SSLMode,
		int(d.ConnTimeout.Seconds()),
	)
}

type IngestionConfig struct {
	NVD     NVDConfig     `mapstructure:"nvd"`
	CISAKEV CISAKEVConfig `mapstructure:"cisa_kev"`
	EPSS    EPSSConfig    `mapstructure:"epss"`
	OSV     OSVConfig     `mapstructure:"osv"`
}

type NVDConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	APIURL          string        `mapstructure:"api_url"`
	APIKey          string        `mapstructure:"api_key"` // CVERA_INGESTION_NVD_API_KEY
	Schedule        string        `mapstructure:"schedule"`
	InitialLookback time.Duration `mapstructure:"initial_lookback"`
	RateLimitDelay  time.Duration `mapstructure:"rate_limit_delay"`
	ResultsPerPage  int           `mapstructure:"results_per_page"`
	MaxRetries      int           `mapstructure:"max_retries"`
	RetryBaseDelay  time.Duration `mapstructure:"retry_base_delay"`
	RetryMaxDelay   time.Duration `mapstructure:"retry_max_delay"`
}

type CISAKEVConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	URL        string        `mapstructure:"url"`
	Schedule   string        `mapstructure:"schedule"`
	MaxRetries int           `mapstructure:"max_retries"`
}

type EPSSConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	APIURL       string `mapstructure:"api_url"`
	Schedule     string `mapstructure:"schedule"`
	LookbackDays int    `mapstructure:"lookback_days"`
}

type OSVConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	APIURL     string `mapstructure:"api_url"`
	MaxRetries int    `mapstructure:"max_retries"`
}

type MatchingConfig struct {
	MinConfidence      string `mapstructure:"min_confidence"`
	MinAlertConfidence string `mapstructure:"min_alert_confidence"`
	RunAfterIngestion  bool   `mapstructure:"run_after_ingestion"`
}

type AlertingConfig struct {
	Slack                  SlackConfig   `mapstructure:"slack"`
	MinCVSSScore           float64       `mapstructure:"min_cvss_score"`
	AlertOnKEV             bool          `mapstructure:"alert_on_kev"`
	AlertOnEPSSThreshold   float64       `mapstructure:"alert_on_epss_threshold"`
	ReNotifyOnKEVEntry     bool          `mapstructure:"re_notify_on_kev_entry"`
	ReNotifyOnCVSSIncrease float64       `mapstructure:"re_notify_on_cvss_increase"`
	ReNotifyCooldown       time.Duration `mapstructure:"re_notify_cooldown"`
}

type SlackConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	WebhookURL string        `mapstructure:"webhook_url"` // CVERA_ALERTING_SLACK_WEBHOOK_URL
	Channel    string        `mapstructure:"channel"`
	Timeout    time.Duration `mapstructure:"timeout"`
	MaxRetries int           `mapstructure:"max_retries"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

// Load reads config from file + env var overrides.
// Env vars use the prefix CVERA_ and dot → underscore mapping.
// Example: CVERA_DATABASE_PASSWORD overrides database.password
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("database.backend", "sqlite")
	v.SetDefault("database.sqlite_path", "cvera.db")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.ssl_mode", "require")
	v.SetDefault("database.max_open_conns", 20)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_timeout", "10s")
	v.SetDefault("ingestion.nvd.api_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
	v.SetDefault("ingestion.nvd.schedule", "0 * * * *")
	v.SetDefault("ingestion.nvd.initial_lookback", "720h")
	v.SetDefault("ingestion.nvd.rate_limit_delay", "700ms")
	v.SetDefault("ingestion.nvd.results_per_page", 2000)
	v.SetDefault("ingestion.nvd.max_retries", 3)
	v.SetDefault("ingestion.nvd.retry_base_delay", "2s")
	v.SetDefault("ingestion.nvd.retry_max_delay", "60s")
	v.SetDefault("ingestion.cisa_kev.url",
		"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	v.SetDefault("ingestion.cisa_kev.schedule", "0 6 * * *")
	v.SetDefault("ingestion.cisa_kev.max_retries", 3)
	v.SetDefault("ingestion.epss.api_url", "https://api.first.org/data/v1/epss")
	v.SetDefault("ingestion.epss.schedule", "0 7 * * *")
	v.SetDefault("ingestion.epss.lookback_days", 7)
	v.SetDefault("ingestion.osv.api_url", "https://api.osv.dev/v1")
	v.SetDefault("ingestion.osv.max_retries", 3)
	v.SetDefault("matching.min_confidence", "weak")
	v.SetDefault("matching.min_alert_confidence", "strong")
	v.SetDefault("matching.run_after_ingestion", true)
	v.SetDefault("alerting.min_cvss_score", 7.0)
	v.SetDefault("alerting.alert_on_kev", true)
	v.SetDefault("alerting.alert_on_epss_threshold", 0.5)
	v.SetDefault("alerting.re_notify_on_kev_entry", true)
	v.SetDefault("alerting.re_notify_on_cvss_increase", 2.0)
	v.SetDefault("alerting.re_notify_cooldown", "24h")
	v.SetDefault("alerting.slack.timeout", "10s")
	v.SetDefault("alerting.slack.max_retries", 3)
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.path", "/metrics")

	// Config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath("./configs")
		v.AddConfigPath("/etc/cvera")
	}
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	// Env var overrides
	v.SetEnvPrefix("CVERA")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, cfg.Validate()
}

func (c *Config) Validate() error {
	switch c.Database.Backend {
	case "sqlite", "":
		// SQLitePath defaults to "cvera.db" — nothing required.
	case "postgres":
		if c.Database.Host == "" {
			return fmt.Errorf("database.host is required when backend is postgres")
		}
		if c.Database.Name == "" {
			return fmt.Errorf("database.name is required when backend is postgres")
		}
	default:
		return fmt.Errorf("database.backend must be \"sqlite\" or \"postgres\", got %q", c.Database.Backend)
	}
	if c.Alerting.Slack.Enabled && c.Alerting.Slack.WebhookURL == "" {
		return fmt.Errorf("alerting.slack.webhook_url required when slack enabled")
	}
	valid := map[string]bool{"exact": true, "strong": true, "weak": true, "unknown": true}
	if c.Matching.MinAlertConfidence != "" && !valid[c.Matching.MinAlertConfidence] {
		return fmt.Errorf("matching.min_alert_confidence must be one of: exact, strong, weak, unknown")
	}
	return nil
}
