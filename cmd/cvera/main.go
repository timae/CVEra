package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/yourorg/cvera/internal/alerting/slack"
	"github.com/yourorg/cvera/internal/api"
	"github.com/yourorg/cvera/internal/config"
	"github.com/yourorg/cvera/internal/db"
	"github.com/yourorg/cvera/internal/ingestion"
	"github.com/yourorg/cvera/internal/ingestion/nvd"
	"github.com/yourorg/cvera/internal/matching"
	"github.com/yourorg/cvera/internal/repository"
	"github.com/yourorg/cvera/internal/scheduler"
)

var configPath string

func main() {
	root := &cobra.Command{
		Use:   "cvera",
		Short: "Vulnerability monitoring for managed services",
	}
	root.PersistentFlags().StringVar(&configPath, "config", "", "path to config file (default: ./configs/config.yaml)")

	root.AddCommand(
		newServeCmd(),
		newMigrateCmd(),
		newCatalogCmd(),
		newClientCmd(),
		newAlertCmd(),
		newIngestCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// newServeCmd is the main daemon command.
func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the vulnerability monitoring daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			logger, err := buildLogger(cfg.Logging)
			if err != nil {
				return fmt.Errorf("building logger: %w", err)
			}
			defer logger.Sync() //nolint:errcheck

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			// Database
			sqlDB, backend, err := db.Open(ctx, cfg.Database)
			if err != nil {
				return fmt.Errorf("connecting to database: %w", err)
			}
			defer sqlDB.Close()

			// Run migrations on startup
			if err := db.Migrate(ctx, sqlDB, backend); err != nil {
				return fmt.Errorf("running migrations: %w", err)
			}

			// Repositories
			catalogRepo := repository.NewCatalogRepository(sqlDB)
			enrollRepo  := repository.NewEnrollmentRepository(sqlDB)
			vulnRepo    := repository.NewVulnerabilityRepository(sqlDB)
			matchRepo   := repository.NewMatchRepository(sqlDB)
			alertRepo   := repository.NewAlertRepository(sqlDB)
			checkpoints := repository.NewCheckpointRepository(sqlDB)

			// Slack notifier
			notifier := slack.NewNotifier(cfg.Alerting.Slack, logger)
			_ = notifier // wired into alert engine below

			// Matching engine — matchers run in order: CPE exact → CPE range → package → fuzzy
			matchEngine := matching.NewEngine(
				[]matching.Matcher{
					matching.NewCPEMatcher(),
					matching.NewPackageMatcher(),
				},
				catalogRepo,
				vulnRepo,
				matchRepo,
				nil, // alert trigger wired below
				logger,
			)
			_ = matchEngine

			// NVD ingestion
			nvdSource := nvd.NewSource(cfg.Ingestion.NVD, logger)
			nvdJob    := nvd.NewJob(nvdSource, vulnRepo, checkpoints, nil, logger, cfg.Ingestion.NVD)

			// Ingestion runner
			runner := ingestion.NewRunner(logger, nvdJob)
			_ = runner

			// Scheduler
			sched := scheduler.New(sqlDB, backend, logger)
			sched.Register("nvd_ingestion", cfg.Ingestion.NVD.Schedule, func(ctx context.Context) error {
				return runner.RunSource(ctx, "nvd")
			})

			// HTTP server
			httpSrv := api.NewServer(cfg.Server, cfg.Metrics, logger, func() *time.Time {
				// TODO: return real last NVD ingestion time from checkpoint repo
				return nil
			})

			// Wire up unused vars to prevent compile error while stubs exist
			_, _, _, _, _ = enrollRepo, matchRepo, alertRepo, checkpoints, notifier

			// Start scheduler
			sched.Start()
			defer sched.Stop()

			logger.Info("cvera started")

			// Start HTTP server (non-blocking)
			go func() {
				if err := httpSrv.Start(ctx); err != nil {
					logger.Error("http server error", zap.Error(err))
				}
			}()

			// Wait for shutdown signal
			<-ctx.Done()
			logger.Info("shutting down")
			return nil
		},
	}
}

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "migrate", Short: "Database migration commands"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "up",
			Short: "Apply all pending migrations",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := config.Load(configPath)
				if err != nil {
					return err
				}
				return sqlDB2, backend2, _ := db.Open(context.Background(), cfg.Database); defer sqlDB2.Close(); return db.Migrate(context.Background(), sqlDB2, backend2)
			},
		},
		&cobra.Command{
			Use:   "down",
			Short: "Roll back the last migration",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := config.Load(configPath)
				if err != nil {
					return err
				}
				return sqlDB2, backend2, _ := db.Open(context.Background(), cfg.Database); defer sqlDB2.Close(); return db.MigrateDown(context.Background(), sqlDB2, backend2)
			},
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show migration status",
			RunE: func(cmd *cobra.Command, args []string) error {
				cfg, err := config.Load(configPath)
				if err != nil {
					return err
				}
				return sqlDB2, backend2, _ := db.Open(context.Background(), cfg.Database); defer sqlDB2.Close(); return db.MigrateStatus(context.Background(), sqlDB2, backend2)
			},
		},
	)
	return cmd
}

func newCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "catalog", Short: "Manage the service catalog"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "import",
			Short: "Import catalog services from a YAML file",
			RunE: func(cmd *cobra.Command, args []string) error {
				// TODO: implement
				return fmt.Errorf("not implemented")
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List catalog services",
			RunE: func(cmd *cobra.Command, args []string) error {
				// TODO: implement
				return fmt.Errorf("not implemented")
			},
		},
		&cobra.Command{
			Use:   "update",
			Short: "Update a catalog service version",
			RunE: func(cmd *cobra.Command, args []string) error {
				// TODO: implement — parse --service and --version flags
				return fmt.Errorf("not implemented")
			},
		},
	)
	return cmd
}

func newClientCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "client", Short: "Manage clients and enrollments"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "import",
			Short: "Import clients and enrollments from a YAML file",
			RunE: func(cmd *cobra.Command, args []string) error {
				return fmt.Errorf("not implemented")
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List clients",
			RunE: func(cmd *cobra.Command, args []string) error {
				return fmt.Errorf("not implemented")
			},
		},
	)
	return cmd
}

func newAlertCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "alert", Short: "Manage alerts"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List alerts",
			RunE: func(cmd *cobra.Command, args []string) error {
				return fmt.Errorf("not implemented")
			},
		},
		&cobra.Command{
			Use:   "ack [alert-id]",
			Short: "Acknowledge an alert",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return fmt.Errorf("not implemented")
			},
		},
		&cobra.Command{
			Use:   "suppress",
			Short: "Create a suppression rule",
			RunE: func(cmd *cobra.Command, args []string) error {
				return fmt.Errorf("not implemented")
			},
		},
	)
	return cmd
}

func newIngestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ingest run",
		Short: "Trigger an immediate ingestion run",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}

func buildLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	var zapCfg zap.Config
	if cfg.Level == "debug" {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}
	level, err := zap.ParseAtomicLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("parsing log level: %w", err)
	}
	zapCfg.Level = level
	return zapCfg.Build()
}
