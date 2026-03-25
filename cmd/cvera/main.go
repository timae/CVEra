package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/yourorg/cvera/internal/alerting"
	"github.com/yourorg/cvera/internal/alerting/slack"
	"github.com/yourorg/cvera/internal/api"
	"github.com/yourorg/cvera/internal/config"
	"github.com/yourorg/cvera/internal/db"
	"github.com/yourorg/cvera/internal/ingestion"
	"github.com/yourorg/cvera/internal/ingestion/nvd"
	"github.com/yourorg/cvera/internal/matching"
	"github.com/yourorg/cvera/internal/models"
	"github.com/yourorg/cvera/internal/repository"
	"github.com/yourorg/cvera/internal/scheduler"
)

var (
	configPath string
	Version    = "dev"
	Commit     = "unknown"
	BuildDate  = "unknown"
)

func main() {
	root := &cobra.Command{
		Use:   "cvera",
		Short: "Vulnerability monitoring for managed services",
	}
	root.PersistentFlags().StringVar(&configPath, "config", "", "path to config file (default: ./configs/config.yaml)")
	root.Version = fmt.Sprintf("%s (%s, %s)", Version, Commit, BuildDate)

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

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the vulnerability monitoring daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, sqlDB, backend, checkpoints, err := openRuntime(cmd.Context())
			if err != nil {
				return err
			}
			defer logger.Sync() //nolint:errcheck
			defer sqlDB.Close()

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			catalogRepo := repository.NewCatalogRepository(sqlDB)
			enrollRepo := repository.NewEnrollmentRepository(sqlDB)
			vulnRepo := repository.NewVulnerabilityRepository(sqlDB)
			matchRepo := repository.NewMatchRepository(sqlDB)
			alertRepo := repository.NewAlertRepository(sqlDB)

			notifier := slack.NewNotifier(cfg.Alerting.Slack, logger)
			suppressRepo := repository.NewSuppressionRepository(sqlDB)
			alertEngine := alerting.NewEngine(
				matchRepo,
				alertRepo,
				enrollRepo,
				vulnRepo,
				catalogRepo,
				suppressRepo,
				notifier,
				cfg.Alerting,
				logger,
			)
			matchEngine := matching.NewEngine(
				[]matching.Matcher{
					matching.NewCPEMatcher(),
					matching.NewPackageMatcher(),
				},
				catalogRepo,
				vulnRepo,
				matchRepo,
				alertEngine.ProcessNewMatches,
				logger,
			)

			nvdSource := nvd.NewSource(cfg.Ingestion.NVD, logger)
			nvdJob := nvd.NewJob(nvdSource, vulnRepo, checkpoints, matchEngine.RunForVulnerability, logger, cfg.Ingestion.NVD)
			runner := ingestion.NewRunner(logger, nvdJob)

			sched := scheduler.New(sqlDB, backend, logger)
			if cfg.Ingestion.NVD.Schedule != "" {
				sched.Register("nvd_ingestion", cfg.Ingestion.NVD.Schedule, func(ctx context.Context) error {
					return runner.RunSource(ctx, "nvd")
				})
			}

			httpSrv := api.NewServer(cfg.Server, cfg.Metrics, logger, func() *time.Time {
				cp, err := checkpoints.Get(context.Background(), "nvd")
				if err != nil || cp == nil {
					return nil
				}
				return cp.LastSuccessAt
			})

			_, _, _, _ = enrollRepo, alertRepo, notifier, alertEngine

			sched.Start()
			defer sched.Stop()

			logger.Info("cvera started", zap.String("version", Version))

			go func() {
				if err := httpSrv.Start(ctx); err != nil {
					logger.Error("http server error", zap.Error(err))
				}
			}()

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
				return withDatabase(cmd.Context(), func(_ *config.Config, sqlDB *sql.DB, backend db.Backend) error {
					return db.Migrate(cmd.Context(), sqlDB, backend)
				})
			},
		},
		&cobra.Command{
			Use:   "down",
			Short: "Roll back the last migration",
			RunE: func(cmd *cobra.Command, args []string) error {
				return withDatabase(cmd.Context(), func(_ *config.Config, sqlDB *sql.DB, backend db.Backend) error {
					return db.MigrateDown(cmd.Context(), sqlDB, backend)
				})
			},
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show migration status",
			RunE: func(cmd *cobra.Command, args []string) error {
				return withDatabase(cmd.Context(), func(_ *config.Config, sqlDB *sql.DB, backend db.Backend) error {
					return db.MigrateStatus(cmd.Context(), sqlDB, backend)
				})
			},
		},
	)
	return cmd
}

func newCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "catalog", Short: "Manage the service catalog"}

	cmd.AddCommand(&cobra.Command{
		Use:   "import <path>",
		Short: "Import catalog services from a YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDatabase(cmd.Context(), func(_ *config.Config, sqlDB *sql.DB, _ db.Backend) error {
				repo := repository.NewCatalogRepository(sqlDB)
				spec, err := loadCatalogSpec(args[0])
				if err != nil {
					return err
				}
				for _, service := range spec.Services {
					model := &models.CatalogService{
						ID:               uuid.New(),
						Slug:             service.Slug,
						Name:             service.Name,
						Version:          service.CurrentVersion,
						CPE23:            service.CPE23,
						PackageName:      service.PackageName,
						PackageEcosystem: service.PackageType,
						Criticality:      defaultString(service.DefaultCriticality, "medium"),
						Exposure:         defaultString(service.DefaultExposure, "internal"),
						Tags:             service.Metadata,
						Notes:            service.Description,
						Active:           true,
					}
					if err := repo.Upsert(cmd.Context(), model); err != nil {
						return fmt.Errorf("importing service %s: %w", service.Slug, err)
					}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "imported %d catalog services\n", len(spec.Services))
				return nil
			})
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List catalog services",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDatabase(cmd.Context(), func(_ *config.Config, sqlDB *sql.DB, _ db.Backend) error {
				repo := repository.NewCatalogRepository(sqlDB)
				services, err := repo.List(cmd.Context())
				if err != nil {
					return err
				}
				for _, service := range services {
					fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", service.Slug, service.Version, service.Name)
				}
				return nil
			})
		},
	})

	return cmd
}

func newClientCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "client", Short: "Manage clients and enrollments"}

	cmd.AddCommand(&cobra.Command{
		Use:   "import <path>",
		Short: "Import clients and enrollments from a YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDatabase(cmd.Context(), func(_ *config.Config, sqlDB *sql.DB, _ db.Backend) error {
				clientRepo := repository.NewClientRepository(sqlDB)
				catalogRepo := repository.NewCatalogRepository(sqlDB)
				enrollmentRepo := repository.NewEnrollmentRepository(sqlDB)

				spec, err := loadClientSpec(args[0])
				if err != nil {
					return err
				}
				for _, client := range spec.Clients {
					model := &models.Client{
						ID:      uuid.New(),
						Slug:    client.Slug,
						Name:    client.Name,
						Contact: client.ContactEmail,
						Active:  true,
					}
					if err := clientRepo.Upsert(cmd.Context(), model); err != nil {
						return fmt.Errorf("importing client %s: %w", client.Slug, err)
					}
					savedClient, err := clientRepo.GetBySlug(cmd.Context(), client.Slug)
					if err != nil || savedClient == nil {
						return fmt.Errorf("reloading client %s: %w", client.Slug, err)
					}
					for _, enrollment := range client.Enrollments {
						service, err := catalogRepo.GetBySlug(cmd.Context(), enrollment.Service)
						if err != nil {
							return err
						}
						if service == nil {
							return fmt.Errorf("unknown service slug %q for client %s", enrollment.Service, client.Slug)
						}
						entry := &models.ClientEnrollment{
							ID:                  uuid.New(),
							ClientID:            savedClient.ID,
							CatalogServiceID:    service.ID,
							CriticalityOverride: enrollment.Criticality,
							ExposureOverride:    enrollment.Exposure,
							Notes:               enrollment.SuppressionReason,
							Active:              true,
						}
						if enrollment.Suppressed {
							if enrollment.SuppressionEndDate != "" {
								ts, err := time.Parse(time.RFC3339, enrollment.SuppressionEndDate)
								if err != nil {
									return fmt.Errorf("invalid suppression_end_date for %s/%s: %w", client.Slug, enrollment.Service, err)
								}
								entry.SuppressUntil = &ts
							} else {
								farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
								entry.SuppressUntil = &farFuture
							}
						}
						if err := enrollmentRepo.Enroll(cmd.Context(), entry); err != nil {
							return fmt.Errorf("enrolling %s in %s: %w", client.Slug, enrollment.Service, err)
						}
					}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "imported %d clients\n", len(spec.Clients))
				return nil
			})
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List clients",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDatabase(cmd.Context(), func(_ *config.Config, sqlDB *sql.DB, _ db.Backend) error {
				repo := repository.NewClientRepository(sqlDB)
				clients, err := repo.List(cmd.Context())
				if err != nil {
					return err
				}
				for _, client := range clients {
					fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", client.Slug, client.Name)
				}
				return nil
			})
		},
	})

	return cmd
}

func newAlertCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "alert",
		Short: "Manage alerts",
	}
}

func newIngestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Run ingestion tasks",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Trigger an immediate ingestion run",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, sqlDB, _, checkpoints, err := openRuntime(cmd.Context())
			if err != nil {
				return err
			}
			defer logger.Sync() //nolint:errcheck
			defer sqlDB.Close()

			vulnRepo := repository.NewVulnerabilityRepository(sqlDB)
			catalogRepo := repository.NewCatalogRepository(sqlDB)
			matchRepo := repository.NewMatchRepository(sqlDB)
			alertRepo := repository.NewAlertRepository(sqlDB)
			enrollRepo := repository.NewEnrollmentRepository(sqlDB)
			suppressRepo := repository.NewSuppressionRepository(sqlDB)
			source := nvd.NewSource(cfg.Ingestion.NVD, logger)
			notifier := slack.NewNotifier(cfg.Alerting.Slack, logger)
			alertEngine := alerting.NewEngine(matchRepo, alertRepo, enrollRepo, vulnRepo, catalogRepo, suppressRepo, notifier, cfg.Alerting, logger)
			matchEngine := matching.NewEngine(
				[]matching.Matcher{
					matching.NewCPEMatcher(),
					matching.NewPackageMatcher(),
				},
				catalogRepo,
				vulnRepo,
				matchRepo,
				alertEngine.ProcessNewMatches,
				logger,
			)
			job := nvd.NewJob(source, vulnRepo, checkpoints, matchEngine.RunForVulnerability, logger, cfg.Ingestion.NVD)
			if err := job.Run(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ingestion completed")
			return nil
		},
	})
	return cmd
}

func openRuntime(ctx context.Context) (*config.Config, *zap.Logger, *sql.DB, db.Backend, repository.CheckpointRepository, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, nil, "", nil, fmt.Errorf("loading config: %w", err)
	}

	logger, err := buildLogger(cfg.Logging)
	if err != nil {
		return nil, nil, nil, "", nil, fmt.Errorf("building logger: %w", err)
	}

	sqlDB, backend, err := db.Open(ctx, cfg.Database)
	if err != nil {
		return nil, nil, nil, "", nil, fmt.Errorf("connecting to database: %w", err)
	}
	if err := db.Migrate(ctx, sqlDB, backend); err != nil {
		sqlDB.Close()
		return nil, nil, nil, "", nil, fmt.Errorf("running migrations: %w", err)
	}

	return cfg, logger, sqlDB, backend, repository.NewCheckpointRepository(sqlDB), nil
}

func withDatabase(ctx context.Context, fn func(cfg *config.Config, sqlDB *sql.DB, backend db.Backend) error) error {
	cfg, _, sqlDB, backend, _, err := openRuntime(ctx)
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	return fn(cfg, sqlDB, backend)
}

type catalogSpec struct {
	Services []catalogServiceSpec `yaml:"services"`
}

type catalogServiceSpec struct {
	Slug               string            `yaml:"slug"`
	Name               string            `yaml:"name"`
	Description        string            `yaml:"description"`
	CPE23              string            `yaml:"cpe23"`
	CurrentVersion     string            `yaml:"current_version"`
	PackageName        string            `yaml:"package_name"`
	PackageType        string            `yaml:"package_type"`
	DefaultCriticality string            `yaml:"default_criticality"`
	DefaultExposure    string            `yaml:"default_exposure"`
	Metadata           map[string]string `yaml:"metadata"`
}

type clientSpec struct {
	Clients []clientEntrySpec `yaml:"clients"`
}

type clientEntrySpec struct {
	Slug         string             `yaml:"slug"`
	Name         string             `yaml:"name"`
	ContactEmail string             `yaml:"contact_email"`
	Enrollments  []clientEnrollSpec `yaml:"enrollments"`
}

type clientEnrollSpec struct {
	Service            string `yaml:"service"`
	Exposure           string `yaml:"exposure"`
	Criticality        string `yaml:"criticality"`
	Suppressed         bool   `yaml:"suppressed"`
	SuppressionReason  string `yaml:"suppression_reason"`
	SuppressionEndDate string `yaml:"suppression_end_date"`
}

func loadCatalogSpec(path string) (*catalogSpec, error) {
	var spec catalogSpec
	if err := loadYAML(path, &spec); err != nil {
		return nil, err
	}
	sort.Slice(spec.Services, func(i, j int) bool { return spec.Services[i].Slug < spec.Services[j].Slug })
	return &spec, nil
}

func loadClientSpec(path string) (*clientSpec, error) {
	var spec clientSpec
	if err := loadYAML(path, &spec); err != nil {
		return nil, err
	}
	sort.Slice(spec.Clients, func(i, j int) bool { return spec.Clients[i].Slug < spec.Clients[j].Slug })
	return &spec, nil
}

func loadYAML(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	return nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
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
	if cfg.Format == "console" {
		zapCfg.Encoding = "console"
	}
	return zapCfg.Build()
}
