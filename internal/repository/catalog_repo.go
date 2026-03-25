package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/yourorg/cvera/internal/models"
)

type pgCatalogRepository struct {
	db *sql.DB
}

func NewCatalogRepository(db *sql.DB) CatalogRepository {
	return &pgCatalogRepository{db: db}
}

func (r *pgCatalogRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.CatalogService, error) {
	return r.getOne(ctx, "WHERE id = ?", id.String())
}

func (r *pgCatalogRepository) GetBySlug(ctx context.Context, slug string) (*models.CatalogService, error) {
	return r.getOne(ctx, "WHERE slug = ?", slug)
}

func (r *pgCatalogRepository) List(ctx context.Context) ([]*models.CatalogService, error) {
	query := rebindPlaceholders(r.db, baseCatalogSelect()+" ORDER BY name")
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCatalogRows(rows)
}

func (r *pgCatalogRepository) ListActive(ctx context.Context) ([]*models.CatalogService, error) {
	query := rebindPlaceholders(r.db, baseCatalogSelect()+" WHERE 1=1 ORDER BY name")
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	services, err := scanCatalogRows(rows)
	if err != nil {
		return nil, err
	}
	active := make([]*models.CatalogService, 0, len(services))
	for _, s := range services {
		if s.Active {
			active = append(active, s)
		}
	}
	return active, nil
}

func (r *pgCatalogRepository) Upsert(ctx context.Context, s *models.CatalogService) error {
	if s == nil {
		return errors.New("nil catalog service")
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	s.UpdatedAt = time.Now().UTC()
	if s.Criticality == "" {
		s.Criticality = "medium"
	}
	if s.Exposure == "" {
		s.Exposure = "internal"
	}
	if !s.Active {
		s.Active = true
	}
	tags, err := json.Marshal(s.Tags)
	if err != nil {
		return err
	}

	if isPostgres(r.db) {
		query := `
			INSERT INTO catalog_services (
				id, slug, name, description, cpe23, current_version, package_name, package_type,
				default_criticality, default_exposure, metadata
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
			ON CONFLICT (slug) DO UPDATE SET
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				cpe23 = EXCLUDED.cpe23,
				current_version = EXCLUDED.current_version,
				package_name = EXCLUDED.package_name,
				package_type = EXCLUDED.package_type,
				default_criticality = EXCLUDED.default_criticality,
				default_exposure = EXCLUDED.default_exposure,
				metadata = EXCLUDED.metadata,
				updated_at = NOW()
		`
		_, err = r.db.ExecContext(ctx, query,
			s.ID.String(), s.Slug, s.Name, s.Notes, nullableString(s.CPE23), s.Version,
			nullableString(s.PackageName), nullableString(s.PackageEcosystem), s.Criticality, s.Exposure, string(tags),
		)
		return err
	}

	query := `
		INSERT INTO catalog_services (
			id, slug, name, description, cpe23, current_version, package_name, package_type,
			default_criticality, default_exposure, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(slug) DO UPDATE SET
			name = excluded.name,
			description = excluded.description,
			cpe23 = excluded.cpe23,
			current_version = excluded.current_version,
			package_name = excluded.package_name,
			package_type = excluded.package_type,
			default_criticality = excluded.default_criticality,
			default_exposure = excluded.default_exposure,
			metadata = excluded.metadata,
			updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
	`
	_, err = r.db.ExecContext(ctx, query,
		s.ID.String(), s.Slug, s.Name, s.Notes, nullableString(s.CPE23), s.Version,
		nullableString(s.PackageName), nullableString(s.PackageEcosystem), s.Criticality, s.Exposure, string(tags),
	)
	return err
}

func (r *pgCatalogRepository) UpdateVersion(ctx context.Context, id uuid.UUID, newVersion, changedBy, notes string) (string, error) {
	current, err := r.GetByID(ctx, id)
	if err != nil {
		return "", err
	}
	if current == nil {
		return "", sql.ErrNoRows
	}

	updateQuery := rebindPlaceholders(r.db, "UPDATE catalog_services SET current_version = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	if !isPostgres(r.db) {
		updateQuery = "UPDATE catalog_services SET current_version = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?"
	}
	if _, err := r.db.ExecContext(ctx, updateQuery, newVersion, id.String()); err != nil {
		return "", err
	}

	historyQuery := rebindPlaceholders(r.db, "INSERT INTO catalog_version_history (id, catalog_service_id, previous_version, new_version, changed_by) VALUES (?, ?, ?, ?, ?)")
	_, err = r.db.ExecContext(ctx, historyQuery, uuid.New().String(), id.String(), current.Version, newVersion, firstNonEmpty(changedBy, notes, "system"))
	if err != nil {
		return "", err
	}
	return current.Version, nil
}

func (r *pgCatalogRepository) ListByCPEComponent(ctx context.Context, vendor, product string) ([]*models.CatalogService, error) {
	query := rebindPlaceholders(r.db, baseCatalogSelect()+" WHERE cpe23 LIKE ? ORDER BY name")
	rows, err := r.db.QueryContext(ctx, query, "%:"+vendor+":"+product+":%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCatalogRows(rows)
}

func (r *pgCatalogRepository) ListByPackage(ctx context.Context, ecosystem, name string) ([]*models.CatalogService, error) {
	query := rebindPlaceholders(r.db, baseCatalogSelect()+" WHERE package_type = ? AND package_name = ? ORDER BY name")
	rows, err := r.db.QueryContext(ctx, query, ecosystem, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCatalogRows(rows)
}

func (r *pgCatalogRepository) getOne(ctx context.Context, where string, arg any) (*models.CatalogService, error) {
	query := rebindPlaceholders(r.db, baseCatalogSelect()+" "+where+" LIMIT 1")
	rows, err := r.db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	services, err := scanCatalogRows(rows)
	if err != nil {
		return nil, err
	}
	if len(services) == 0 {
		return nil, nil
	}
	return services[0], nil
}

func baseCatalogSelect() string {
	return `
		SELECT id, slug, name, description, cpe23, current_version, package_name, package_type,
		       default_criticality, default_exposure, metadata, created_at, updated_at
		FROM catalog_services
	`
}

func scanCatalogRows(rows *sql.Rows) ([]*models.CatalogService, error) {
	var services []*models.CatalogService
	for rows.Next() {
		var (
			s         models.CatalogService
			cpe23     sql.NullString
			pkgName   sql.NullString
			pkgType   sql.NullString
			metaRaw   string
			createdAt any
			updatedAt any
		)
		if err := rows.Scan(
			&s.ID, &s.Slug, &s.Name, &s.Notes, &cpe23, &s.Version, &pkgName, &pkgType,
			&s.Criticality, &s.Exposure, &metaRaw, &createdAt, &updatedAt,
		); err != nil {
			return nil, err
		}
		if cpe23.Valid {
			s.CPE23 = cpe23.String
		}
		if pkgName.Valid {
			s.PackageName = pkgName.String
		}
		if pkgType.Valid {
			s.PackageEcosystem = pkgType.String
		}
		if metaRaw != "" {
			_ = json.Unmarshal([]byte(metaRaw), &s.Tags)
		}
		s.Active = true
		if ts, err := parseDBTime(createdAt); err == nil {
			s.CreatedAt = ts
		}
		if ts, err := parseDBTime(updatedAt); err == nil {
			s.UpdatedAt = ts
		}
		services = append(services, &s)
	}
	return services, rows.Err()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
