package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourorg/cvera/internal/models"
)

type pgEnrollmentRepository struct {
	pool *pgxpool.Pool
}

func NewEnrollmentRepository(pool *pgxpool.Pool) EnrollmentRepository {
	return &pgEnrollmentRepository{pool: pool}
}

func (r *pgEnrollmentRepository) ListByService(ctx context.Context, catalogServiceID uuid.UUID) ([]*models.ClientEnrollment, error) {
	// TODO: implement
	// JOIN client_enrollments ON clients to populate ClientName, ClientSlug, Contact
	// WHERE catalog_service_id = $1 AND active = true
	return nil, errors.New("not implemented")
}

func (r *pgEnrollmentRepository) ListByClient(ctx context.Context, clientID uuid.UUID) ([]*models.ClientEnrollment, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (r *pgEnrollmentRepository) Enroll(ctx context.Context, e *models.ClientEnrollment) error {
	// TODO: implement — ON CONFLICT (client_id, catalog_service_id) DO UPDATE
	return errors.New("not implemented")
}

func (r *pgEnrollmentRepository) Unenroll(ctx context.Context, clientID, catalogServiceID uuid.UUID) error {
	// TODO: implement — SET active = false
	return errors.New("not implemented")
}

func (r *pgEnrollmentRepository) CountByService(ctx context.Context, catalogServiceID uuid.UUID) (int, error) {
	// TODO: implement — SELECT COUNT(*) WHERE catalog_service_id = $1 AND active = true
	return 0, errors.New("not implemented")
}
