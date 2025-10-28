package storage

import (
	"context"
	"fmt"

	"github.com/gigvault/shared/pkg/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CSRStorage handles CSR database operations
type CSRStorage struct {
	db *pgxpool.Pool
}

// NewCSRStorage creates a new CSR storage
func NewCSRStorage(db *pgxpool.Pool) *CSRStorage {
	return &CSRStorage{db: db}
}

// Create creates a new CSR
func (s *CSRStorage) Create(ctx context.Context, csr *models.CSR) error {
	query := `
		INSERT INTO csrs (subject_cn, subject_org, subject_ou, pem, status, submitted_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`

	err := s.db.QueryRow(ctx, query,
		csr.SubjectCN,
		csr.SubjectOrg,
		csr.SubjectOU,
		csr.PEM,
		csr.Status,
		csr.SubmittedBy,
		csr.CreatedAt,
		csr.UpdatedAt,
	).Scan(&csr.ID)

	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	return nil
}

// GetByID retrieves a CSR by ID
func (s *CSRStorage) GetByID(ctx context.Context, id int64) (*models.CSR, error) {
	query := `
		SELECT id, subject_cn, subject_org, subject_ou, pem, status, 
		       submitted_by, approved_by, certificate_id, created_at, updated_at
		FROM csrs
		WHERE id = $1
	`

	var csr models.CSR
	err := s.db.QueryRow(ctx, query, id).Scan(
		&csr.ID,
		&csr.SubjectCN,
		&csr.SubjectOrg,
		&csr.SubjectOU,
		&csr.PEM,
		&csr.Status,
		&csr.SubmittedBy,
		&csr.ApprovedBy,
		&csr.CertificateID,
		&csr.CreatedAt,
		&csr.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get CSR: %w", err)
	}

	return &csr, nil
}
