package storage

import (
	"context"
	"fmt"
	"strconv"
	"time"

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

// GetByID retrieves a CSR by ID (string or int64)
func (s *CSRStorage) GetByID(ctx context.Context, idStr string) (*models.CSR, error) {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid CSR ID: %w", err)
	}

	query := `
		SELECT id, subject_cn, subject_org, subject_ou, pem, status, 
		       submitted_by, approved_by, certificate_id, created_at, updated_at
		FROM csrs
		WHERE id = $1
	`

	var csr models.CSR
	err = s.db.QueryRow(ctx, query, id).Scan(
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

// List retrieves all CSRs with optional status filter
func (s *CSRStorage) List(ctx context.Context, status string) ([]*models.CSR, error) {
	var query string
	var args []interface{}

	if status != "" {
		query = `
			SELECT id, subject_cn, subject_org, subject_ou, pem, status, 
			       submitted_by, approved_by, certificate_id, created_at, updated_at
			FROM csrs
			WHERE status = $1
			ORDER BY created_at DESC
			LIMIT 100
		`
		args = append(args, status)
	} else {
		query = `
			SELECT id, subject_cn, subject_org, subject_ou, pem, status, 
			       submitted_by, approved_by, certificate_id, created_at, updated_at
			FROM csrs
			ORDER BY created_at DESC
			LIMIT 100
		`
	}

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list CSRs: %w", err)
	}
	defer rows.Close()

	var csrs []*models.CSR
	for rows.Next() {
		var csr models.CSR
		err := rows.Scan(
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
			return nil, fmt.Errorf("failed to scan CSR: %w", err)
		}
		csrs = append(csrs, &csr)
	}

	return csrs, nil
}

// Update updates a CSR
func (s *CSRStorage) Update(ctx context.Context, csr *models.CSR) error {
	query := `
		UPDATE csrs
		SET status = $1, approved_by = $2, certificate_id = $3, updated_at = $4
		WHERE id = $5
	`

	csr.UpdatedAt = time.Now()

	_, err := s.db.Exec(ctx, query,
		csr.Status,
		csr.ApprovedBy,
		csr.CertificateID,
		csr.UpdatedAt,
		csr.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update CSR: %w", err)
	}

	return nil
}
