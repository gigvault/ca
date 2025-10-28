package storage

import (
	"context"
	"fmt"

	"github.com/gigvault/shared/pkg/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CertificateStorage handles certificate database operations
type CertificateStorage struct {
	db *pgxpool.Pool
}

// NewCertificateStorage creates a new certificate storage
func NewCertificateStorage(db *pgxpool.Pool) *CertificateStorage {
	return &CertificateStorage{db: db}
}

// Create creates a new certificate
func (s *CertificateStorage) Create(ctx context.Context, cert *models.Certificate) error {
	query := `
		INSERT INTO certificates (serial, subject_cn, not_before, not_after, pem, revoked, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`

	err := s.db.QueryRow(ctx, query,
		cert.Serial,
		cert.SubjectCN,
		cert.NotBefore,
		cert.NotAfter,
		cert.PEM,
		cert.Revoked,
		cert.CreatedAt,
	).Scan(&cert.ID)

	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	return nil
}

// GetBySerial retrieves a certificate by serial number
func (s *CertificateStorage) GetBySerial(ctx context.Context, serial string) (*models.Certificate, error) {
	query := `
		SELECT id, serial, subject_cn, not_before, not_after, pem, revoked, revoked_at, created_at
		FROM certificates
		WHERE serial = $1
	`

	var cert models.Certificate
	err := s.db.QueryRow(ctx, query, serial).Scan(
		&cert.ID,
		&cert.Serial,
		&cert.SubjectCN,
		&cert.NotBefore,
		&cert.NotAfter,
		&cert.PEM,
		&cert.Revoked,
		&cert.RevokedAt,
		&cert.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return &cert, nil
}

// List retrieves all certificates
func (s *CertificateStorage) List(ctx context.Context) ([]*models.Certificate, error) {
	query := `
		SELECT id, serial, subject_cn, not_before, not_after, pem, revoked, revoked_at, created_at
		FROM certificates
		ORDER BY created_at DESC
		LIMIT 100
	`

	rows, err := s.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}
	defer rows.Close()

	var certs []*models.Certificate
	for rows.Next() {
		var cert models.Certificate
		err := rows.Scan(
			&cert.ID,
			&cert.Serial,
			&cert.SubjectCN,
			&cert.NotBefore,
			&cert.NotAfter,
			&cert.PEM,
			&cert.Revoked,
			&cert.RevokedAt,
			&cert.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}
		certs = append(certs, &cert)
	}

	return certs, nil
}

// Update updates a certificate
func (s *CertificateStorage) Update(ctx context.Context, cert *models.Certificate) error {
	query := `
		UPDATE certificates
		SET revoked = $1, revoked_at = $2
		WHERE id = $3
	`

	_, err := s.db.Exec(ctx, query, cert.Revoked, cert.RevokedAt, cert.ID)
	if err != nil {
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	return nil
}
