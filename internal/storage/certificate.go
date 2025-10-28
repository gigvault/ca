package storage

import (
	"context"
	"fmt"
	"time"

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

// Certificate represents a certificate for gRPC server
type Certificate struct {
	Serial           string
	SubjectCN        string
	IssuerCN         string
	NotBefore        time.Time
	NotAfter         time.Time
	PEM              string
	Status           string
	Profile          string
	RevokedAt        *time.Time
	RevocationReason string
}

// StoreCertificate stores a certificate
func (s *CertificateStorage) StoreCertificate(ctx context.Context, cert *Certificate) error {
	query := `
		INSERT INTO certificates (serial, subject_cn, issuer_cn, not_before, not_after, pem, status, profile)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := s.db.Exec(ctx, query,
		cert.Serial,
		cert.SubjectCN,
		cert.IssuerCN,
		cert.NotBefore,
		cert.NotAfter,
		cert.PEM,
		cert.Status,
		cert.Profile,
	)

	if err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	return nil
}

// GetCertificate retrieves a certificate by serial
func (s *CertificateStorage) GetCertificate(ctx context.Context, serial string) (*Certificate, error) {
	query := `
		SELECT serial, subject_cn, issuer_cn, not_before, not_after, pem, status, profile, revoked_at, revocation_reason
		FROM certificates
		WHERE serial = $1
	`

	var cert Certificate
	err := s.db.QueryRow(ctx, query, serial).Scan(
		&cert.Serial,
		&cert.SubjectCN,
		&cert.IssuerCN,
		&cert.NotBefore,
		&cert.NotAfter,
		&cert.PEM,
		&cert.Status,
		&cert.Profile,
		&cert.RevokedAt,
		&cert.RevocationReason,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return &cert, nil
}

// ListCertificates lists certificates with optional status filter
func (s *CertificateStorage) ListCertificates(ctx context.Context, statusFilter string) ([]*Certificate, error) {
	query := `
		SELECT serial, subject_cn, issuer_cn, not_before, not_after, pem, status, profile, revoked_at, revocation_reason
		FROM certificates
	`

	var args []interface{}
	if statusFilter != "" {
		query += " WHERE status = $1"
		args = append(args, statusFilter)
	}

	query += " ORDER BY not_before DESC LIMIT 100"

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}
	defer rows.Close()

	var certs []*Certificate
	for rows.Next() {
		var cert Certificate
		err := rows.Scan(
			&cert.Serial,
			&cert.SubjectCN,
			&cert.IssuerCN,
			&cert.NotBefore,
			&cert.NotAfter,
			&cert.PEM,
			&cert.Status,
			&cert.Profile,
			&cert.RevokedAt,
			&cert.RevocationReason,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}
		certs = append(certs, &cert)
	}

	return certs, nil
}

// RevokeCertificate revokes a certificate
func (s *CertificateStorage) RevokeCertificate(ctx context.Context, serial string, reason string) error {
	query := `
		UPDATE certificates
		SET status = 'revoked', revoked_at = NOW(), revocation_reason = $2
		WHERE serial = $1
	`

	_, err := s.db.Exec(ctx, query, serial, reason)
	if err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	return nil
}
