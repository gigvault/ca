package service

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/gigvault/ca/internal/storage"
	"github.com/gigvault/shared/pkg/crypto"
	"github.com/gigvault/shared/pkg/logger"
	"github.com/gigvault/shared/pkg/models"
	"go.uber.org/zap"
)

// CAService handles certificate authority operations
type CAService struct {
	certStorage *storage.CertificateStorage
	csrStorage  *storage.CSRStorage
	logger      *logger.Logger
	// TODO: Load CA certificate and key from secure storage
}

// NewCAService creates a new CA service
func NewCAService(certStorage *storage.CertificateStorage, csrStorage *storage.CSRStorage, logger *logger.Logger) *CAService {
	return &CAService{
		certStorage: certStorage,
		csrStorage:  csrStorage,
		logger:      logger,
	}
}

// ListCertificates lists all certificates
func (s *CAService) ListCertificates(ctx context.Context) ([]*models.Certificate, error) {
	return s.certStorage.List(ctx)
}

// GetCertificate retrieves a certificate by serial number
func (s *CAService) GetCertificate(ctx context.Context, serial string) (*models.Certificate, error) {
	return s.certStorage.GetBySerial(ctx, serial)
}

// SignCertificate signs a CSR and creates a certificate
func (s *CAService) SignCertificate(ctx context.Context, csrPEM string, validityDays int) (*models.Certificate, error) {
	// Parse the CSR
	csr, err := crypto.ParseCSR([]byte(csrPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	s.logger.Info("Signing certificate",
		zap.String("subject", csr.Subject.CommonName),
		zap.Int("validity_days", validityDays),
	)

	// TODO: In production, load the actual CA certificate and key from secure storage
	// For now, generate a temporary certificate template
	template, err := crypto.CreateCertificateTemplate(csr.Subject.CommonName, validityDays)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate template: %w", err)
	}

	// Copy subject information from CSR
	template.Subject = pkix.Name{
		CommonName:   csr.Subject.CommonName,
		Organization: csr.Subject.Organization,
		Country:      csr.Subject.Country,
	}

	// TODO: Load CA key and cert, then sign
	// For development, we'll create a self-signed cert as placeholder
	caKey, err := crypto.GenerateP256Key()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	certPEM, err := crypto.SignCertificate(template, template, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Store certificate in database
	cert := &models.Certificate{
		Serial:    template.SerialNumber.String(),
		SubjectCN: template.Subject.CommonName,
		NotBefore: template.NotBefore,
		NotAfter:  template.NotAfter,
		PEM:       string(certPEM),
		Revoked:   false,
		CreatedAt: time.Now(),
	}

	if err := s.certStorage.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("failed to store certificate: %w", err)
	}

	return cert, nil
}

// RevokeCertificate revokes a certificate
func (s *CAService) RevokeCertificate(ctx context.Context, serial string) error {
	s.logger.Info("Revoking certificate", zap.String("serial", serial))

	cert, err := s.certStorage.GetBySerial(ctx, serial)
	if err != nil {
		return fmt.Errorf("certificate not found: %w", err)
	}

	now := time.Now()
	cert.Revoked = true
	cert.RevokedAt = &now

	if err := s.certStorage.Update(ctx, cert); err != nil {
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	// TODO: Publish to CRL and OCSP responder

	return nil
}

// SubmitCSR submits a new CSR for approval
func (s *CAService) SubmitCSR(ctx context.Context, csrPEM, submittedBy string) (*models.CSR, error) {
	// Parse the CSR
	csr, err := crypto.ParseCSR([]byte(csrPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	csrModel := &models.CSR{
		SubjectCN:   csr.Subject.CommonName,
		SubjectOrg:  getFirst(csr.Subject.Organization),
		SubjectOU:   getFirst(csr.Subject.OrganizationalUnit),
		PEM:         csrPEM,
		Status:      "pending",
		SubmittedBy: submittedBy,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.csrStorage.Create(ctx, csrModel); err != nil {
		return nil, fmt.Errorf("failed to store CSR: %w", err)
	}

	s.logger.Info("CSR submitted", zap.String("subject", csr.Subject.CommonName))

	return csrModel, nil
}

func getFirst(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
