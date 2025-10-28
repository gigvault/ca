package service

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/gigvault/ca/internal/storage"
	"github.com/gigvault/shared/pkg/crypto"
	"github.com/gigvault/shared/pkg/keystore"
	"github.com/gigvault/shared/pkg/logger"
	"github.com/gigvault/shared/pkg/models"
	"go.uber.org/zap"
)

// CAService handles certificate authority operations
type CAService struct {
	certStorage    *storage.CertificateStorage
	csrStorage     *storage.CSRStorage
	logger         *logger.Logger
	revocationChan chan<- *models.Certificate // Channel for async revocation publishing
	keystore       *keystore.EnvelopeEncryption
	caCert         *x509.Certificate
	caKeyID        string
}

// NewCAService creates a new CA service
func NewCAService(certStorage *storage.CertificateStorage, csrStorage *storage.CSRStorage, logger *logger.Logger) *CAService {
	return &CAService{
		certStorage: certStorage,
		csrStorage:  csrStorage,
		logger:      logger,
	}
}

// NewCAServiceWithKeystore creates a new CA service with keystore integration
func NewCAServiceWithKeystore(
	certStorage *storage.CertificateStorage,
	csrStorage *storage.CSRStorage,
	logger *logger.Logger,
	revocationChan chan<- *models.Certificate,
	keystore *keystore.EnvelopeEncryption,
	caCert *x509.Certificate,
	caKeyID string,
) *CAService {
	return &CAService{
		certStorage:    certStorage,
		csrStorage:     csrStorage,
		logger:         logger,
		revocationChan: revocationChan,
		keystore:       keystore,
		caCert:         caCert,
		caKeyID:        caKeyID,
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

	// Check if keystore is configured
	if s.keystore != nil && s.caCert != nil && s.caKeyID != "" {
		// Use keystore for signing (production mode)
		return s.signWithKeystore(ctx, csr, validityDays)
	}

	// Fallback to temporary key generation (development mode)
	return s.signWithTemporaryKey(ctx, csr, validityDays)
}

// signWithKeystore signs using the keystore (production)
func (s *CAService) signWithKeystore(ctx context.Context, csr *x509.CertificateRequest, validityDays int) (*models.Certificate, error) {
	s.logger.Info("Signing certificate with keystore",
		zap.String("subject", csr.Subject.CommonName),
		zap.String("ca_key_id", s.caKeyID),
		zap.Int("validity_days", validityDays),
	)

	// Create certificate template
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

	// Load encrypted CA key from keystore
	encryptedKey, err := s.keystore.Storage.Get(ctx, s.caKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA key from keystore: %w", err)
	}

	// Decrypt CA key (key will be in memory only during signing)
	caKey, err := s.keystore.DecryptPrivateKey(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CA key: %w", err)
	}
	// Ensure key is zeroed from memory after use
	defer func() {
		if caKey != nil && caKey.D != nil {
			caKey.D.SetInt64(0)
		}
	}()

	// Sign the certificate with CA key
	certPEM, err := crypto.SignCertificate(template, s.caCert, csr.PublicKey, caKey)
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

	s.logger.Info("Certificate signed successfully with keystore",
		zap.String("serial", cert.Serial),
		zap.String("subject", cert.SubjectCN),
	)

	return cert, nil
}

// signWithTemporaryKey signs using a temporary key (development only)
func (s *CAService) signWithTemporaryKey(ctx context.Context, csr *x509.CertificateRequest, validityDays int) (*models.Certificate, error) {
	s.logger.Warn("Signing certificate with temporary key (DEVELOPMENT ONLY)",
		zap.String("subject", csr.Subject.CommonName),
	)

	// Create certificate template
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

	// Generate temporary CA key (DEVELOPMENT ONLY!)
	caKey, err := crypto.GenerateP256Key()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Self-sign (no real CA)
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

	// Publish to CRL and OCSP responder (async via worker)
	if s.revocationChan != nil {
		select {
		case s.revocationChan <- cert:
			s.logger.Info("Revocation queued for publishing", zap.String("serial", serial))
		default:
			s.logger.Warn("Revocation channel full, publishing may be delayed", zap.String("serial", serial))
		}
	}

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

// GetCSR retrieves a CSR by ID
func (s *CAService) GetCSR(ctx context.Context, id string) (*models.CSR, error) {
	return s.csrStorage.GetByID(ctx, id)
}

// ListCSRs lists all CSRs with optional status filter
func (s *CAService) ListCSRs(ctx context.Context, status string) ([]*models.CSR, error) {
	return s.csrStorage.List(ctx, status)
}

func getFirst(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
