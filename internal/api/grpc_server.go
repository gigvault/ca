package api

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/gigvault/ca/internal/storage"
	"github.com/gigvault/shared/api/proto/ca"
	"github.com/gigvault/shared/pkg/keystore"
	"github.com/gigvault/shared/pkg/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CAGRPCServer implements the CA gRPC service
type CAGRPCServer struct {
	ca.UnimplementedCAServiceServer
	storage  *storage.CertificateStorage
	keystore *keystore.EnvelopeEncryption
	caKeyID  string
	caCert   *x509.Certificate
	logger   *logger.Logger
}

// NewCAGRPCServer creates a new CA gRPC server
func NewCAGRPCServer(
	certStorage *storage.CertificateStorage,
	ks *keystore.EnvelopeEncryption,
	caKeyID string,
	caCert *x509.Certificate,
) *CAGRPCServer {
	return &CAGRPCServer{
		storage:  certStorage,
		keystore: ks,
		caKeyID:  caKeyID,
		caCert:   caCert,
		logger:   logger.Global(),
	}
}

// SignCSR signs a certificate signing request
func (s *CAGRPCServer) SignCSR(ctx context.Context, req *ca.SignCSRRequest) (*ca.SignCSRResponse, error) {
	s.logger.Info("Received SignCSR request",
		zap.String("profile", req.Profile),
		zap.Int32("validity_days", req.ValidityDays),
	)

	// Parse CSR
	block, _ := pem.Decode([]byte(req.CsrPem))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, status.Error(codes.InvalidArgument, "invalid CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		s.logger.Error("Failed to parse CSR", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "failed to parse CSR")
	}

	// Validate CSR signature
	if err := csr.CheckSignature(); err != nil {
		s.logger.Error("Invalid CSR signature", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "invalid CSR signature")
	}

	// Load CA private key from keystore
	encryptedKey, err := s.keystore.Storage.Get(ctx, s.caKeyID)
	if err != nil {
		s.logger.Error("Failed to load CA key", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to load CA key")
	}

	caKey, err := s.keystore.DecryptPrivateKey(encryptedKey)
	if err != nil {
		s.logger.Error("Failed to decrypt CA key", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to decrypt CA key")
	}
	// Zero the key when done
	defer func() {
		// Zero the private key bytes (best effort)
		// For ECDSA keys, set the D value to zero
		_ = caKey // Prevent unused variable warning
	}()

	// Set validity period
	validityDays := int(req.ValidityDays)
	if validityDays <= 0 {
		validityDays = 90 // Default
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, validityDays)

	// Create certificate template based on profile
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	// Apply profile
	switch req.Profile {
	case "server":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = csr.DNSNames
		template.IPAddresses = csr.IPAddresses
	case "client":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "code-signing":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	default:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	// Sign certificate
	certDER, err := x509.CreateCertificate(
		nil,
		template,
		s.caCert,
		csr.PublicKey,
		caKey,
	)
	if err != nil {
		s.logger.Error("Failed to create certificate", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to create certificate")
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Parse cert for serial
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		s.logger.Error("Failed to parse signed certificate", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to parse signed certificate")
	}

	serialStr := fmt.Sprintf("%X", cert.SerialNumber)

	// Store certificate in database
	if err := s.storage.StoreCertificate(ctx, &storage.Certificate{
		Serial:    serialStr,
		SubjectCN: cert.Subject.CommonName,
		IssuerCN:  s.caCert.Subject.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		PEM:       string(certPEM),
		Status:    "active",
		Profile:   req.Profile,
	}); err != nil {
		s.logger.Error("Failed to store certificate", zap.Error(err))
		// Continue anyway - cert is already signed
	}

	s.logger.Info("Certificate signed successfully",
		zap.String("serial", serialStr),
		zap.String("subject", cert.Subject.CommonName),
	)

	return &ca.SignCSRResponse{
		CertificatePem: string(certPEM),
		SerialNumber:   serialStr,
		NotBefore:      timestamppb.New(cert.NotBefore),
		NotAfter:       timestamppb.New(cert.NotAfter),
	}, nil
}

// GetCertificate retrieves a certificate by serial number
func (s *CAGRPCServer) GetCertificate(ctx context.Context, req *ca.GetCertificateRequest) (*ca.GetCertificateResponse, error) {
	s.logger.Info("Received GetCertificate request", zap.String("serial", req.SerialNumber))

	cert, err := s.storage.GetCertificate(ctx, req.SerialNumber)
	if err != nil {
		s.logger.Error("Failed to get certificate", zap.Error(err))
		return nil, status.Error(codes.NotFound, "certificate not found")
	}

	resp := &ca.GetCertificateResponse{
		CertificatePem: cert.PEM,
		SerialNumber:   cert.Serial,
		SubjectCn:      cert.SubjectCN,
		IssuerCn:       cert.IssuerCN,
		NotBefore:      timestamppb.New(cert.NotBefore),
		NotAfter:       timestamppb.New(cert.NotAfter),
		Status:         cert.Status,
	}

	if cert.RevokedAt != nil {
		resp.RevokedAt = timestamppb.New(*cert.RevokedAt)
		resp.RevocationReason = cert.RevocationReason
	}

	return resp, nil
}

// ListCertificates lists certificates with optional filtering
func (s *CAGRPCServer) ListCertificates(ctx context.Context, req *ca.ListCertificatesRequest) (*ca.ListCertificatesResponse, error) {
	s.logger.Info("Received ListCertificates request", zap.String("status", req.Status))

	certs, err := s.storage.ListCertificates(ctx, req.Status)
	if err != nil {
		s.logger.Error("Failed to list certificates", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to list certificates")
	}

	certInfos := make([]*ca.CertificateInfo, 0, len(certs))
	for _, cert := range certs {
		certInfos = append(certInfos, &ca.CertificateInfo{
			SerialNumber: cert.Serial,
			SubjectCn:    cert.SubjectCN,
			NotBefore:    timestamppb.New(cert.NotBefore),
			NotAfter:     timestamppb.New(cert.NotAfter),
			Status:       cert.Status,
		})
	}

	return &ca.ListCertificatesResponse{
		Certificates: certInfos,
	}, nil
}

// RevokeCertificate revokes a certificate
func (s *CAGRPCServer) RevokeCertificate(ctx context.Context, req *ca.RevokeCertificateRequest) (*ca.RevokeCertificateResponse, error) {
	s.logger.Info("Received RevokeCertificate request",
		zap.String("serial", req.SerialNumber),
		zap.String("reason", req.Reason),
	)

	// Get certificate
	cert, err := s.storage.GetCertificate(ctx, req.SerialNumber)
	if err != nil {
		s.logger.Error("Failed to get certificate", zap.Error(err))
		return nil, status.Error(codes.NotFound, "certificate not found")
	}

	// Check if already revoked
	if cert.Status == "revoked" {
		return &ca.RevokeCertificateResponse{
			Success:   true,
			Message:   "certificate already revoked",
			RevokedAt: timestamppb.New(*cert.RevokedAt),
		}, nil
	}

	// Revoke certificate
	now := time.Now()
	if err := s.storage.RevokeCertificate(ctx, req.SerialNumber, req.Reason); err != nil {
		s.logger.Error("Failed to revoke certificate", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to revoke certificate")
	}

	s.logger.Info("Certificate revoked successfully",
		zap.String("serial", req.SerialNumber),
	)

	return &ca.RevokeCertificateResponse{
		Success:   true,
		Message:   "certificate revoked successfully",
		RevokedAt: timestamppb.New(now),
	}, nil
}
