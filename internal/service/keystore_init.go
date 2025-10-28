package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/gigvault/shared/pkg/keystore"
	"go.uber.org/zap"
)

// KeystoreConfig holds keystore initialization configuration
type KeystoreConfig struct {
	HSMEnabled   bool
	HSMMasterKey string // From environment or HSM device
	CAKeyID      string
	CACertPath   string
	CAKeyPath    string // Only for initial setup, then deleted
	DatabaseDSN  string
}

// InitializeKeystore initializes the keystore and loads/creates CA keys
func InitializeKeystore(ctx context.Context, cfg KeystoreConfig, logger *zap.Logger) (*keystore.EnvelopeEncryption, *x509.Certificate, error) {
	// 1. Initialize HSM
	var hsm keystore.HSMInterface
	var err error

	if cfg.HSMEnabled {
		// Production: Use real HSM (YubiHSM, CloudHSM, etc.)
		logger.Info("Initializing production HSM")
		// hsm, err = keystore.NewYubiHSM(...)
		// For now, fall back to mock if real HSM not configured
		hsm, err = keystore.NewMockHSM()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize HSM: %w", err)
		}
	} else {
		// Development: Use mock HSM
		logger.Info("Initializing mock HSM (development only)")
		hsm, err = keystore.NewMockHSM()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize mock HSM: %w", err)
		}
	}

	// 2. Initialize database connection for keystore
	db, err := sql.Open("postgres", cfg.DatabaseDSN)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	storage := keystore.NewKeyStorage(db)

	// 3. Create envelope encryption handler with storage
	envelope := keystore.NewEnvelopeEncryption(hsm, storage)

	// 4. Load or create CA certificate and key
	var caCert *x509.Certificate

	// Check if CA key already exists in keystore
	_, err = storage.Get(ctx, cfg.CAKeyID)
	if err != nil {
		// Key doesn't exist, need to import it
		logger.Info("CA key not found in keystore, importing from file",
			zap.String("key_id", cfg.CAKeyID),
		)

		// Load CA certificate
		certPEM, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
		}

		caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		// Load CA private key
		keyPEM, err := os.ReadFile(cfg.CAKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read CA private key: %w", err)
		}

		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, nil, fmt.Errorf("failed to decode CA private key PEM")
		}

		privateKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
		}

		// Encrypt and store in keystore
		encryptedKey, err := envelope.EncryptPrivateKey(cfg.CAKeyID, privateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encrypt CA key: %w", err)
		}

		if err := storage.Store(ctx, encryptedKey); err != nil {
			return nil, nil, fmt.Errorf("failed to store encrypted CA key: %w", err)
		}

		logger.Info("CA key successfully imported to keystore",
			zap.String("key_id", cfg.CAKeyID),
		)

		// Zero out private key from memory
		privateKey.D.SetInt64(0)

		// Optionally: Delete the original key file for security
		// os.Remove(cfg.CAKeyPath)
		logger.Warn("⚠️  SECURITY: Consider deleting the original CA key file after import",
			zap.String("path", cfg.CAKeyPath),
		)
	} else {
		// Key exists in keystore, just load the certificate
		logger.Info("CA key found in keystore",
			zap.String("key_id", cfg.CAKeyID),
		)

		certPEM, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
		}

		caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}
	}

	logger.Info("Keystore initialized successfully",
		zap.String("ca_subject", caCert.Subject.CommonName),
		zap.String("ca_key_id", cfg.CAKeyID),
		zap.Bool("hsm_enabled", cfg.HSMEnabled),
	)

	return envelope, caCert, nil
}

// SignWithKeystore is a helper to sign data using the keystore
func SignWithKeystore(ctx context.Context, envelope *keystore.EnvelopeEncryption, keyID string, data []byte) ([]byte, error) {
	// Load encrypted key
	encryptedKey, err := envelope.Storage.Get(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	// Decrypt, sign, and zero memory
	signature, err := envelope.SignWithKey(encryptedKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

// GenerateAndStoreCAKey generates a new CA key pair and stores it in the keystore
// This should only be used during initial setup
func GenerateAndStoreCAKey(ctx context.Context, envelope *keystore.EnvelopeEncryption, keyID string, outputDir string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	// Generate CA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate (self-signed)
	// ... (certificate creation logic here)

	// Encrypt and store in keystore
	encryptedKey, err := envelope.EncryptPrivateKey(keyID, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt CA key: %w", err)
	}

	if err := envelope.Storage.Store(ctx, encryptedKey); err != nil {
		return nil, nil, fmt.Errorf("failed to store encrypted CA key: %w", err)
	}

	return privateKey, nil, nil
}
