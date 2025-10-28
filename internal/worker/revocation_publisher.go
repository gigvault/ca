package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/gigvault/shared/pkg/logger"
	"github.com/gigvault/shared/pkg/models"
	"go.uber.org/zap"
)

// RevocationPublisher publishes certificate revocations to CRL and OCSP
type RevocationPublisher struct {
	crlEndpoint  string
	ocspEndpoint string
	logger       *zap.Logger
}

// NewRevocationPublisher creates a new revocation publisher
func NewRevocationPublisher(crlEndpoint, ocspEndpoint string) *RevocationPublisher {
	return &RevocationPublisher{
		crlEndpoint:  crlEndpoint,
		ocspEndpoint: ocspEndpoint,
		logger:       logger.Global(),
	}
}

// PublishRevocation publishes a certificate revocation
func (p *RevocationPublisher) PublishRevocation(ctx context.Context, cert *models.Certificate) error {
	p.logger.Info("Publishing certificate revocation",
		zap.String("serial", cert.Serial),
		zap.String("subject", cert.SubjectCN),
	)

	// Publish to CRL service (async)
	if err := p.publishToCRL(ctx, cert); err != nil {
		p.logger.Error("Failed to publish to CRL",
			zap.Error(err),
			zap.String("serial", cert.Serial),
		)
		// Don't fail the revocation, continue to OCSP
	}

	// Publish to OCSP responder (async)
	if err := p.publishToOCSP(ctx, cert); err != nil {
		p.logger.Error("Failed to publish to OCSP",
			zap.Error(err),
			zap.String("serial", cert.Serial),
		)
		// Don't fail the revocation
	}

	p.logger.Info("Revocation published successfully",
		zap.String("serial", cert.Serial),
	)

	return nil
}

// publishToCRL sends revocation to CRL distribution service
func (p *RevocationPublisher) publishToCRL(ctx context.Context, cert *models.Certificate) error {
	// TODO: Implement gRPC/HTTP call to CRL service
	// For now, log it
	p.logger.Info("CRL publish (stub)",
		zap.String("endpoint", p.crlEndpoint),
		zap.String("serial", cert.Serial),
	)

	// Example implementation:
	/*
		client := crlpb.NewCRLServiceClient(p.crlConn)
		req := &crlpb.AddRevocationRequest{
			Serial:     cert.Serial,
			RevokedAt:  cert.RevokedAt.Unix(),
			Reason:     "unspecified",
		}
		_, err := client.AddRevocation(ctx, req)
		return err
	*/

	return nil
}

// publishToOCSP sends revocation to OCSP responder
func (p *RevocationPublisher) publishToOCSP(ctx context.Context, cert *models.Certificate) error {
	// TODO: Implement gRPC/HTTP call to OCSP service
	// For now, log it
	p.logger.Info("OCSP publish (stub)",
		zap.String("endpoint", p.ocspEndpoint),
		zap.String("serial", cert.Serial),
	)

	// Example implementation:
	/*
		client := ocspb.NewOCSPServiceClient(p.ocspConn)
		req := &ocspb.UpdateStatusRequest{
			Serial: cert.Serial,
			Status: "revoked",
		}
		_, err := client.UpdateStatus(ctx, req)
		return err
	*/

	return nil
}

// StartWorker starts the revocation publishing worker
func (p *RevocationPublisher) StartWorker(ctx context.Context, revocationChan <-chan *models.Certificate) {
	p.logger.Info("Starting revocation publisher worker",
		zap.String("crl_endpoint", p.crlEndpoint),
		zap.String("ocsp_endpoint", p.ocspEndpoint),
	)

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Revocation publisher worker stopped")
			return
		case cert := <-revocationChan:
			// Process revocation asynchronously
			go func(c *models.Certificate) {
				publishCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				if err := p.PublishRevocation(publishCtx, c); err != nil {
					p.logger.Error("Failed to publish revocation",
						zap.Error(err),
						zap.String("serial", c.Serial),
					)
					// TODO: Implement retry mechanism with exponential backoff
				}
			}(cert)
		}
	}
}

