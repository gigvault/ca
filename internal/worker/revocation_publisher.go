package worker

import (
	"context"
	"time"

	crlpb "github.com/gigvault/shared/api/proto/crl"
	ocsppb "github.com/gigvault/shared/api/proto/ocsp"
	"github.com/gigvault/shared/pkg/logger"
	"github.com/gigvault/shared/pkg/models"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RevocationPublisher publishes certificate revocations to CRL and OCSP
type RevocationPublisher struct {
	crlEndpoint  string
	ocspEndpoint string
	crlConn      *grpc.ClientConn
	ocspConn     *grpc.ClientConn
	logger       *logger.Logger
}

// NewRevocationPublisher creates a new revocation publisher
func NewRevocationPublisher(crlEndpoint, ocspEndpoint string, crlConn, ocspConn *grpc.ClientConn) *RevocationPublisher {
	return &RevocationPublisher{
		crlEndpoint:  crlEndpoint,
		ocspEndpoint: ocspEndpoint,
		crlConn:      crlConn,
		ocspConn:     ocspConn,
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
	if p.crlConn == nil {
		p.logger.Warn("CRL connection not configured, skipping CRL publish")
		return nil
	}

	client := crlpb.NewCRLServiceClient(p.crlConn)

	var revokedAtTimestamp *timestamppb.Timestamp
	if cert.RevokedAt != nil {
		revokedAtTimestamp = timestamppb.New(*cert.RevokedAt)
	} else {
		revokedAtTimestamp = timestamppb.Now()
	}

	req := &crlpb.AddRevocationRequest{
		SerialNumber: cert.Serial,
		RevokedAt:    revokedAtTimestamp,
		Reason:       "unspecified",
	}

	_, err := client.AddRevocation(ctx, req)
	if err != nil {
		p.logger.Error("Failed to publish to CRL",
			zap.String("serial", cert.Serial),
			zap.Error(err),
		)
		return err
	}

	p.logger.Info("Published to CRL",
		zap.String("serial", cert.Serial),
	)

	return nil
}

// publishToOCSP sends revocation to OCSP responder
func (p *RevocationPublisher) publishToOCSP(ctx context.Context, cert *models.Certificate) error {
	if p.ocspConn == nil {
		p.logger.Warn("OCSP connection not configured, skipping OCSP publish")
		return nil
	}

	client := ocsppb.NewOCSPServiceClient(p.ocspConn)

	var revokedAtTimestamp *timestamppb.Timestamp
	if cert.RevokedAt != nil {
		revokedAtTimestamp = timestamppb.New(*cert.RevokedAt)
	} else {
		revokedAtTimestamp = timestamppb.Now()
	}

	req := &ocsppb.UpdateStatusRequest{
		SerialNumber:     cert.Serial,
		Status:           "revoked",
		RevokedAt:        revokedAtTimestamp,
		RevocationReason: "unspecified",
	}

	_, err := client.UpdateStatus(ctx, req)
	if err != nil {
		p.logger.Error("Failed to publish to OCSP",
			zap.String("serial", cert.Serial),
			zap.Error(err),
		)
		return err
	}

	p.logger.Info("Published to OCSP",
		zap.String("serial", cert.Serial),
	)

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

				// Retry with exponential backoff
				maxRetries := 3
				backoff := time.Second

				for attempt := 0; attempt < maxRetries; attempt++ {
					if err := p.PublishRevocation(publishCtx, c); err != nil {
						if attempt < maxRetries-1 {
							p.logger.Warn("Publish failed, retrying",
								zap.Error(err),
								zap.String("serial", c.Serial),
								zap.Int("attempt", attempt+1),
								zap.Duration("backoff", backoff),
							)
							time.Sleep(backoff)
							backoff *= 2 // Exponential backoff
							continue
						}
						p.logger.Error("Failed to publish revocation after retries",
							zap.Error(err),
							zap.String("serial", c.Serial),
							zap.Int("attempts", maxRetries),
						)
					} else {
						// Success
						break
					}
				}
			}(cert)
		}
	}
}
