# GigVault CA - Intermediate Certificate Authority

The online Certificate Authority service for signing and issuing certificates.

## Features

- Certificate signing and issuance
- CSR (Certificate Signing Request) management
- Certificate revocation
- RESTful API for certificate operations
- PostgreSQL-backed certificate storage
- mTLS support for secure inter-service communication

## API Endpoints

### Health Checks
- `GET /health` - Health check
- `GET /ready` - Readiness check

### Certificate Operations
- `GET /api/v1/certificates` - List certificates
- `GET /api/v1/certificates/{serial}` - Get certificate by serial
- `POST /api/v1/certificates/sign` - Sign a certificate
- `POST /api/v1/certificates/{serial}/revoke` - Revoke a certificate

### CSR Operations
- `POST /api/v1/csr` - Submit a new CSR
- `GET /api/v1/csr/{id}` - Get CSR by ID

## Configuration

See `config/example.yaml` for configuration options.

Environment variables:
- `CONFIG_PATH` - Path to config file (default: `config/config.yaml`)
- `DB_HOST` - Database host
- `DB_PASSWORD` - Database password

## Development

```bash
# Build
make build

# Run tests
make test

# Run locally
make run-local

# Database migrations
make migrate
```

## Docker

```bash
# Build Docker image
make docker

# Run in Docker
docker run -p 8080:8080 gigvault/ca:local
```

## Database Schema

See `migrations/` for database schema definitions.

## License

Copyright © 2025 GigVault

