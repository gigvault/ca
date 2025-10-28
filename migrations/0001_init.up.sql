-- Certificates table
CREATE TABLE IF NOT EXISTS certificates (
    id SERIAL PRIMARY KEY,
    serial VARCHAR(64) UNIQUE NOT NULL,
    subject_cn TEXT NOT NULL,
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,
    pem TEXT NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_certificates_serial ON certificates(serial);
CREATE INDEX idx_certificates_subject_cn ON certificates(subject_cn);
CREATE INDEX idx_certificates_revoked ON certificates(revoked);

-- CSRs table
CREATE TABLE IF NOT EXISTS csrs (
    id SERIAL PRIMARY KEY,
    subject_cn TEXT NOT NULL,
    subject_org TEXT,
    subject_ou TEXT,
    pem TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    submitted_by VARCHAR(255) NOT NULL,
    approved_by VARCHAR(255),
    certificate_id INTEGER REFERENCES certificates(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_csrs_status ON csrs(status);
CREATE INDEX idx_csrs_submitted_by ON csrs(submitted_by);

