CREATE TABLE oauth_token_issuances (
    issuance_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    grant_key_blake3 VARCHAR(64) NOT NULL,
    request_digest VARCHAR(64) NOT NULL,
    phase VARCHAR(16) NOT NULL,
    access_token_jti VARCHAR(128),
    access_token_expires_at TIMESTAMPTZ,
    response_ciphertext BYTEA,
    response_digest VARCHAR(64),
    response_envelope_version VARCHAR(16),
    response_key_id VARCHAR(128),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oauth_token_issuances_phase_check
        CHECK (phase IN ('prepared', 'signed', 'persisted', 'delivered')),
    CONSTRAINT oauth_token_issuances_response_pair_check
        CHECK ((response_ciphertext IS NULL) = (response_digest IS NULL)
            AND ((response_ciphertext IS NULL) = (response_envelope_version IS NULL))
            AND ((response_ciphertext IS NULL) = (response_key_id IS NULL))),
    CONSTRAINT oauth_token_issuances_phase_response_check
        CHECK ((phase = 'prepared') = (response_ciphertext IS NULL)),
    CONSTRAINT oauth_token_issuances_signed_fields_check
        CHECK (phase = 'prepared' OR (access_token_jti IS NOT NULL AND access_token_expires_at IS NOT NULL)),
    CONSTRAINT oauth_token_issuances_grant_key_check
        CHECK (length(grant_key_blake3) = 64),
    CONSTRAINT oauth_token_issuances_request_digest_check
        CHECK (length(request_digest) = 64)
);

CREATE UNIQUE INDEX oauth_token_issuances_grant_key_idx
    ON oauth_token_issuances (tenant_id, client_id, grant_key_blake3);

CREATE INDEX oauth_token_issuances_expiry_idx
    ON oauth_token_issuances (expires_at);

COMMENT ON TABLE oauth_token_issuances IS
    'Recoverable OAuth/OIDC token issuance saga; response ciphertext is encrypted by the configured response key ring, with envelope format and key id stored independently.';
