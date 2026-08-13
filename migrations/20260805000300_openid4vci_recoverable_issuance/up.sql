ALTER TABLE openid4vci_nonces
    ADD COLUMN claim_id VARCHAR(128),
    ADD COLUMN claim_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_openid4vci_nonce_claim CHECK (
        (claim_id IS NULL AND claim_expires_at IS NULL)
        OR (claim_id IS NOT NULL AND claim_expires_at IS NOT NULL
            AND char_length(btrim(claim_id)) BETWEEN 1 AND 128)
    );

ALTER TABLE openid4vci_deferred_transactions
    ADD COLUMN claim_id VARCHAR(128),
    ADD COLUMN claim_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_openid4vci_deferred_claim CHECK (
        (claim_id IS NULL AND claim_expires_at IS NULL)
        OR (claim_id IS NOT NULL AND claim_expires_at IS NOT NULL
            AND char_length(btrim(claim_id)) BETWEEN 1 AND 128)
    );

CREATE INDEX ix_openid4vci_nonce_claim_expiry
    ON openid4vci_nonces (claim_expires_at)
    WHERE claim_id IS NOT NULL;

CREATE INDEX ix_openid4vci_deferred_claim_expiry
    ON openid4vci_deferred_transactions (claim_expires_at)
    WHERE claim_id IS NOT NULL;

COMMENT ON COLUMN openid4vci_nonces.claim_id IS
    'Ephemeral issuance lease owner; consumed_at remains the permanent single-use marker.';
COMMENT ON COLUMN openid4vci_deferred_transactions.claim_id IS
    'Ephemeral deferred-issuance lease owner; consumed_at is set only after signing succeeds.';

CREATE TABLE openid4vci_issuance_responses (
    issuance_id UUID PRIMARY KEY,
    token_id UUID NOT NULL REFERENCES openid4vci_access_grants(token_id) ON DELETE CASCADE,
    request_digest VARCHAR(64) NOT NULL,
    body_ciphertext BYTEA NOT NULL,
    encoding VARCHAR(16) NOT NULL,
    status SMALLINT NOT NULL,
    dpop_nonce VARCHAR(256),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_openid4vci_issuance_response_request UNIQUE (token_id, request_digest),
    CONSTRAINT ck_openid4vci_issuance_response_digest
        CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_openid4vci_issuance_response_encoding
        CHECK (encoding IN ('json', 'jwt')),
    CONSTRAINT ck_openid4vci_issuance_response_status
        CHECK (status IN (200, 202)),
    CONSTRAINT ck_openid4vci_issuance_response_expiry CHECK (expires_at > created_at)
);

CREATE INDEX ix_openid4vci_issuance_response_expiry
    ON openid4vci_issuance_responses (expires_at);

COMMENT ON COLUMN openid4vci_issuance_responses.body_ciphertext IS
    'AEAD-encrypted exact credential HTTP response body; plaintext is never persisted.';
