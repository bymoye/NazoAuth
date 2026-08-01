CREATE TABLE initial_admin_bootstrap (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_initial_admin_bootstrap_singleton CHECK (singleton),
    CONSTRAINT ck_initial_admin_bootstrap_token_hash_length CHECK (length(token_hash) = 64),
    CONSTRAINT ck_initial_admin_bootstrap_expiry CHECK (expires_at > created_at)
);

COMMENT ON TABLE initial_admin_bootstrap IS
    'Single-use verifier for claiming the first administrator; no plaintext bootstrap token is stored.';
