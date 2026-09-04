CREATE TABLE tenant_signing_keysets (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL CHECK (revision >= 1),
    public_metadata JSONB NOT NULL,
    encrypted_private_material BYTEA NOT NULL,
    wrapping_key_id VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
