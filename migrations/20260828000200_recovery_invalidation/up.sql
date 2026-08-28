CREATE TABLE recovery_invalidations (
    operation_id UUID PRIMARY KEY,
    request_hash VARCHAR(64) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    state_epoch UUID NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    revoked_refresh_tokens BIGINT NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_recovery_invalidations_tenant_epoch UNIQUE (tenant_id, state_epoch),
    CONSTRAINT ck_recovery_invalidations_request_hash CHECK (
        request_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_recovery_invalidations_not_before CHECK (not_before > completed_at),
    CONSTRAINT ck_recovery_invalidations_revoked_refresh_tokens CHECK (
        revoked_refresh_tokens >= 0
    )
);

CREATE FUNCTION nazo_recovery_invalidations_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'recovery invalidations are append-only' USING ERRCODE = '55006';
END;
$$;

CREATE TRIGGER trg_recovery_invalidations_append_only
BEFORE UPDATE OR DELETE ON recovery_invalidations
FOR EACH ROW
EXECUTE FUNCTION nazo_recovery_invalidations_append_only();
