CREATE TABLE conformance_leases (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    profile VARCHAR(64) NOT NULL,
    material_sha256 VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    cleaned_at TIMESTAMPTZ,
    CONSTRAINT ck_conformance_lease_profile CHECK (
        profile = btrim(profile) AND char_length(profile) BETWEEN 1 AND 64
    ),
    CONSTRAINT ck_conformance_lease_material_sha256 CHECK (
        material_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_conformance_lease_lifetime CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '24 hours'
    ),
    CONSTRAINT ck_conformance_lease_revocation CHECK (
        revoked_at IS NULL OR revoked_at >= created_at
    ),
    CONSTRAINT ck_conformance_lease_cleanup CHECK (
        cleaned_at IS NULL OR revoked_at IS NOT NULL
    ),
    CONSTRAINT uq_conformance_lease_tenant_id UNIQUE (tenant_id, id)
);

CREATE INDEX ix_conformance_leases_pending_cleanup
    ON conformance_leases (expires_at, id)
    WHERE cleaned_at IS NULL;

ALTER TABLE oauth_clients
    ADD COLUMN conformance_lease_id UUID,
    ADD CONSTRAINT fk_oauth_clients_conformance_lease
        FOREIGN KEY (tenant_id, conformance_lease_id)
        REFERENCES conformance_leases(tenant_id, id);

CREATE INDEX ix_oauth_clients_conformance_lease
    ON oauth_clients (tenant_id, conformance_lease_id)
    WHERE conformance_lease_id IS NOT NULL;

CREATE OR REPLACE FUNCTION nazo_oauth_conformance_lease_is_active(
    candidate_tenant_id UUID,
    candidate_lease_id UUID
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT candidate_lease_id IS NULL OR EXISTS (
        SELECT 1
        FROM conformance_leases lease
        WHERE lease.tenant_id = candidate_tenant_id
          AND lease.id = candidate_lease_id
          AND lease.expires_at > CURRENT_TIMESTAMP
          AND lease.revoked_at IS NULL
          AND lease.cleaned_at IS NULL
    )
$$;

CREATE OR REPLACE FUNCTION nazo_oauth_validate_conformance_lease_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    lease_expires_at TIMESTAMPTZ;
    lease_revoked_at TIMESTAMPTZ;
    lease_cleaned_at TIMESTAMPTZ;
BEGIN
    IF NEW.conformance_lease_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT expires_at, revoked_at, cleaned_at
    INTO lease_expires_at, lease_revoked_at, lease_cleaned_at
    FROM conformance_leases
    WHERE id = NEW.conformance_lease_id
      AND tenant_id = NEW.tenant_id
    FOR KEY SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'conformance lease does not exist in the client tenant'
            USING ERRCODE = '23514';
    END IF;

    IF (TG_OP = 'INSERT' OR NEW.is_active)
       AND (
           lease_expires_at <= CURRENT_TIMESTAMP
           OR lease_revoked_at IS NOT NULL
           OR lease_cleaned_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'conformance lease is not active'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_oauth_clients_conformance_lease
BEFORE INSERT OR UPDATE ON oauth_clients
FOR EACH ROW
EXECUTE FUNCTION nazo_oauth_validate_conformance_lease_binding();

CREATE OR REPLACE FUNCTION nazo_oauth_cleanup_expired_conformance_leases()
RETURNS TABLE (
    cleaned_leases INTEGER,
    deleted_clients INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    candidate RECORD;
    affected INTEGER := 0;
BEGIN
    cleaned_leases := 0;
    deleted_clients := 0;

    FOR candidate IN
        SELECT id, tenant_id
        FROM conformance_leases
        WHERE cleaned_at IS NULL
          AND (expires_at <= CURRENT_TIMESTAMP OR revoked_at IS NOT NULL)
        ORDER BY expires_at, id
        FOR UPDATE SKIP LOCKED
    LOOP
        UPDATE conformance_leases
        SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
        WHERE id = candidate.id AND tenant_id = candidate.tenant_id;

        UPDATE oauth_clients
        SET is_active = FALSE,
            client_secret_hash = NULL,
            registration_access_token_blake3 = NULL,
            jwks = NULL,
            jwks_uri = NULL,
            tls_client_auth_subject_dn = NULL,
            tls_client_auth_cert_sha256 = NULL,
            tls_client_auth_san_dns = '[]'::jsonb,
            tls_client_auth_san_uri = '[]'::jsonb,
            tls_client_auth_san_ip = '[]'::jsonb,
            tls_client_auth_san_email = '[]'::jsonb,
            updated_at = CURRENT_TIMESTAMP
        WHERE tenant_id = candidate.tenant_id
          AND conformance_lease_id = candidate.id;

        DELETE FROM oauth_client_mtls_trust_anchor_events event
        USING oauth_client_mtls_trust_anchor_requests request,
              oauth_clients client
        WHERE event.tenant_id = candidate.tenant_id
          AND event.request_id = request.id
          AND request.tenant_id = candidate.tenant_id
          AND request.client_id = client.id
          AND client.tenant_id = candidate.tenant_id
          AND client.conformance_lease_id = candidate.id;

        DELETE FROM oauth_client_mtls_trust_anchor_requests request
        USING oauth_clients client
        WHERE request.tenant_id = candidate.tenant_id
          AND request.client_id = client.id
          AND client.tenant_id = candidate.tenant_id
          AND client.conformance_lease_id = candidate.id;

        DELETE FROM backchannel_logout_deliveries delivery
        USING oauth_clients client
        WHERE delivery.tenant_id = candidate.tenant_id
          AND delivery.client_id = client.id
          AND client.tenant_id = candidate.tenant_id
          AND client.conformance_lease_id = candidate.id;

        DELETE FROM oauth_tokens token
        USING oauth_clients client
        WHERE token.tenant_id = candidate.tenant_id
          AND token.client_id = client.id
          AND client.tenant_id = candidate.tenant_id
          AND client.conformance_lease_id = candidate.id;

        DELETE FROM user_client_grants grant_row
        USING oauth_clients client
        WHERE grant_row.tenant_id = candidate.tenant_id
          AND grant_row.client_id = client.id
          AND client.tenant_id = candidate.tenant_id
          AND client.conformance_lease_id = candidate.id;

        DELETE FROM access_token_revocations revocation
        USING oauth_clients client
        WHERE revocation.tenant_id = candidate.tenant_id
          AND revocation.client_id = client.id
          AND client.tenant_id = candidate.tenant_id
          AND client.conformance_lease_id = candidate.id;

        DELETE FROM client_access_requests request
        USING oauth_clients client
        WHERE request.tenant_id = candidate.tenant_id
          AND request.approved_client_id = client.id
          AND client.tenant_id = candidate.tenant_id
          AND client.conformance_lease_id = candidate.id;

        DELETE FROM oauth_clients
        WHERE tenant_id = candidate.tenant_id
          AND conformance_lease_id = candidate.id;
        GET DIAGNOSTICS affected = ROW_COUNT;
        deleted_clients := deleted_clients + affected;

        UPDATE conformance_leases
        SET cleaned_at = CURRENT_TIMESTAMP
        WHERE id = candidate.id AND tenant_id = candidate.tenant_id;
        cleaned_leases := cleaned_leases + 1;
    END LOOP;

    RETURN NEXT;
END;
$$;

COMMENT ON TABLE conformance_leases IS
    'Audited, time-bounded isolation boundary for temporary conformance clients; never stores private key material or client secrets.';
COMMENT ON COLUMN oauth_clients.conformance_lease_id IS
    'Optional temporary conformance ownership. Expired lease clients are unusable before asynchronous physical cleanup.';
