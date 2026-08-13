DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM conformance_lease_applicants
    ) OR EXISTS (
        SELECT 1
        FROM conformance_lease_clients
    ) THEN
        RAISE EXCEPTION
            'cannot roll back conformance onboarding while lease-owned rows remain';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM oauth_client_mtls_trust_anchor_requests
        WHERE source = 'operator-conformance'
    ) THEN
        RAISE EXCEPTION 'cannot roll back conformance onboarding while operator trust rows remain';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS trg_mtls_trust_event_actor ON oauth_client_mtls_trust_anchor_events;
DROP FUNCTION IF EXISTS nazo_oauth_validate_mtls_trust_event_actor();
ALTER TABLE oauth_client_mtls_trust_anchor_events
    ALTER COLUMN actor_user_id SET NOT NULL;
ALTER TABLE oauth_client_mtls_trust_anchor_requests
    DROP CONSTRAINT IF EXISTS ck_mtls_trust_anchor_state,
    DROP CONSTRAINT IF EXISTS ck_mtls_trust_anchor_source,
    DROP COLUMN IF EXISTS source,
    ADD CONSTRAINT ck_mtls_trust_anchor_state CHECK (
        (status = 0 AND resolved_by_user_id IS NULL AND resolved_at IS NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status IN (1, 2) AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 3 AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL)
    );

DROP FUNCTION IF EXISTS nazo_oauth_cleanup_expired_conformance_leases();
DROP INDEX IF EXISTS ix_conformance_lease_applicants_user;
DROP TABLE IF EXISTS conformance_lease_applicants;
DROP TABLE IF EXISTS conformance_lease_clients;
DROP INDEX IF EXISTS uq_conformance_lease_tenant_task_jti;
ALTER TABLE conformance_leases
    DROP CONSTRAINT IF EXISTS ck_conformance_lease_task_jti,
    DROP CONSTRAINT IF EXISTS ck_conformance_lease_bundle_schema,
    DROP CONSTRAINT IF EXISTS ck_conformance_lease_bundle_sha256,
    DROP CONSTRAINT IF EXISTS ck_conformance_lease_client_count,
    DROP COLUMN IF EXISTS task_jti,
    DROP COLUMN IF EXISTS bundle_schema,
    DROP COLUMN IF EXISTS bundle_sha256,
    DROP COLUMN IF EXISTS client_count;

CREATE FUNCTION nazo_oauth_cleanup_expired_conformance_leases()
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

        DELETE FROM oauth_client_mtls_trust_anchor_events AS trust_event
        USING oauth_client_mtls_trust_anchor_requests request,
              oauth_clients client
        WHERE trust_event.tenant_id = candidate.tenant_id
          AND trust_event.request_id = request.id
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
