ALTER TABLE openid4vci_credential_dataset_events
    DROP CONSTRAINT ck_openid4vci_dataset_event_source;

ALTER TABLE openid4vci_credential_dataset_events
    ADD CONSTRAINT ck_openid4vci_dataset_event_source
    CHECK (source IN ('admin-session', 'operator-conformance'));

ALTER TABLE conformance_lease_applicants
    ADD COLUMN deleted_credential_dataset_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE conformance_lease_applicants
    DROP CONSTRAINT ck_conformance_lease_applicants_counts;

ALTER TABLE conformance_lease_applicants
    ADD CONSTRAINT ck_conformance_lease_applicants_counts CHECK (
        deleted_token_count >= 0
        AND deleted_grant_count >= 0
        AND deleted_access_request_count >= 0
        AND deleted_mtls_request_count >= 0
        AND deleted_user_state_count >= 0
        AND deleted_credential_dataset_count >= 0
    );

-- Replace the cleanup function so every lease-owned durable resource has an
-- explicit tombstone count.  The body intentionally keeps the established
-- deletion ordering: dependents first, ownership tombstone second, applicant
-- user last.
ALTER FUNCTION nazo_oauth_cleanup_expired_conformance_leases()
    RENAME TO nazo_oauth_cleanup_expired_conformance_leases_v1;

REVOKE ALL ON FUNCTION nazo_oauth_cleanup_expired_conformance_leases_v1() FROM PUBLIC;

CREATE FUNCTION nazo_oauth_cleanup_expired_conformance_leases()
RETURNS TABLE (
    cleaned_leases INTEGER,
    deleted_clients INTEGER,
    deleted_credential_datasets INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    candidate RECORD;
    applicant_user_id UUID;
    affected INTEGER := 0;
    deleted_tokens INTEGER := 0;
    deleted_grants INTEGER := 0;
    deleted_access_requests INTEGER := 0;
    deleted_mtls_requests INTEGER := 0;
    deleted_user_state INTEGER := 0;
    deleted_datasets_for_applicant INTEGER := 0;
    client_ids UUID[];
BEGIN
    cleaned_leases := 0;
    deleted_clients := 0;
    deleted_credential_datasets := 0;

    FOR candidate IN
        SELECT id, tenant_id
        FROM conformance_leases
        WHERE cleaned_at IS NULL
          AND (expires_at <= CURRENT_TIMESTAMP OR revoked_at IS NOT NULL)
        ORDER BY expires_at, id
        FOR UPDATE SKIP LOCKED
    LOOP
        applicant_user_id := NULL;
        deleted_tokens := 0;
        deleted_grants := 0;
        deleted_access_requests := 0;
        deleted_mtls_requests := 0;
        deleted_user_state := 0;
        deleted_datasets_for_applicant := 0;
        UPDATE conformance_leases
        SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
        WHERE id = candidate.id AND tenant_id = candidate.tenant_id;

        SELECT ARRAY_AGG(id) INTO client_ids
        FROM oauth_clients
        WHERE tenant_id = candidate.tenant_id
          AND conformance_lease_id = candidate.id;

        DELETE FROM oauth_client_mtls_trust_anchor_events AS trust_event
        USING oauth_client_mtls_trust_anchor_requests request
        WHERE trust_event.tenant_id = candidate.tenant_id
          AND trust_event.request_id = request.id
          AND request.tenant_id = candidate.tenant_id
          AND request.client_id = ANY(COALESCE(client_ids, ARRAY[]::uuid[]));
        DELETE FROM oauth_client_mtls_trust_anchor_requests request
        WHERE request.tenant_id = candidate.tenant_id
          AND request.client_id = ANY(COALESCE(client_ids, ARRAY[]::uuid[]));
        GET DIAGNOSTICS affected = ROW_COUNT;
        deleted_mtls_requests := affected;

        SELECT cla.applicant_user_id INTO applicant_user_id
        FROM conformance_lease_applicants cla
        WHERE cla.tenant_id = candidate.tenant_id
          AND cla.lease_id = candidate.id
        FOR UPDATE;

        IF applicant_user_id IS NOT NULL THEN
            DELETE FROM oauth_client_mtls_trust_anchor_events AS trust_event
            USING oauth_client_mtls_trust_anchor_requests request
            WHERE trust_event.tenant_id = candidate.tenant_id
              AND trust_event.request_id = request.id
              AND request.tenant_id = candidate.tenant_id
              AND (request.user_id = applicant_user_id
                   OR request.resolved_by_user_id = applicant_user_id
                   OR request.revoked_by_user_id = applicant_user_id);

            DELETE FROM oauth_client_mtls_trust_anchor_requests request
            WHERE request.tenant_id = candidate.tenant_id
              AND (request.user_id = applicant_user_id
                   OR request.resolved_by_user_id = applicant_user_id
                   OR request.revoked_by_user_id = applicant_user_id);
            GET DIAGNOSTICS affected = ROW_COUNT;
            deleted_mtls_requests := deleted_mtls_requests + affected;
        END IF;

        DELETE FROM backchannel_logout_deliveries delivery
        WHERE delivery.tenant_id = candidate.tenant_id
          AND delivery.client_id = ANY(COALESCE(client_ids, ARRAY[]::uuid[]));

        DELETE FROM oauth_token_issuances issuance
        WHERE issuance.tenant_id = candidate.tenant_id
          AND issuance.client_id = ANY(COALESCE(client_ids, ARRAY[]::uuid[]));

        UPDATE oauth_tokens child
        SET rotated_from_id = NULL
        WHERE child.rotated_from_id IN (
            SELECT id FROM oauth_tokens
            WHERE tenant_id = candidate.tenant_id
              AND client_id = ANY(COALESCE(client_ids, ARRAY[]::uuid[]))
        );

        DELETE FROM oauth_tokens token
        WHERE token.tenant_id = candidate.tenant_id
          AND token.client_id = ANY(COALESCE(client_ids, ARRAY[]::uuid[]));

        DELETE FROM user_client_grants grant_row
        WHERE grant_row.tenant_id = candidate.tenant_id
          AND grant_row.client_id = ANY(COALESCE(client_ids, ARRAY[]::uuid[]));

        DELETE FROM access_token_revocations revocation
        WHERE revocation.tenant_id = candidate.tenant_id
          AND revocation.client_id = ANY(COALESCE(client_ids, ARRAY[]::uuid[]));

        DELETE FROM client_access_requests request
        WHERE request.tenant_id = candidate.tenant_id
          AND request.approved_client_id = ANY(COALESCE(client_ids, ARRAY[]::uuid[]));
        GET DIAGNOSTICS deleted_access_requests = ROW_COUNT;

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

        DELETE FROM conformance_lease_clients
        WHERE tenant_id = candidate.tenant_id
          AND lease_id = candidate.id;

        DELETE FROM oauth_clients
        WHERE tenant_id = candidate.tenant_id
          AND conformance_lease_id = candidate.id;
        GET DIAGNOSTICS affected = ROW_COUNT;
        deleted_clients := deleted_clients + affected;

        IF applicant_user_id IS NOT NULL THEN
            UPDATE oauth_tokens child
            SET rotated_from_id = NULL
            WHERE child.rotated_from_id IN (
                SELECT id FROM oauth_tokens
                WHERE tenant_id = candidate.tenant_id
                  AND user_id = applicant_user_id
            );

            DELETE FROM oauth_tokens token
            WHERE token.tenant_id = candidate.tenant_id
              AND token.user_id = applicant_user_id;
            GET DIAGNOSTICS deleted_tokens = ROW_COUNT;

            DELETE FROM user_client_grants grant_row
            WHERE grant_row.tenant_id = candidate.tenant_id
              AND grant_row.user_id = applicant_user_id;
            GET DIAGNOSTICS deleted_grants = ROW_COUNT;

            DELETE FROM client_access_requests request
            WHERE request.tenant_id = candidate.tenant_id
              AND (request.user_id = applicant_user_id
                   OR request.resolved_by_user_id = applicant_user_id);
            GET DIAGNOSTICS affected = ROW_COUNT;
            deleted_access_requests := deleted_access_requests + affected;

            DELETE FROM openid4vci_offers AS vci_offer
            WHERE vci_offer.tenant_id = candidate.tenant_id
              AND vci_offer.subject_id = applicant_user_id;
            GET DIAGNOSTICS affected = ROW_COUNT;
            deleted_grants := deleted_grants + affected;

            DELETE FROM openid4vci_access_grants grant_row
            WHERE grant_row.tenant_id = candidate.tenant_id
              AND grant_row.subject_id = applicant_user_id;
            GET DIAGNOSTICS affected = ROW_COUNT;
            deleted_grants := deleted_grants + affected;

            SELECT COUNT(*) INTO deleted_datasets_for_applicant
            FROM openid4vci_credential_datasets AS dataset
            WHERE dataset.tenant_id = candidate.tenant_id
              AND dataset.subject_id = applicant_user_id;

            DELETE FROM openid4vci_credential_dataset_events AS dataset_event
            WHERE dataset_event.tenant_id = candidate.tenant_id
              AND (dataset_event.subject_id = applicant_user_id
                   OR dataset_event.actor_user_id = applicant_user_id);
            DELETE FROM openid4vci_credential_datasets AS dataset
            WHERE dataset.tenant_id = candidate.tenant_id
              AND dataset.subject_id = applicant_user_id;
            deleted_credential_datasets :=
                deleted_credential_datasets + deleted_datasets_for_applicant;

            DELETE FROM oauth_client_mtls_trust_anchor_events AS trust_event
            WHERE trust_event.tenant_id = candidate.tenant_id
              AND trust_event.actor_user_id = applicant_user_id;

            DELETE FROM identity_security_events AS security_event
            WHERE security_event.tenant_id = candidate.tenant_id
              AND (security_event.actor_id = applicant_user_id
                   OR security_event.target_user_id = applicant_user_id);

            IF NOT EXISTS (
                SELECT 1
                FROM users
                WHERE tenant_id = candidate.tenant_id
                  AND id = applicant_user_id
                  AND role = 'user'
                  AND admin_level = 0
            ) THEN
                RAISE EXCEPTION
                    'conformance applicant ownership changed before cleanup'
                    USING ERRCODE = '23514';
            END IF;

            UPDATE conformance_lease_applicants
            SET applicant_user_id = NULL,
                cleaned_at = CURRENT_TIMESTAMP,
                deleted_at = CURRENT_TIMESTAMP,
                deleted_token_count = deleted_tokens,
                deleted_grant_count = deleted_grants,
                deleted_access_request_count = deleted_access_requests,
                deleted_mtls_request_count = deleted_mtls_requests,
                deleted_credential_dataset_count = deleted_datasets_for_applicant
            WHERE tenant_id = candidate.tenant_id AND lease_id = candidate.id;

            DELETE FROM users
            WHERE tenant_id = candidate.tenant_id
              AND id = applicant_user_id
              AND role = 'user'
              AND admin_level = 0;
            GET DIAGNOSTICS deleted_user_state = ROW_COUNT;
            IF deleted_user_state <> 1 THEN
                RAISE EXCEPTION
                    'conformance applicant cleanup did not delete exactly one user'
                    USING ERRCODE = '23514';
            END IF;

            UPDATE conformance_lease_applicants
            SET deleted_user_state_count = deleted_user_state
            WHERE tenant_id = candidate.tenant_id AND lease_id = candidate.id;
        END IF;

        UPDATE conformance_leases
        SET cleaned_at = CURRENT_TIMESTAMP,
            public_material = NULL
        WHERE id = candidate.id AND tenant_id = candidate.tenant_id;
        cleaned_leases := cleaned_leases + 1;
    END LOOP;

    RETURN NEXT;
END;
$$;
