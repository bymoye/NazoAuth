-- A conformance run is an operator capability, not a collection of ordinary
-- users and clients.  Bind the capability to the signed bundle and to the
-- operator task identity so a retry cannot silently create a different
-- payload under the same task.
ALTER TABLE conformance_leases
    ADD COLUMN task_jti VARCHAR(255),
    ADD COLUMN bundle_schema INTEGER,
    ADD COLUMN bundle_sha256 VARCHAR(64),
    ADD COLUMN client_count INTEGER;

-- Older leases pre-date the onboarding transaction.  Preserve their
-- historical rows with deterministic legacy keys; new callers are required
-- to supply the full binding fields through the repository API.
UPDATE conformance_leases
SET task_jti = 'legacy:' || id::text,
    bundle_schema = 1,
    bundle_sha256 = material_sha256,
    client_count = (
        SELECT COUNT(*)::integer
        FROM oauth_clients
        WHERE oauth_clients.tenant_id = conformance_leases.tenant_id
          AND oauth_clients.conformance_lease_id = conformance_leases.id
    )
WHERE task_jti IS NULL;

ALTER TABLE conformance_leases
    ALTER COLUMN task_jti SET NOT NULL,
    ALTER COLUMN bundle_schema SET NOT NULL,
    ALTER COLUMN bundle_sha256 SET NOT NULL,
    ALTER COLUMN client_count SET NOT NULL,
    ADD CONSTRAINT ck_conformance_lease_task_jti CHECK (
        octet_length(task_jti) BETWEEN 1 AND 255
        AND task_jti = btrim(task_jti)
        AND task_jti !~ '[[:cntrl:]]'
    ),
    ADD CONSTRAINT ck_conformance_lease_bundle_schema CHECK (
        bundle_schema BETWEEN 1 AND 32
    ),
    ADD CONSTRAINT ck_conformance_lease_bundle_sha256 CHECK (
        bundle_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT ck_conformance_lease_client_count CHECK (
        client_count >= 0
    );

CREATE UNIQUE INDEX uq_conformance_lease_tenant_task_jti
    ON conformance_leases (tenant_id, task_jti);

-- Explicit ownership is kept separately from the lease so cleanup can retain
-- a durable tombstone and deletion counters without retaining a live user
-- foreign key.  applicant_user_id is nulled by the cleanup transaction only
-- after every dependent row has been removed.
CREATE TABLE conformance_lease_applicants (
    tenant_id UUID NOT NULL,
    lease_id UUID NOT NULL,
    applicant_user_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cleaned_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    deleted_token_count INTEGER NOT NULL DEFAULT 0,
    deleted_grant_count INTEGER NOT NULL DEFAULT 0,
    deleted_access_request_count INTEGER NOT NULL DEFAULT 0,
    deleted_mtls_request_count INTEGER NOT NULL DEFAULT 0,
    deleted_user_state_count INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT pk_conformance_lease_applicants PRIMARY KEY (tenant_id, lease_id),
    CONSTRAINT fk_conformance_lease_applicants_lease
        FOREIGN KEY (tenant_id, lease_id)
        REFERENCES conformance_leases(tenant_id, id),
    CONSTRAINT fk_conformance_lease_applicants_user
        FOREIGN KEY (applicant_user_id, tenant_id)
        REFERENCES users(id, tenant_id),
    CONSTRAINT uq_conformance_lease_applicants_user
        UNIQUE (tenant_id, applicant_user_id),
    CONSTRAINT ck_conformance_lease_applicants_tombstone CHECK (
        (applicant_user_id IS NOT NULL AND deleted_at IS NULL)
        OR (applicant_user_id IS NULL AND deleted_at IS NOT NULL)
    ),
    CONSTRAINT ck_conformance_lease_applicants_counts CHECK (
        deleted_token_count >= 0
        AND deleted_grant_count >= 0
        AND deleted_access_request_count >= 0
        AND deleted_mtls_request_count >= 0
        AND deleted_user_state_count >= 0
    )
);

CREATE INDEX ix_conformance_lease_applicants_user
    ON conformance_lease_applicants (tenant_id, applicant_user_id)
    WHERE applicant_user_id IS NOT NULL;

-- Persist the bundle's logical client identity separately from the generated
-- database UUID.  Replay must return the exact logical-to-actual mapping;
-- created_at/UUID ordering is not a semantic contract.
CREATE TABLE conformance_lease_clients (
    tenant_id UUID NOT NULL,
    lease_id UUID NOT NULL,
    logical_client_id VARCHAR(128) NOT NULL,
    client_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_conformance_lease_clients
        PRIMARY KEY (tenant_id, lease_id, logical_client_id),
    CONSTRAINT uq_conformance_lease_clients_actual
        UNIQUE (tenant_id, client_id),
    CONSTRAINT fk_conformance_lease_clients_lease
        FOREIGN KEY (tenant_id, lease_id)
        REFERENCES conformance_leases(tenant_id, id),
    CONSTRAINT fk_conformance_lease_clients_client
        FOREIGN KEY (client_id, tenant_id)
        REFERENCES oauth_clients(id, tenant_id),
    CONSTRAINT ck_conformance_lease_clients_logical_id CHECK (
        octet_length(logical_client_id) BETWEEN 1 AND 128
        AND logical_client_id = btrim(logical_client_id)
        AND logical_client_id !~ '[[:cntrl:]]'
    )
);

COMMENT ON TABLE conformance_lease_clients IS
    'Stable mapping from a signed conformance bundle logical client identifier to its lease-owned database client UUID.';

COMMENT ON COLUMN conformance_leases.task_jti IS
    'Operator task identity used as the tenant-scoped idempotency key for atomic conformance onboarding.';
COMMENT ON COLUMN conformance_leases.bundle_sha256 IS
    'SHA-256 digest of the complete, canonical conformance onboarding bundle; payload changes require a new task_jti.';
COMMENT ON TABLE conformance_lease_applicants IS
    'Explicit lease-owned applicant account and cleanup tombstone. The account is always ordinary (role=user, admin_level=0).';

-- Operator conformance is a separate, signed server-side capability.  It must
-- not manufacture a browser access-request approval or impersonate an admin
-- actor merely to satisfy the normal HTTP workflow.  Keep the provenance
-- explicit on the trust request and allow its event actor to be absent only
-- for this source.
ALTER TABLE oauth_client_mtls_trust_anchor_requests
    ADD COLUMN source VARCHAR(32) NOT NULL DEFAULT 'admin-session',
    DROP CONSTRAINT IF EXISTS ck_mtls_trust_anchor_state,
    ADD CONSTRAINT ck_mtls_trust_anchor_source CHECK (
        source IN ('admin-session', 'operator-conformance')
    ),
    ADD CONSTRAINT ck_mtls_trust_anchor_state CHECK (
        (status = 0 AND resolved_by_user_id IS NULL AND resolved_at IS NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status IN (1, 2) AND source = 'admin-session'
            AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 1 AND source = 'operator-conformance'
            AND resolved_by_user_id IS NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 3 AND source = 'admin-session'
            AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL)
        OR (status = 3 AND source = 'operator-conformance'
            AND resolved_by_user_id IS NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL)
    );

ALTER TABLE oauth_client_mtls_trust_anchor_events
    ALTER COLUMN actor_user_id DROP NOT NULL;

CREATE OR REPLACE FUNCTION nazo_oauth_validate_mtls_trust_event_actor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    request_source VARCHAR(32);
BEGIN
    SELECT source INTO request_source
    FROM oauth_client_mtls_trust_anchor_requests
    WHERE tenant_id = NEW.tenant_id AND id = NEW.request_id;
    IF request_source IS NULL THEN
        RAISE EXCEPTION 'mTLS trust event request does not exist'
            USING ERRCODE = '23503';
    END IF;
    IF request_source = 'admin-session' AND NEW.actor_user_id IS NULL THEN
        RAISE EXCEPTION 'admin-session trust events require an actor'
            USING ERRCODE = '23514';
    END IF;
    IF request_source = 'operator-conformance'
       AND (
           (NEW.action IN (0, 1) AND NEW.actor_user_id IS NOT NULL)
           OR (NEW.action = 3 AND NEW.actor_user_id IS NULL)
           OR NEW.action = 2
       ) THEN
        RAISE EXCEPTION 'operator-conformance trust event actor/action is inconsistent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_mtls_trust_event_actor
BEFORE INSERT OR UPDATE ON oauth_client_mtls_trust_anchor_events
FOR EACH ROW
EXECUTE FUNCTION nazo_oauth_validate_mtls_trust_event_actor();

COMMENT ON COLUMN oauth_client_mtls_trust_anchor_requests.source IS
    'admin-session for ordinary approval; operator-conformance for the signed narrow onboarding capability.';

DROP FUNCTION IF EXISTS nazo_oauth_cleanup_expired_conformance_leases();

CREATE FUNCTION nazo_oauth_cleanup_expired_conformance_leases()
RETURNS TABLE (
    cleaned_leases INTEGER,
    deleted_clients INTEGER
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
    client_ids UUID[];
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
        applicant_user_id := NULL;
        deleted_tokens := 0;
        deleted_grants := 0;
        deleted_access_requests := 0;
        deleted_mtls_requests := 0;
        deleted_user_state := 0;
        UPDATE conformance_leases
        SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
        WHERE id = candidate.id AND tenant_id = candidate.tenant_id;

        SELECT ARRAY_AGG(id) INTO client_ids
        FROM oauth_clients
        WHERE tenant_id = candidate.tenant_id
          AND conformance_lease_id = candidate.id;

        -- Revoke and remove trust state before deleting clients.  Trust event
        -- rows carry non-cascading actor/request FKs.
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

        -- Remove any remaining trust rows authored by the lease applicant;
        -- this also covers a failed/interrupted onboarding before a client was
        -- bound to the lease.
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

        -- The mapping FK deliberately prevents deleting a client before its
        -- lease ownership record is removed.
        DELETE FROM conformance_lease_clients
        WHERE tenant_id = candidate.tenant_id
          AND lease_id = candidate.id;

        DELETE FROM oauth_clients
        WHERE tenant_id = candidate.tenant_id
          AND conformance_lease_id = candidate.id;
        GET DIAGNOSTICS affected = ROW_COUNT;
        deleted_clients := deleted_clients + affected;

        IF applicant_user_id IS NOT NULL THEN
            -- Break refresh-token self-links before deleting the applicant's
            -- own tokens; tokens belonging to another principal are retained.
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

            -- Remove issuer-side OpenID4VC grants/offers explicitly before
            -- deleting the applicant. Their deferred transactions and
            -- notifications are dependent rows with ON DELETE CASCADE.
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

            DELETE FROM openid4vci_credential_dataset_events AS dataset_event
            WHERE dataset_event.tenant_id = candidate.tenant_id
              AND (dataset_event.subject_id = applicant_user_id
                   OR dataset_event.actor_user_id = applicant_user_id);
            DELETE FROM openid4vci_credential_datasets AS dataset
            WHERE dataset.tenant_id = candidate.tenant_id
              AND dataset.subject_id = applicant_user_id;

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

            -- Preserve a tombstone before removing the user row so the
            -- ownership foreign key never blocks deletion.
            UPDATE conformance_lease_applicants
            SET applicant_user_id = NULL,
                cleaned_at = CURRENT_TIMESTAMP,
                deleted_at = CURRENT_TIMESTAMP,
                deleted_token_count = deleted_tokens,
                deleted_grant_count = deleted_grants,
                deleted_access_request_count = deleted_access_requests,
                deleted_mtls_request_count = deleted_mtls_requests
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
