-- The legacy in-process OIDF conformance lease is retired.  Ordinary
-- tenant-resource management is the only machine-managed lifecycle and must
-- remain intact.  Refuse to erase any live or partially cleaned legacy state.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM conformance_leases
        WHERE cleaned_at IS NULL
           OR revoked_at IS NULL
    )
    OR EXISTS (SELECT 1 FROM oauth_clients WHERE conformance_lease_id IS NOT NULL)
    OR EXISTS (SELECT 1 FROM openid4vp_transactions WHERE conformance_lease_id IS NOT NULL)
    OR EXISTS (SELECT 1 FROM conformance_lease_applicants WHERE applicant_user_id IS NOT NULL)
    OR EXISTS (SELECT 1 FROM conformance_lease_clients)
    OR EXISTS (
        SELECT 1 FROM oauth_client_mtls_trust_anchor_requests
        WHERE source = 'operator-conformance'
    )
    OR EXISTS (
        SELECT 1 FROM openid4vci_credential_datasets
        WHERE source = 'operator-conformance'
    )
    OR EXISTS (
        SELECT 1 FROM openid4vci_credential_dataset_events
        WHERE source = 'operator-conformance'
    ) THEN
        RAISE EXCEPTION
            'cannot remove legacy conformance schema while legacy state remains'
            USING ERRCODE = '55006';
    END IF;
END;
$$;

-- The ordinary OpenID4VC trust-policy owner replaces the mutually-exclusive
-- lease owner.  Keep the policy constraint and all ordinary policy objects.
ALTER TABLE openid4vp_transactions
    DROP CONSTRAINT IF EXISTS ck_openid4vp_transactions_trust_owner;

DROP TRIGGER IF EXISTS trg_openid4vp_transactions_conformance_lease
    ON openid4vp_transactions;
DROP TRIGGER IF EXISTS trg_conformance_leases_delete_presentations
    ON conformance_leases;
DROP FUNCTION IF EXISTS nazo_oauth_validate_conformance_presentation_lease_binding();
DROP FUNCTION IF EXISTS nazo_oauth_delete_revoked_conformance_presentations();
DROP INDEX IF EXISTS ix_openid4vp_transactions_conformance_lease;
ALTER TABLE openid4vp_transactions
    DROP CONSTRAINT IF EXISTS fk_openid4vp_transactions_conformance_lease,
    DROP COLUMN IF EXISTS conformance_lease_id;

DROP TRIGGER IF EXISTS trg_oauth_clients_conformance_lease ON oauth_clients;
DROP FUNCTION IF EXISTS nazo_oauth_validate_conformance_lease_binding();
DROP INDEX IF EXISTS ix_oauth_clients_conformance_lease;
ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_conformance_lease,
    DROP COLUMN IF EXISTS conformance_lease_id;

DROP FUNCTION IF EXISTS nazo_oauth_cleanup_expired_conformance_leases();
DROP FUNCTION IF EXISTS nazo_oauth_cleanup_expired_conformance_leases_v1();
DROP FUNCTION IF EXISTS nazo_oauth_conformance_lease_is_active(UUID, UUID);

DROP TABLE IF EXISTS conformance_lease_applicants;
DROP TABLE IF EXISTS conformance_lease_clients;
DROP TABLE IF EXISTS conformance_leases;

-- Remove the retired provenance while preserving both ordinary admin and
-- operator-managed state transitions.
ALTER TABLE oauth_client_mtls_trust_anchor_requests
    DROP CONSTRAINT IF EXISTS ck_mtls_trust_anchor_source,
    DROP CONSTRAINT IF EXISTS ck_mtls_trust_anchor_state;

ALTER TABLE oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT ck_mtls_trust_anchor_source CHECK (
        source IN ('admin-session', 'operator-managed')
    ),
    ADD CONSTRAINT ck_mtls_trust_anchor_state CHECK (
        (status = 0 AND source = 'admin-session'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NULL AND resolved_at IS NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 0 AND source = 'operator-managed'
            AND user_id IS NULL AND resolved_by_user_id IS NULL AND resolved_at IS NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status IN (1, 2) AND source = 'admin-session'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status IN (1, 2) AND source = 'operator-managed'
            AND user_id IS NULL AND resolved_by_user_id IS NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 3 AND source = 'admin-session'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL)
        OR (status = 3 AND source = 'operator-managed'
            AND user_id IS NULL AND resolved_by_user_id IS NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NOT NULL)
    );

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
        RAISE EXCEPTION 'mTLS trust event request does not exist' USING ERRCODE = '23503';
    END IF;
    IF request_source = 'admin-session' AND NEW.actor_user_id IS NULL THEN
        RAISE EXCEPTION 'admin-session trust events require an actor' USING ERRCODE = '23514';
    END IF;
    IF request_source = 'operator-managed' AND NEW.actor_user_id IS NOT NULL THEN
        RAISE EXCEPTION 'operator-managed trust events cannot carry a user actor' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE openid4vci_credential_dataset_events
    DROP CONSTRAINT IF EXISTS ck_openid4vci_dataset_event_source;
ALTER TABLE openid4vci_credential_dataset_events
    ADD CONSTRAINT ck_openid4vci_dataset_event_source
    CHECK (source IN ('admin-session', 'operator-managed'));

CREATE OR REPLACE FUNCTION nazo_oauth_validate_openid4vci_dataset_event_actor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.source = 'admin-session' AND NEW.actor_user_id IS NULL THEN
        RAISE EXCEPTION 'admin-session dataset events require a user actor' USING ERRCODE = '23514';
    END IF;
    IF NEW.source = 'operator-managed' AND NEW.actor_user_id IS NOT NULL THEN
        RAISE EXCEPTION 'operator-managed dataset events cannot carry a user actor' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
