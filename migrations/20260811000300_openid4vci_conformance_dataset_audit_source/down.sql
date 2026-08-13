ALTER TABLE openid4vci_credential_dataset_events
    DROP CONSTRAINT ck_openid4vci_dataset_event_source;

ALTER TABLE openid4vci_credential_dataset_events
    ADD CONSTRAINT ck_openid4vci_dataset_event_source
    CHECK (source = 'admin-session');

DROP FUNCTION nazo_oauth_cleanup_expired_conformance_leases();

ALTER FUNCTION nazo_oauth_cleanup_expired_conformance_leases_v1()
    RENAME TO nazo_oauth_cleanup_expired_conformance_leases;

GRANT EXECUTE ON FUNCTION nazo_oauth_cleanup_expired_conformance_leases() TO PUBLIC;

ALTER TABLE conformance_lease_applicants
    DROP CONSTRAINT ck_conformance_lease_applicants_counts;

ALTER TABLE conformance_lease_applicants
    DROP COLUMN deleted_credential_dataset_count;

ALTER TABLE conformance_lease_applicants
    ADD CONSTRAINT ck_conformance_lease_applicants_counts CHECK (
        deleted_token_count >= 0
        AND deleted_grant_count >= 0
        AND deleted_access_request_count >= 0
        AND deleted_mtls_request_count >= 0
        AND deleted_user_state_count >= 0
    );
