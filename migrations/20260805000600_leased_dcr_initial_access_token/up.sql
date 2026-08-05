ALTER TABLE conformance_leases
    ADD COLUMN dynamic_registration_initial_access_token_sha256 VARCHAR(64),
    ADD COLUMN ciba_automated_decision_token_sha256 VARCHAR(64),
    ADD CONSTRAINT ck_conformance_lease_dcr_token_sha256
        CHECK (
            dynamic_registration_initial_access_token_sha256 IS NULL
            OR (
                char_length(dynamic_registration_initial_access_token_sha256) = 64
                AND dynamic_registration_initial_access_token_sha256 ~ '^[0-9a-f]{64}$'
            )
        ),
    ADD CONSTRAINT ck_conformance_lease_ciba_decision_token_sha256
        CHECK (
            ciba_automated_decision_token_sha256 IS NULL
            OR (
                char_length(ciba_automated_decision_token_sha256) = 64
                AND ciba_automated_decision_token_sha256 ~ '^[0-9a-f]{64}$'
            )
        );

CREATE UNIQUE INDEX uq_conformance_lease_tenant_dcr_token_sha256
    ON conformance_leases (tenant_id, dynamic_registration_initial_access_token_sha256)
WHERE dynamic_registration_initial_access_token_sha256 IS NOT NULL;

CREATE UNIQUE INDEX uq_conformance_lease_tenant_ciba_decision_token_sha256
    ON conformance_leases (tenant_id, ciba_automated_decision_token_sha256)
    WHERE ciba_automated_decision_token_sha256 IS NOT NULL;

CREATE FUNCTION nazo_oauth_clear_conformance_lease_token_digests()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL OR NEW.cleaned_at IS NOT NULL THEN
        NEW.dynamic_registration_initial_access_token_sha256 := NULL;
        NEW.ciba_automated_decision_token_sha256 := NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_conformance_leases_clear_token_digests
BEFORE UPDATE OF revoked_at, cleaned_at ON conformance_leases
FOR EACH ROW
EXECUTE FUNCTION nazo_oauth_clear_conformance_lease_token_digests();

COMMENT ON COLUMN conformance_leases.dynamic_registration_initial_access_token_sha256 IS
    'Optional per-run SHA-256 binding for the oidc-fapi-ciba dynamic-registration initial-access token; never stores the token itself.';

COMMENT ON COLUMN conformance_leases.ciba_automated_decision_token_sha256 IS
    'Optional per-run SHA-256 binding for the oidc-fapi-ciba CIBA automated-decision token; never stores the token itself.';
