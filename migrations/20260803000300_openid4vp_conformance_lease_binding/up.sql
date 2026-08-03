ALTER TABLE openid4vp_transactions
    ADD COLUMN conformance_lease_id UUID,
    ADD CONSTRAINT fk_openid4vp_transactions_conformance_lease
        FOREIGN KEY (tenant_id, conformance_lease_id)
        REFERENCES conformance_leases(tenant_id, id);

CREATE INDEX ix_openid4vp_transactions_conformance_lease
    ON openid4vp_transactions (tenant_id, conformance_lease_id)
    WHERE conformance_lease_id IS NOT NULL;

CREATE FUNCTION nazo_oauth_validate_conformance_presentation_lease_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.conformance_lease_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF NOT nazo_oauth_conformance_lease_is_active(
        NEW.tenant_id,
        NEW.conformance_lease_id
    ) THEN
        RAISE EXCEPTION 'conformance lease is not active for the presentation tenant'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_openid4vp_transactions_conformance_lease
BEFORE INSERT OR UPDATE ON openid4vp_transactions
FOR EACH ROW
EXECUTE FUNCTION nazo_oauth_validate_conformance_presentation_lease_binding();

CREATE FUNCTION nazo_oauth_delete_revoked_conformance_presentations()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL OR NEW.cleaned_at IS NOT NULL THEN
        DELETE FROM openid4vp_transactions
        WHERE tenant_id = NEW.tenant_id
          AND conformance_lease_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_conformance_leases_delete_presentations
AFTER UPDATE OF revoked_at, cleaned_at ON conformance_leases
FOR EACH ROW
EXECUTE FUNCTION nazo_oauth_delete_revoked_conformance_presentations();

COMMENT ON COLUMN openid4vp_transactions.conformance_lease_id IS
    'Optional time-bounded trust owner for verifier transactions. Expiry or revocation invalidates the transaction; cleanup deletes it.';
