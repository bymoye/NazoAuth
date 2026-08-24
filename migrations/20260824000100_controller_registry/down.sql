-- Downgrade is fail-closed (04 §2): the controller registry is the deployment's
-- only enrollment authority, so it must never be silently destroyed while any
-- slot could still admit operations or any approval could still be redeemed.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM controller_registry_slots WHERE status <> 'revoked'
    ) THEN
        RAISE EXCEPTION
            'downgrade refused: revoke every controller slot before removing the controller registry';
    END IF;
    IF EXISTS (
        SELECT 1 FROM controller_identity_approvals WHERE consumed_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'downgrade refused: unconsumed controller identity approvals remain';
    END IF;
END
$$;

DROP INDEX ux_controller_identity_approvals_token_hash;
DROP TABLE controller_identity_approvals;
DROP INDEX ux_controller_registry_slots_active_slot_index;
DROP INDEX ux_controller_registry_slots_deployment_kid;
DROP TABLE controller_registry_slots;
