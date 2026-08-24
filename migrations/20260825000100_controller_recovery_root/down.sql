-- Downgrade is fail-closed (04A): an in-flight recovery must never be
-- silently destroyed, and historical approval evidence keeps its closed
-- catalog.  Dropping the root table removes the deployment's only recovery
-- anchor; that is acceptable only once nothing is mid-flight — the root can
-- always be re-enrolled through a fresh-2FA rotation afterwards.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM controller_recovery_challenges WHERE consumed_at IS NULL
    ) THEN
        RAISE EXCEPTION
            'downgrade refused: unconsumed recovery challenges remain';
    END IF;
END
$$;

DROP INDEX ux_controller_recovery_challenges_pending_per_deployment;
DROP TABLE controller_recovery_challenges;
DROP TABLE controller_recovery_roots;

ALTER TABLE controller_identity_approvals
    DROP CONSTRAINT ck_controller_identity_approvals_action_catalog;
ALTER TABLE controller_identity_approvals
    ADD CONSTRAINT ck_controller_identity_approvals_action_catalog
    CHECK (action IN ('bind', 'add', 'rotate', 'revoke'));
ALTER TABLE controller_identity_approvals
    ALTER COLUMN action TYPE VARCHAR(16);
