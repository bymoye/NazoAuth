ALTER TABLE controller_recovery_challenges
    ADD COLUMN accepted_signature_sha256 BYTEA,
    ADD COLUMN recovered_controller_id VARCHAR(36),
    ADD COLUMN recovered_slot_index SMALLINT,
    ADD COLUMN recovered_slot_issued_at TIMESTAMPTZ,
    ADD COLUMN recovered_slot_expires_at TIMESTAMPTZ,
    ADD COLUMN recovery_generation INTEGER;

ALTER TABLE controller_recovery_challenges
    ADD CONSTRAINT ck_controller_recovery_challenges_receipt_shape CHECK (
        (accepted_signature_sha256 IS NULL
            AND recovered_controller_id IS NULL
            AND recovered_slot_index IS NULL
            AND recovered_slot_issued_at IS NULL
            AND recovered_slot_expires_at IS NULL
            AND recovery_generation IS NULL)
        OR
        (octet_length(accepted_signature_sha256) = 32
            AND recovered_controller_id IS NOT NULL
            AND recovered_slot_index BETWEEN 0 AND 2
            AND recovered_slot_issued_at IS NOT NULL
            AND recovered_slot_expires_at > recovered_slot_issued_at
            AND recovery_generation IS NOT NULL
            AND consumed_at IS NOT NULL)
    );

ALTER TABLE controller_recovery_challenges
    ADD CONSTRAINT fk_controller_recovery_challenges_recovered_slot
    FOREIGN KEY (deployment_id, recovered_controller_id)
    REFERENCES controller_registry_slots (deployment_id, controller_id);

COMMENT ON COLUMN controller_recovery_challenges.accepted_signature_sha256 IS
    'SHA-256 of the accepted recovery signature; binds an idempotent retry to the exact submission.';
COMMENT ON COLUMN controller_recovery_challenges.recovered_controller_id IS
    'Controller slot committed by the accepted recovery, returned on exact retry.';
COMMENT ON COLUMN controller_recovery_challenges.recovered_slot_index IS
    'Immutable slot index from the accepted recovery result.';
COMMENT ON COLUMN controller_recovery_challenges.recovered_slot_issued_at IS
    'Immutable issuance time from the accepted recovery result.';
COMMENT ON COLUMN controller_recovery_challenges.recovered_slot_expires_at IS
    'Immutable expiry time from the accepted recovery result.';
COMMENT ON COLUMN controller_recovery_challenges.recovery_generation IS
    'Recovery Root generation committed by the accepted recovery, returned on exact retry.';
