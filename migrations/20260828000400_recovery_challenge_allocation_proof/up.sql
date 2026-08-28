-- Hard cut: every challenge allocation must prove possession of the current
-- Recovery Root before a pending row exists.  Old unsigned pending rows are
-- terminalized so they cannot carry the pre-proof allocation weakness across
-- deployment.  Historical rows receive a deterministic unique 32-byte marker;
-- application code consults allocation_nonce only for proof-era requests.

UPDATE controller_recovery_challenges
SET consumed_at = GREATEST(created_at, CURRENT_TIMESTAMP)
WHERE consumed_at IS NULL;

ALTER TABLE controller_recovery_challenges
    ADD COLUMN allocation_nonce BYTEA;

UPDATE controller_recovery_challenges
SET allocation_nonce = uuid_send(challenge_id) || uuid_send(challenge_id);

ALTER TABLE controller_recovery_challenges
    ALTER COLUMN allocation_nonce SET NOT NULL;

ALTER TABLE controller_recovery_challenges
    ADD CONSTRAINT ck_controller_recovery_challenges_allocation_nonce_length
    CHECK (octet_length(allocation_nonce) = 32);

ALTER TABLE controller_recovery_challenges
    ADD CONSTRAINT uq_controller_recovery_challenges_allocation_nonce
    UNIQUE (deployment_id, allocation_nonce);

COMMENT ON COLUMN controller_recovery_challenges.allocation_nonce IS
    'Client-generated nonce in the current-Recovery-Root allocation proof; unique per deployment and retained after consumption to reject replay.';
