-- A Recovery Root public key is single-use for one deployment. Keeping every
-- accepted key prevents a later A -> B -> A rotation from reviving an old
-- offline Recovery Secret or an allocation proof signed by it.
CREATE TABLE controller_recovery_root_key_history (
    deployment_id VARCHAR(128) NOT NULL,
    recovery_public_key BYTEA NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_controller_recovery_root_key_history
        PRIMARY KEY (deployment_id, recovery_public_key),
    CONSTRAINT fk_controller_recovery_root_key_history_deployment
        FOREIGN KEY (deployment_id)
        REFERENCES controller_recovery_roots (deployment_id)
        ON DELETE RESTRICT,
    CONSTRAINT ck_controller_recovery_root_key_history_deployment_shape CHECK (
        deployment_id ~ '^[A-Za-z0-9.:_+-]{1,128}$'
    ),
    CONSTRAINT ck_controller_recovery_root_key_history_public_key_length CHECK (
        octet_length(recovery_public_key) = 32
    )
);

INSERT INTO controller_recovery_root_key_history
    (deployment_id, recovery_public_key, first_seen_at)
SELECT deployment_id, recovery_public_key, created_at
FROM controller_recovery_roots;
