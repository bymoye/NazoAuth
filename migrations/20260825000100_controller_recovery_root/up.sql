-- Controller Recovery Root (D10/D11/D12, NazoAuthCtl-goal-plan/04A).
--
-- Per-deployment anchor for the offline Recovery Secret.  Only PUBLIC
-- verification material is ever persisted: the control side derives
-- `RecoveryKey = Ed25519(HKDF-SHA-256(secret, salt=deployment_id,
-- info="nazoauthctl/recovery"))` entirely offline and NazoAuth stores nothing
-- but the resulting public key and its kid.  The exact parameter set is
-- pinned per row by the `kdf` column (`hkdf-sha256-v1`), so a future KDF
-- change can never silently reinterpret stored roots.
--
-- One deployment has at most one Recovery Root at any time (04A §1); each
-- approved replacement bumps an explicit generation counter and instantly
-- invalidates every earlier secret.

CREATE TABLE controller_recovery_roots (
    deployment_id VARCHAR(128) NOT NULL,
    recovery_kid VARCHAR(43) NOT NULL,
    recovery_public_key BYTEA NOT NULL,
    kdf VARCHAR(32) NOT NULL,
    generation INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_controller_recovery_roots PRIMARY KEY (deployment_id),
    CONSTRAINT ck_controller_recovery_roots_deployment_shape CHECK (
        deployment_id ~ '^[A-Za-z0-9.:_+-]{1,128}$'
    ),
    CONSTRAINT ck_controller_recovery_roots_kid_shape CHECK (
        recovery_kid ~ '^[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT ck_controller_recovery_roots_public_key_length CHECK (
        octet_length(recovery_public_key) = 32
    ),
    -- Pinned derivation parameters; see nazo-operator-protocol::recovery.
    CONSTRAINT ck_controller_recovery_roots_kdf_pinned CHECK (
        kdf = 'hkdf-sha256-v1'
    ),
    CONSTRAINT ck_controller_recovery_roots_generation_positive CHECK (
        generation >= 1
    )
);

COMMENT ON TABLE controller_recovery_roots IS
    'Single per-deployment Recovery Public Key anchor; derived public material only.';

-- Single-use recovery challenge (D11): NazoAuth binds one random nonce to the
-- deployment and to the EXACT proposed controller key and replacement
-- Recovery Public Key.  The control side signs the canonical challenge
-- message with the OLD Recovery Key; verification against the current root is
-- atomic with revoking every controller slot, enrolling exactly one new slot,
-- and replacing the root.  Challenges bypass fresh-2FA by design (the admin
-- identity may be unreachable), so they are single-use, fixed short TTL,
-- capped in attempts, and limited to one pending challenge per deployment.
CREATE TABLE controller_recovery_challenges (
    challenge_id UUID NOT NULL,
    deployment_id VARCHAR(128) NOT NULL,
    nonce BYTEA NOT NULL,
    controller_label VARCHAR(128) NOT NULL,
    controller_kid VARCHAR(43) NOT NULL,
    controller_public_key BYTEA NOT NULL,
    recovery_kid VARCHAR(43) NOT NULL,
    recovery_public_key BYTEA NOT NULL,
    attempts SMALLINT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_controller_recovery_challenges PRIMARY KEY (challenge_id),
    CONSTRAINT ck_controller_recovery_challenges_deployment_shape CHECK (
        deployment_id ~ '^[A-Za-z0-9.:_+-]{1,128}$'
    ),
    CONSTRAINT ck_controller_recovery_challenges_nonce_length CHECK (
        octet_length(nonce) = 32
    ),
    CONSTRAINT ck_controller_recovery_challenges_label_bounded CHECK (
        length(controller_label) >= 1 AND length(controller_label) <= 128
    ),
    CONSTRAINT ck_controller_recovery_challenges_kids_shape CHECK (
        controller_kid ~ '^[A-Za-z0-9_-]{43}$'
        AND recovery_kid ~ '^[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT ck_controller_recovery_challenges_key_lengths CHECK (
        octet_length(controller_public_key) = 32
        AND octet_length(recovery_public_key) = 32
    ),
    CONSTRAINT ck_controller_recovery_challenges_attempts_bounded CHECK (
        attempts >= 0 AND attempts <= 64
    ),
    -- Fixed short window computed server-side: exactly ten minutes.
    CONSTRAINT ck_controller_recovery_challenges_fixed_ttl CHECK (
        expires_at = created_at + INTERVAL '600 seconds'
    ),
    CONSTRAINT ck_controller_recovery_challenges_single_use CHECK (
        consumed_at IS NULL OR consumed_at >= created_at
    ),
    -- A challenge can only exist for a deployment that already anchored a
    -- Recovery Root: no root, no recovery path (fail closed).
    CONSTRAINT fk_controller_recovery_challenges_root FOREIGN KEY (deployment_id)
        REFERENCES controller_recovery_roots (deployment_id)
);

COMMENT ON TABLE controller_recovery_challenges IS
    'Single-use nonce-bound recovery challenges; expired or consumed rows are dead.';

-- Rate-limit backstop: at most one outstanding challenge per deployment.
CREATE UNIQUE INDEX ux_controller_recovery_challenges_pending_per_deployment
    ON controller_recovery_challenges (deployment_id)
    WHERE consumed_at IS NULL;

-- D12 rotates the Recovery Root through the same fresh-2FA approval machinery
-- as every other identity action, so the approval catalog gains exactly one
-- action value.  The column must widen because the new name exceeds the old
-- VARCHAR(16).
ALTER TABLE controller_identity_approvals
    ALTER COLUMN action TYPE VARCHAR(32);
ALTER TABLE controller_identity_approvals
    DROP CONSTRAINT ck_controller_identity_approvals_action_catalog;
ALTER TABLE controller_identity_approvals
    ADD CONSTRAINT ck_controller_identity_approvals_action_catalog
    CHECK (action IN ('bind', 'add', 'rotate', 'revoke', 'recovery-root-rotate'));
