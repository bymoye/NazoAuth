-- Controller Registry (D01/D02, NazoAuthCtl-goal-plan/04 §2/§3).
--
-- Per-deployment authoritative store for controller public keys.  Only public
-- key material is persisted: private keys never leave the controlling host and
-- recovery secrets are out of scope for this registry.  The two hard service
-- invariants are pinned at the storage boundary itself:
--
-- * fixed 30-day TTL: `expires_at` must equal `issued_at + 2592000 seconds`
--   exactly; no renewal-in-place row shape exists;
-- * at most three concurrently non-revoked slots per deployment: slot indices
--   are bounded to 0..=2 by a CHECK and one active row may hold an index via a
--   partial unique index.

CREATE TABLE controller_registry_slots (
    deployment_id VARCHAR(128) NOT NULL,
    controller_id VARCHAR(36) NOT NULL,
    label VARCHAR(128) NOT NULL,
    kid VARCHAR(43) NOT NULL,
    public_key BYTEA NOT NULL,
    slot_index SMALLINT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    status VARCHAR(16) NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_controller_registry_slots PRIMARY KEY (deployment_id, controller_id),
    CONSTRAINT ck_controller_registry_slots_deployment_shape CHECK (
        deployment_id ~ '^[A-Za-z0-9.:_+-]{1,128}$'
    ),
    CONSTRAINT ck_controller_registry_slots_controller_id_is_uuidv7 CHECK (
        controller_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT ck_controller_registry_slots_kid_shape CHECK (
        kid ~ '^[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT ck_controller_registry_slots_public_key_length CHECK (
        octet_length(public_key) = 32
    ),
    CONSTRAINT ck_controller_registry_slots_slot_index_range CHECK (
        slot_index >= 0 AND slot_index <= 2
    ),
    -- Fixed lifetime, no natural months, no configurable window (04 §2).
    CONSTRAINT ck_controller_registry_slots_fixed_ttl CHECK (
        expires_at = issued_at + INTERVAL '2592000 seconds'
    ),
    CONSTRAINT ck_controller_registry_slots_status_catalog CHECK (
        status IN ('active', 'revoked')
    ),
    -- Revocation is terminal: a revoked row keeps its revocation timestamp and
    -- can never return to the active set.
    CONSTRAINT ck_controller_registry_slots_revocation_terminal CHECK (
        (status = 'active' AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

COMMENT ON TABLE controller_registry_slots IS
    'Authoritative per-deployment Controller Public Key registry; public material only.';

-- One key material identity per deployment.
CREATE UNIQUE INDEX ux_controller_registry_slots_deployment_kid
    ON controller_registry_slots (deployment_id, kid);

-- Hard backstop for the three-slot invariant: only three active rows can ever
-- hold the three legal slot indices of one deployment.
CREATE UNIQUE INDEX ux_controller_registry_slots_active_slot_index
    ON controller_registry_slots (deployment_id, slot_index)
    WHERE status = 'active';

-- Fresh single-use administrator 2FA approval for one exact identity action
-- (D05).  The plaintext approval token is shown once and stored only as a
-- BLAKE3 digest; consumption is atomic with the registry mutation it authorizes.
CREATE TABLE controller_identity_approvals (
    approval_id UUID NOT NULL,
    deployment_id VARCHAR(128) NOT NULL,
    action VARCHAR(16) NOT NULL,
    action_sha256 VARCHAR(64) NOT NULL,
    admin_user_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_controller_identity_approvals PRIMARY KEY (approval_id),
    CONSTRAINT ck_controller_identity_approvals_action_catalog CHECK (
        action IN ('bind', 'add', 'rotate', 'revoke')
    ),
    CONSTRAINT ck_controller_identity_approvals_action_digest_shape CHECK (
        action_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_controller_identity_approvals_token_hash_shape CHECK (
        token_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_controller_identity_approvals_deployment_shape CHECK (
        deployment_id ~ '^[A-Za-z0-9.:_+-]{1,128}$'
    ),
    CONSTRAINT ck_controller_identity_approvals_single_use CHECK (
        consumed_at IS NULL OR consumed_at >= created_at
    )
);

COMMENT ON TABLE controller_identity_approvals IS
    'Single-use fresh-2FA approvals binding one controller identity action hash to one administrator.';

CREATE UNIQUE INDEX ux_controller_identity_approvals_token_hash
    ON controller_identity_approvals (token_hash);
