-- This is the clean-lineage barrier for persisted security state. Old binaries
-- cannot understand the resulting schema, and current binaries must not retain
-- runtime compatibility paths for any shape removed here.

CREATE FUNCTION nazo_refresh_auth_context_is_current(context JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT jsonb_typeof(context) = 'object'
       AND context ?& ARRAY[
            'version', 'issuer', 'audience', 'auth_time', 'amr', 'oidc_sid',
            'id_token_sid', 'acr', 'nonce', 'userinfo_claims',
            'userinfo_claim_requests', 'id_token_claims', 'id_token_claim_requests'
       ]
       AND context - ARRAY[
            'version', 'issuer', 'audience', 'auth_time', 'amr', 'oidc_sid',
            'id_token_sid', 'acr', 'nonce', 'userinfo_claims',
            'userinfo_claim_requests', 'id_token_claims', 'id_token_claim_requests'
       ] = '{}'::jsonb
       AND jsonb_typeof(context -> 'version') = 'number'
       AND context ->> 'version' = '1'
       AND jsonb_typeof(context -> 'issuer') = 'string'
       AND btrim(context ->> 'issuer') <> ''
       AND jsonb_typeof(context -> 'audience') = 'string'
       AND btrim(context ->> 'audience') <> ''
       AND jsonb_typeof(context -> 'auth_time') = 'number'
       AND context ->> 'auth_time' ~ '^[1-9][0-9]{0,18}$'
       AND (
            char_length(context ->> 'auth_time') < 19
            OR context ->> 'auth_time' <= '9223372036854775807'
       )
       AND jsonb_path_match(
            context -> 'amr',
            '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))'
       )
       AND jsonb_typeof(context -> 'oidc_sid') IN ('null', 'string')
       AND (jsonb_typeof(context -> 'oidc_sid') = 'null' OR btrim(context ->> 'oidc_sid') <> '')
       AND jsonb_typeof(context -> 'id_token_sid') IN ('null', 'string')
       AND (jsonb_typeof(context -> 'id_token_sid') = 'null' OR btrim(context ->> 'id_token_sid') <> '')
       AND jsonb_typeof(context -> 'acr') IN ('null', 'string')
       AND (jsonb_typeof(context -> 'acr') = 'null' OR btrim(context ->> 'acr') <> '')
       AND jsonb_typeof(context -> 'nonce') IN ('null', 'string')
       AND jsonb_path_match(
            context -> 'userinfo_claims',
            '$.type() == "array" && !exists($[*] ? (@.type() != "string"))'
       )
       AND jsonb_path_match(
            context -> 'id_token_claims',
            '$.type() == "array" && !exists($[*] ? (@.type() != "string"))'
       )
       AND jsonb_path_match(
            context -> 'userinfo_claim_requests',
            '$.type() == "array" && !exists($[*] ? (@.type() != "object" || !exists(@.name) || @.name.type() != "string"))'
       )
       AND jsonb_path_match(
            context -> 'id_token_claim_requests',
            '$.type() == "array" && !exists($[*] ? (@.type() != "object" || !exists(@.name) || @.name.type() != "string"))'
       );
$$;

-- oauth_tokens has only ever stored refresh-token family rows, and
-- token_family_id has been NOT NULL since the baseline schema. A malformed row
-- compromises the entire tenant-scoped family because rotation and lost-response
-- recovery can otherwise select a sibling with a weaker contract. The
-- IS NOT DISTINCT FROM join also closes safely if a deployment drifted from the
-- historical NOT NULL constraint; no NULL family can escape through SQL IN.
WITH compromised_families AS (
    SELECT DISTINCT candidate.tenant_id, candidate.token_family_id
    FROM oauth_tokens AS candidate
    LEFT JOIN oauth_clients AS client ON client.id = candidate.client_id
    WHERE candidate.token_family_id IS NULL
       OR NOT jsonb_path_match(
            candidate.audience,
            '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))'
       )
       OR NOT COALESCE(nazo_refresh_auth_context_is_current(candidate.oidc_auth_context), FALSE)
       OR candidate.oidc_auth_context ->> 'audience' IS DISTINCT FROM client.client_id
       OR CASE
            WHEN nazo_refresh_auth_context_is_current(candidate.oidc_auth_context)
            THEN (candidate.oidc_auth_context ->> 'auth_time')::BIGINT
                 > floor(EXTRACT(EPOCH FROM candidate.issued_at))::BIGINT
            ELSE TRUE
       END
       OR EXISTS (
            SELECT 1
            FROM oauth_tokens AS sibling
            WHERE sibling.tenant_id = candidate.tenant_id
              AND sibling.token_family_id IS NOT DISTINCT FROM candidate.token_family_id
              AND sibling.oidc_auth_context IS DISTINCT FROM candidate.oidc_auth_context
       )
)
DELETE FROM oauth_tokens AS doomed
USING compromised_families AS compromised
WHERE doomed.tenant_id = compromised.tenant_id
  AND doomed.token_family_id IS NOT DISTINCT FROM compromised.token_family_id;

ALTER TABLE oauth_tokens
    ALTER COLUMN token_family_id SET NOT NULL,
    ALTER COLUMN audience DROP DEFAULT,
    ALTER COLUMN oidc_auth_context SET NOT NULL,
    ADD CONSTRAINT ck_oauth_tokens_refresh_contract_current CHECK (
        jsonb_path_match(
            audience,
            '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))'
        )
        AND CASE
            WHEN COALESCE(nazo_refresh_auth_context_is_current(oidc_auth_context), FALSE)
            THEN (oidc_auth_context ->> 'auth_time')::BIGINT
                <= floor(EXTRACT(EPOCH FROM issued_at))::BIGINT
            ELSE FALSE
        END
    );

CREATE FUNCTION nazo_client_security_policy_is_current(policy JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT jsonb_typeof(policy) = 'object'
       AND policy ?& ARRAY[
            'version', 'assurance', 'require_signed_authorization_request',
            'require_signed_authorization_response',
            'require_signed_introspection_response', 'session_management',
            'allow_cross_device_flows', 'allow_confidential_oidc_without_pkce'
       ]
       AND policy - ARRAY[
            'version', 'assurance', 'require_signed_authorization_request',
            'require_signed_authorization_response',
            'require_signed_introspection_response', 'session_management',
            'allow_cross_device_flows', 'allow_confidential_oidc_without_pkce'
       ] = '{}'::jsonb
       AND jsonb_typeof(policy -> 'version') = 'number'
       AND policy ->> 'version' = '1'
       AND jsonb_typeof(policy -> 'assurance') = 'string'
       AND policy ->> 'assurance' IN ('baseline', 'fapi2')
       AND jsonb_typeof(policy -> 'require_signed_authorization_request') = 'boolean'
       AND jsonb_typeof(policy -> 'require_signed_authorization_response') = 'boolean'
       AND jsonb_typeof(policy -> 'require_signed_introspection_response') = 'boolean'
       AND jsonb_typeof(policy -> 'session_management') = 'boolean'
       AND jsonb_typeof(policy -> 'allow_cross_device_flows') = 'boolean'
       AND jsonb_typeof(policy -> 'allow_confidential_oidc_without_pkce') = 'boolean';
$$;

-- ClientSecurityPolicy depends on deployment policy that is not persisted in
-- legacy rows. Refuse to invent it: operators must materialize an explicit v1
-- policy for every existing client before crossing this barrier.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM oauth_clients
        WHERE NOT COALESCE(nazo_client_security_policy_is_current(security_policy), FALSE)
    ) THEN
        RAISE EXCEPTION
            'migration refused: every OAuth client requires an explicit v1 security_policy';
    END IF;
END
$$;

ALTER TABLE oauth_clients
    DROP CONSTRAINT ck_oauth_clients_security_policy_object,
    ALTER COLUMN security_policy SET NOT NULL,
    ADD CONSTRAINT ck_oauth_clients_security_policy_object CHECK (
        nazo_client_security_policy_is_current(security_policy)
    );

-- TOTP plaintext is not migratable without the deployment data-encryption key.
-- Existing deployments must complete encryption before this schema migration.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM user_totp_credentials
        WHERE secret_base32 IS NOT NULL
           OR secret_ciphertext IS NULL
           OR octet_length(secret_ciphertext) NOT BETWEEN 45 AND 157
           OR get_byte(secret_ciphertext, 0) <> 1
           OR secret_key_id IS NULL
           OR char_length(btrim(secret_key_id)) NOT BETWEEN 1 AND 128
    ) THEN
        RAISE EXCEPTION
            'migration refused: every TOTP credential must already use a complete encrypted envelope';
    END IF;
END
$$;

ALTER TABLE user_totp_credentials
    DROP CONSTRAINT ck_user_totp_credentials_secret_envelope,
    DROP COLUMN secret_base32,
    ALTER COLUMN secret_ciphertext SET NOT NULL,
    ALTER COLUMN secret_key_id SET NOT NULL,
    ADD CONSTRAINT ck_user_totp_credentials_secret_envelope CHECK (
        octet_length(secret_ciphertext) BETWEEN 45 AND 157
        AND get_byte(secret_ciphertext, 0) = 1
        AND char_length(btrim(secret_key_id)) BETWEEN 1 AND 128
    );

-- Runtime module desired state is now the only policy authority. A genuinely
-- clean install has no application or runtime history and receives the explicit
-- baseline once. Any existing deployment must provide a complete explicit
-- catalog before upgrading; missing rows and inherit are configuration loss.
DO $$
DECLARE
    desired_count BIGINT;
BEGIN
    SELECT count(*) INTO desired_count FROM runtime_module_desired_states;

    IF desired_count = 0 THEN
        IF EXISTS (SELECT 1 FROM users)
           OR EXISTS (SELECT 1 FROM oauth_clients)
           OR EXISTS (SELECT 1 FROM oauth_tokens)
           OR EXISTS (SELECT 1 FROM runtime_module_instance_states)
           OR EXISTS (SELECT 1 FROM runtime_module_state_events)
        THEN
            RAISE EXCEPTION
                'migration refused: existing deployment is missing explicit runtime module desired state';
        END IF;

        INSERT INTO runtime_module_desired_states
            (module_id, desired_mode, revision, actor_id, reason, updated_at)
        VALUES
            ('device_authorization', 'enabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('token_exchange', 'enabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('jwt_bearer_grant', 'enabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('ciba', 'enabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('request_objects', 'enabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('jarm', 'enabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('scim', 'enabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('frontchannel_logout', 'enabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('session_management', 'enabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('dynamic_client_registration', 'disabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('authorization_details', 'disabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('http_message_signatures', 'disabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('scim_security_events', 'disabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('openid4vci_issuer', 'disabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('openid4vp_verifier', 'disabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP),
            ('native_sso', 'disabled', 1, NULL, 'clean install baseline', CURRENT_TIMESTAMP);

        INSERT INTO runtime_module_state_events (
            event_id, module_id, event_type, revision, instance_id, actor_id,
            reason, before_state, after_state, outcome_code, occurred_at
        )
        SELECT
            uuidv7(), module_id, 'desired_state_changed', revision, NULL, actor_id,
            reason, NULL, desired_mode, NULL, updated_at
        FROM runtime_module_desired_states;
    ELSIF desired_count <> 16
       OR EXISTS (
            SELECT 1
            FROM runtime_module_desired_states
            WHERE desired_mode NOT IN ('enabled', 'disabled')
       )
       OR EXISTS (
            SELECT module_id
            FROM (VALUES
                ('device_authorization'), ('token_exchange'), ('jwt_bearer_grant'), ('ciba'),
                ('dynamic_client_registration'), ('request_objects'), ('jarm'),
                ('authorization_details'), ('http_message_signatures'), ('scim'),
                ('scim_security_events'), ('native_sso'), ('frontchannel_logout'),
                ('session_management'), ('openid4vci_issuer'), ('openid4vp_verifier')
            ) AS catalog(module_id)
            WHERE NOT EXISTS (
                SELECT 1
                FROM runtime_module_desired_states AS desired
                WHERE desired.module_id = catalog.module_id
            )
       )
    THEN
        RAISE EXCEPTION
            'migration refused: runtime module desired state must contain the complete explicit catalog';
    END IF;
END
$$;

ALTER TABLE runtime_module_desired_states
    DROP CONSTRAINT ck_runtime_module_desired_mode,
    ADD CONSTRAINT ck_runtime_module_desired_mode CHECK (
        desired_mode IN ('enabled', 'disabled')
    );

DROP TABLE runtime_module_default_policy;
