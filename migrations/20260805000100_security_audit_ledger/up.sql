-- Security-sensitive application events are persisted separately from the
-- process log/OTLP pipeline. The ledger is immutable; the outbox is the
-- delivery state for an external exporter.
--
-- This migration deliberately does not provision cluster roles. Deployments must run it
-- as the dedicated migration owner, then grant the SECURITY DEFINER APIs to
-- pre-created writer/exporter roles as described in the operations guide.
CREATE TABLE public.security_audit_chain_state (
    singleton BOOLEAN PRIMARY KEY,
    last_sequence BIGINT NOT NULL,
    last_hash BYTEA NOT NULL,
    CONSTRAINT ck_security_audit_chain_singleton CHECK (singleton),
    CONSTRAINT ck_security_audit_chain_hash_length CHECK (octet_length(last_hash) = 32),
    CONSTRAINT ck_security_audit_chain_sequence_non_negative CHECK (last_sequence >= 0)
);

INSERT INTO public.security_audit_chain_state (singleton, last_sequence, last_hash)
VALUES (TRUE, 0, decode(repeat('00', 32), 'hex'));

CREATE TABLE public.security_audit_events (
    event_id UUID PRIMARY KEY,
    sequence BIGINT NOT NULL UNIQUE,
    event_type VARCHAR(64) NOT NULL,
    event_category VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    previous_hash BYTEA NOT NULL,
    event_hash BYTEA NOT NULL UNIQUE,
    CONSTRAINT ck_security_audit_event_sequence_positive CHECK (sequence > 0),
    CONSTRAINT ck_security_audit_event_type CHECK (
        char_length(event_type) BETWEEN 1 AND 64
        AND event_type ~ '^[a-z][a-z0-9_]*$'
    ),
    CONSTRAINT ck_security_audit_event_category CHECK (
        char_length(event_category) BETWEEN 1 AND 64
        AND event_category ~ '^[a-z][a-z0-9_]*$'
    ),
    CONSTRAINT ck_security_audit_event_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT ck_security_audit_event_previous_hash_length CHECK (octet_length(previous_hash) = 32),
    CONSTRAINT ck_security_audit_event_hash_length CHECK (octet_length(event_hash) = 32)
);

CREATE INDEX idx_security_audit_events_occurred_at
    ON public.security_audit_events (occurred_at DESC, sequence DESC);
CREATE INDEX idx_security_audit_events_type_sequence
    ON public.security_audit_events (event_type, sequence DESC);

CREATE TABLE public.security_audit_event_outbox (
    event_id UUID PRIMARY KEY REFERENCES public.security_audit_events(event_id) ON DELETE RESTRICT,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_at TIMESTAMPTZ,
    exported_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_security_audit_outbox_attempts_non_negative CHECK (attempts >= 0),
    CONSTRAINT ck_security_audit_outbox_terminal_once CHECK (
        exported_at IS NULL OR locked_at IS NULL
    )
);

CREATE INDEX idx_security_audit_outbox_due
    ON public.security_audit_event_outbox (available_at, created_at)
    WHERE exported_at IS NULL;

-- Application code never updates or deletes ledger rows. Keep this invariant
-- in the database as well so an exporter/operator cannot silently rewrite the
-- evidence chain through an accidental UPDATE/DELETE/TRUNCATE.
CREATE FUNCTION public.nazo_reject_security_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'security audit ledger is append-only';
END;
$$;

CREATE TRIGGER security_audit_events_append_only
BEFORE UPDATE OR DELETE ON public.security_audit_events
FOR EACH ROW EXECUTE FUNCTION public.nazo_reject_security_audit_event_mutation();

CREATE TRIGGER security_audit_events_no_truncate
BEFORE TRUNCATE ON public.security_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION public.nazo_reject_security_audit_event_mutation();

-- Lock the chain head in the caller's transaction. The writer computes the
-- BLAKE3 event hash in Rust, then passes the locked head and hash to the
-- append function below. The function re-checks both values before inserting.
CREATE FUNCTION public.nazo_security_audit_chain_head_for_update()
RETURNS TABLE(last_sequence BIGINT, last_hash BYTEA)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT state.last_sequence, state.last_hash
    FROM public.security_audit_chain_state AS state
    WHERE state.singleton IS TRUE
    FOR UPDATE
$$;

CREATE FUNCTION public.nazo_append_security_audit_event(
    p_event_id UUID,
    p_event_type TEXT,
    p_event_category TEXT,
    p_payload JSONB,
    p_occurred_at TIMESTAMPTZ,
    p_previous_hash BYTEA,
    p_event_hash BYTEA
)
RETURNS TABLE(event_id UUID, sequence BIGINT, event_hash BYTEA)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_last_sequence BIGINT;
    v_last_hash BYTEA;
    v_head_sequence BIGINT;
    v_head_hash BYTEA;
    v_next_sequence BIGINT;
    v_existing_sequence BIGINT;
    v_existing_hash BYTEA;
    v_existing_matches BOOLEAN;
BEGIN
    IF p_event_id IS NULL OR p_event_id = '00000000-0000-0000-0000-000000000000'::UUID
       OR p_event_type IS NULL
       OR char_length(p_event_type) NOT BETWEEN 1 AND 64
       OR p_event_type !~ '^[a-z][a-z0-9_]*$'
       OR p_event_category IS NULL
       OR char_length(p_event_category) NOT BETWEEN 1 AND 64
       OR p_event_category !~ '^[a-z][a-z0-9_]*$'
       OR p_payload IS NULL
       OR jsonb_typeof(p_payload) <> 'object'
       OR octet_length(convert_to(p_payload::text, 'UTF8')) > 65536
       OR p_occurred_at IS NULL
       OR p_previous_hash IS NULL
       OR octet_length(p_previous_hash) <> 32
       OR p_event_hash IS NULL
       OR octet_length(p_event_hash) <> 32 THEN
        RAISE EXCEPTION 'invalid security audit event';
    END IF;

    SELECT state.last_sequence, state.last_hash
    INTO v_last_sequence, v_last_hash
    FROM public.security_audit_chain_state AS state
    WHERE state.singleton IS TRUE
    FOR UPDATE;
    IF NOT FOUND OR v_last_sequence < 0 OR v_last_hash IS NULL
       OR octet_length(v_last_hash) <> 32 THEN
        RAISE EXCEPTION 'security audit chain state is invalid';
    END IF;

    SELECT events.sequence,
           events.event_hash,
           events.event_type = p_event_type
               AND events.event_category = p_event_category
               AND events.payload = p_payload
               AND events.occurred_at = p_occurred_at
    INTO v_existing_sequence, v_existing_hash, v_existing_matches
    FROM public.security_audit_events AS events
    WHERE events.event_id = p_event_id;
    IF FOUND THEN
        IF NOT v_existing_matches THEN
            RAISE EXCEPTION 'security audit event id collision';
        END IF;
        RETURN QUERY SELECT p_event_id, v_existing_sequence, v_existing_hash;
        RETURN;
    END IF;

    SELECT events.sequence, events.event_hash
    INTO v_head_sequence, v_head_hash
    FROM public.security_audit_events AS events
    ORDER BY events.sequence DESC
    LIMIT 1;
    IF v_head_sequence IS NULL THEN
        IF v_last_sequence <> 0
           OR v_last_hash <> decode(repeat('00', 32), 'hex') THEN
            RAISE EXCEPTION 'security audit chain state does not match ledger head';
        END IF;
    ELSIF v_head_sequence <> v_last_sequence OR v_head_hash IS DISTINCT FROM v_last_hash THEN
        RAISE EXCEPTION 'security audit chain state does not match ledger head';
    END IF;
    IF p_previous_hash IS DISTINCT FROM v_last_hash THEN
        RAISE EXCEPTION 'security audit append head is stale';
    END IF;
    IF v_last_sequence = 9223372036854775807 THEN
        RAISE EXCEPTION 'security audit sequence overflow';
    END IF;
    v_next_sequence := v_last_sequence + 1;

    INSERT INTO public.security_audit_events (
        event_id,
        sequence,
        event_type,
        event_category,
        payload,
        occurred_at,
        previous_hash,
        event_hash
    )
    VALUES (
        p_event_id,
        v_next_sequence,
        p_event_type,
        p_event_category,
        p_payload,
        p_occurred_at,
        p_previous_hash,
        p_event_hash
    );
    INSERT INTO public.security_audit_event_outbox (event_id)
    VALUES (p_event_id);
    UPDATE public.security_audit_chain_state AS state
    SET last_sequence = v_next_sequence,
        last_hash = p_event_hash
    WHERE state.singleton IS TRUE;

    RETURN QUERY SELECT p_event_id, v_next_sequence, p_event_hash;
END;
$$;

CREATE FUNCTION public.nazo_claim_security_audit_events(
    p_limit BIGINT,
    p_lock_timeout_seconds INTEGER
)
RETURNS TABLE(
    event_id UUID,
    attempts INTEGER,
    sequence BIGINT,
    event_type TEXT,
    event_category TEXT,
    payload JSONB,
    occurred_at TIMESTAMPTZ,
    previous_hash BYTEA,
    event_hash BYTEA
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_limit IS NULL OR p_limit <= 0 OR p_limit > 256
       OR p_lock_timeout_seconds IS NULL
       OR p_lock_timeout_seconds <= 0 OR p_lock_timeout_seconds > 3600 THEN
        RAISE EXCEPTION 'audit outbox claim bounds are invalid';
    END IF;
    IF NOT pg_try_advisory_xact_lock(5582270151998680401) THEN
        RETURN;
    END IF;

    RETURN QUERY
    WITH first_pending AS (
        SELECT outbox.event_id,
               events.sequence,
               outbox.available_at,
               outbox.locked_at
        FROM public.security_audit_event_outbox AS outbox
        JOIN public.security_audit_events AS events ON events.event_id = outbox.event_id
        WHERE outbox.exported_at IS NULL
        ORDER BY events.sequence ASC
        LIMIT 1
    ), eligible_head AS (
        SELECT first_pending.sequence
        FROM first_pending
        WHERE first_pending.available_at <= CURRENT_TIMESTAMP
          AND (
              first_pending.locked_at IS NULL
              OR first_pending.locked_at < CURRENT_TIMESTAMP
                  - (p_lock_timeout_seconds * INTERVAL '1 second')
          )
    ), due AS (
        SELECT outbox.event_id
        FROM public.security_audit_event_outbox AS outbox
        JOIN public.security_audit_events AS events ON events.event_id = outbox.event_id
        JOIN eligible_head ON events.sequence >= eligible_head.sequence
        WHERE outbox.exported_at IS NULL
          AND outbox.available_at <= CURRENT_TIMESTAMP
          AND (
              outbox.locked_at IS NULL
              OR outbox.locked_at < CURRENT_TIMESTAMP
                  - (p_lock_timeout_seconds * INTERVAL '1 second')
          )
        ORDER BY events.sequence ASC
        FOR UPDATE OF outbox
        LIMIT p_limit
    ), claimed AS (
        UPDATE public.security_audit_event_outbox AS outbox
        SET attempts = outbox.attempts + 1,
            locked_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        FROM due
        WHERE outbox.event_id = due.event_id
        RETURNING outbox.event_id, outbox.attempts
    )
    SELECT claimed.event_id,
           claimed.attempts,
           events.sequence,
           events.event_type::TEXT,
           events.event_category::TEXT,
           events.payload,
           events.occurred_at,
           events.previous_hash,
           events.event_hash
    FROM claimed
    JOIN public.security_audit_events AS events ON events.event_id = claimed.event_id
    ORDER BY events.sequence ASC;
END;
$$;

CREATE FUNCTION public.nazo_ack_security_audit_event(
    p_event_id UUID,
    p_expected_attempts INTEGER
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    UPDATE public.security_audit_event_outbox AS outbox
    SET exported_at = CURRENT_TIMESTAMP,
        locked_at = NULL,
        updated_at = CURRENT_TIMESTAMP
    WHERE outbox.event_id = p_event_id
      AND outbox.attempts = p_expected_attempts
      AND outbox.locked_at IS NOT NULL
      AND outbox.exported_at IS NULL;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

CREATE FUNCTION public.nazo_reschedule_security_audit_event(
    p_event_id UUID,
    p_expected_attempts INTEGER,
    p_available_at TIMESTAMPTZ,
    p_last_error TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    IF p_available_at IS NULL
       OR p_available_at > CURRENT_TIMESTAMP + INTERVAL '5 minutes'
       OR p_last_error IS NULL OR char_length(p_last_error) > 128 THEN
        RAISE EXCEPTION 'audit outbox reschedule bounds are invalid';
    END IF;
    UPDATE public.security_audit_event_outbox AS outbox
    SET available_at = p_available_at,
        locked_at = NULL,
        last_error = p_last_error,
        updated_at = CURRENT_TIMESTAMP
    WHERE outbox.event_id = p_event_id
      AND outbox.attempts = p_expected_attempts
      AND outbox.locked_at IS NOT NULL
      AND outbox.exported_at IS NULL;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

-- Return a valid chain head for a writer before a high-impact operation. An
-- invalid/missing head returns no row, which makes the repository fail closed.
CREATE FUNCTION public.nazo_security_audit_anchor_freshness()
RETURNS TABLE(last_sequence BIGINT, last_hash BYTEA, checked_at TIMESTAMPTZ)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH head AS (
        SELECT events.sequence, events.event_hash
        FROM public.security_audit_events AS events
        ORDER BY events.sequence DESC
        LIMIT 1
    )
    SELECT state.last_sequence, state.last_hash, CURRENT_TIMESTAMP
    FROM public.security_audit_chain_state AS state
    LEFT JOIN head ON TRUE
    WHERE state.singleton IS TRUE
      AND state.last_sequence >= 0
      AND octet_length(state.last_hash) = 32
      AND (
          (head.sequence IS NULL
           AND state.last_sequence = 0
           AND state.last_hash = decode(repeat('00', 32), 'hex'))
          OR
          (head.sequence IS NOT NULL
           AND head.sequence = state.last_sequence
           AND head.event_hash = state.last_hash)
      )
$$;

-- Exporters can observe both the chain head and whether the durable outbox is
-- drained without receiving table SELECT privileges.
CREATE FUNCTION public.nazo_security_audit_anchor_health()
RETURNS TABLE(
    last_sequence BIGINT,
    last_hash BYTEA,
    chain_valid BOOLEAN,
    pending_count BIGINT,
    oldest_pending_occurred_at TIMESTAMPTZ,
    last_exported_sequence BIGINT,
    last_exported_hash BYTEA,
    last_exported_occurred_at TIMESTAMPTZ,
    last_exported_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH head AS (
        SELECT events.sequence, events.event_hash
        FROM public.security_audit_events AS events
        ORDER BY events.sequence DESC
        LIMIT 1
    ), chain AS (
        SELECT state.last_sequence,
               state.last_hash,
               (
                   state.last_sequence >= 0
                   AND octet_length(state.last_hash) = 32
                   AND (
                       (head.sequence IS NULL
                        AND state.last_sequence = 0
                        AND state.last_hash = decode(repeat('00', 32), 'hex'))
                       OR
                       (head.sequence IS NOT NULL
                        AND head.sequence = state.last_sequence
                        AND head.event_hash = state.last_hash)
                   )
               ) AS chain_valid
        FROM public.security_audit_chain_state AS state
        LEFT JOIN head ON TRUE
        WHERE state.singleton IS TRUE
    ), backlog AS (
        SELECT COUNT(*)::BIGINT AS pending_count,
               MIN(events.occurred_at) AS oldest_pending_occurred_at
        FROM public.security_audit_event_outbox AS outbox
        JOIN public.security_audit_events AS events ON events.event_id = outbox.event_id
        WHERE outbox.exported_at IS NULL
    ), exported AS (
        SELECT events.sequence AS last_exported_sequence,
               events.event_hash AS last_exported_hash,
               events.occurred_at AS last_exported_occurred_at,
               outbox.exported_at AS last_exported_at
        FROM public.security_audit_event_outbox AS outbox
        JOIN public.security_audit_events AS events ON events.event_id = outbox.event_id
        WHERE outbox.exported_at IS NOT NULL
        ORDER BY events.sequence DESC
        LIMIT 1
    )
    SELECT chain.last_sequence,
           chain.last_hash,
           chain.chain_valid,
           backlog.pending_count,
           backlog.oldest_pending_occurred_at,
           exported.last_exported_sequence,
           exported.last_exported_hash,
           exported.last_exported_occurred_at,
           exported.last_exported_at
    FROM chain
    CROSS JOIN backlog
    LEFT JOIN exported ON TRUE
$$;

-- This preflight is intentionally policy-driven. It always reports effective
-- privileges of the login role (`session_user`), not the SECURITY DEFINER
-- owner. Strict mode rejects a superuser/table owner or any direct table
-- privilege; non-strict mode is only for explicitly isolated development
-- fixtures and still requires the requested function EXECUTEs and a valid
-- chain. No role is created or granted by this migration.
CREATE FUNCTION public.nazo_security_audit_privilege_preflight(
    p_require_least_privilege BOOLEAN,
    p_require_append BOOLEAN,
    p_require_exporter BOOLEAN
)
RETURNS TABLE(
    chain_valid BOOLEAN,
    append_execute BOOLEAN,
    head_execute BOOLEAN,
    anchor_freshness_execute BOOLEAN,
    claim_execute BOOLEAN,
    ack_execute BOOLEAN,
    anchor_health_execute BOOLEAN,
    caller_is_superuser BOOLEAN,
    caller_owns_ledger BOOLEAN,
    direct_ledger_privilege BOOLEAN,
    policy_satisfied BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_caller NAME := session_user;
BEGIN
    RETURN QUERY
    WITH head AS (
        SELECT events.sequence, events.event_hash
        FROM public.security_audit_events AS events
        ORDER BY events.sequence DESC
        LIMIT 1
    ), chain AS (
        SELECT state.last_sequence,
               state.last_hash,
               head.sequence AS head_sequence,
               head.event_hash AS head_hash
        FROM public.security_audit_chain_state AS state
        LEFT JOIN head ON TRUE
        WHERE state.singleton IS TRUE
    ), flags AS (
        SELECT
            COALESCE((
                SELECT cs.last_sequence >= 0
                   AND octet_length(cs.last_hash) = 32
                   AND (
                       (cs.head_sequence IS NULL
                        AND cs.last_sequence = 0
                        AND cs.last_hash = decode(repeat('00', 32), 'hex'))
                       OR
                       (cs.head_sequence IS NOT NULL
                        AND cs.head_sequence = cs.last_sequence
                        AND cs.head_hash = cs.last_hash)
                   )
                FROM chain AS cs
            ), FALSE) AS chain_valid,
            COALESCE(has_function_privilege(
                v_caller,
                'public.nazo_append_security_audit_event(uuid,text,text,jsonb,timestamptz,bytea,bytea)'::REGPROCEDURE,
                'EXECUTE'
            ), FALSE) AS append_execute,
            COALESCE(has_function_privilege(
                v_caller,
                'public.nazo_security_audit_chain_head_for_update()'::REGPROCEDURE,
                'EXECUTE'
            ), FALSE) AS head_execute,
            COALESCE(has_function_privilege(
                v_caller,
                'public.nazo_security_audit_anchor_freshness()'::REGPROCEDURE,
                'EXECUTE'
            ), FALSE) AS anchor_freshness_execute,
            COALESCE(has_function_privilege(
                v_caller,
                'public.nazo_claim_security_audit_events(bigint,integer)'::REGPROCEDURE,
                'EXECUTE'
            ), FALSE) AS claim_execute,
            COALESCE(has_function_privilege(
                v_caller,
                'public.nazo_ack_security_audit_event(uuid,integer)'::REGPROCEDURE,
                'EXECUTE'
            ), FALSE)
            AND COALESCE(has_function_privilege(
                v_caller,
                'public.nazo_reschedule_security_audit_event(uuid,integer,timestamptz,text)'::REGPROCEDURE,
                'EXECUTE'
            ), FALSE) AS ack_execute,
            COALESCE(has_function_privilege(
                v_caller,
                'public.nazo_security_audit_anchor_health()'::REGPROCEDURE,
                'EXECUTE'
            ), FALSE) AS anchor_health_execute,
            COALESCE((
                SELECT bool_or(role.rolsuper)
                FROM pg_roles AS role
                WHERE pg_has_role(v_caller, role.oid, 'MEMBER')
            ), TRUE) AS caller_is_superuser,
            COALESCE((
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_class AS relation
                    JOIN pg_namespace AS namespace
                      ON namespace.oid = relation.relnamespace
                    JOIN pg_roles AS role
                      ON role.oid = relation.relowner
                    WHERE namespace.nspname = 'public'
                      AND relation.relname IN (
                          'security_audit_chain_state',
                          'security_audit_events',
                          'security_audit_event_outbox'
                      )
                      AND pg_has_role(v_caller, role.oid, 'MEMBER')
                )
            ), FALSE) AS caller_owns_ledger,
            (
                has_table_privilege(v_caller, 'public.security_audit_chain_state', 'SELECT')
                OR has_table_privilege(v_caller, 'public.security_audit_chain_state', 'INSERT')
                OR has_table_privilege(v_caller, 'public.security_audit_chain_state', 'UPDATE')
                OR has_table_privilege(v_caller, 'public.security_audit_chain_state', 'DELETE')
                OR has_table_privilege(v_caller, 'public.security_audit_chain_state', 'TRUNCATE')
                OR has_table_privilege(v_caller, 'public.security_audit_chain_state', 'REFERENCES')
                OR has_table_privilege(v_caller, 'public.security_audit_chain_state', 'TRIGGER')
                OR has_table_privilege(v_caller, 'public.security_audit_events', 'SELECT')
                OR has_table_privilege(v_caller, 'public.security_audit_events', 'INSERT')
                OR has_table_privilege(v_caller, 'public.security_audit_events', 'UPDATE')
                OR has_table_privilege(v_caller, 'public.security_audit_events', 'DELETE')
                OR has_table_privilege(v_caller, 'public.security_audit_events', 'TRUNCATE')
                OR has_table_privilege(v_caller, 'public.security_audit_events', 'REFERENCES')
                OR has_table_privilege(v_caller, 'public.security_audit_events', 'TRIGGER')
                OR has_table_privilege(v_caller, 'public.security_audit_event_outbox', 'SELECT')
                OR has_table_privilege(v_caller, 'public.security_audit_event_outbox', 'INSERT')
                OR has_table_privilege(v_caller, 'public.security_audit_event_outbox', 'UPDATE')
                OR has_table_privilege(v_caller, 'public.security_audit_event_outbox', 'DELETE')
                OR has_table_privilege(v_caller, 'public.security_audit_event_outbox', 'TRUNCATE')
                OR has_table_privilege(v_caller, 'public.security_audit_event_outbox', 'REFERENCES')
                OR has_table_privilege(v_caller, 'public.security_audit_event_outbox', 'TRIGGER')
            ) AS direct_ledger_privilege
    )
    SELECT flags.chain_valid,
           flags.append_execute,
           flags.head_execute,
           flags.anchor_freshness_execute,
           flags.claim_execute,
           flags.ack_execute,
           flags.anchor_health_execute,
           flags.caller_is_superuser,
           flags.caller_owns_ledger,
           flags.direct_ledger_privilege,
           flags.chain_valid
               AND (NOT COALESCE(p_require_append, FALSE)
                    OR (flags.append_execute
                        AND flags.head_execute
                        AND flags.anchor_freshness_execute))
               AND (NOT COALESCE(p_require_exporter, FALSE)
                    OR (flags.claim_execute
                        AND flags.ack_execute
                        AND flags.anchor_health_execute))
               AND (
                   NOT COALESCE(p_require_least_privilege, TRUE)
                   OR (
                       NOT flags.caller_is_superuser
                       AND NOT flags.caller_owns_ledger
                       AND NOT flags.direct_ledger_privilege
                   )
               ) AS policy_satisfied
    FROM flags;
END;
$$;

-- Never expose ledger tables or the SECURITY DEFINER APIs through PUBLIC. A
-- deployment grants only the function set required by each pre-created role.
REVOKE ALL ON TABLE
    public.security_audit_chain_state,
    public.security_audit_events,
    public.security_audit_event_outbox
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    public.nazo_reject_security_audit_event_mutation(),
    public.nazo_security_audit_chain_head_for_update(),
    public.nazo_append_security_audit_event(UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ, BYTEA, BYTEA),
    public.nazo_claim_security_audit_events(BIGINT, INTEGER),
    public.nazo_ack_security_audit_event(UUID, INTEGER),
    public.nazo_reschedule_security_audit_event(UUID, INTEGER, TIMESTAMPTZ, TEXT),
    public.nazo_security_audit_anchor_freshness(),
    public.nazo_security_audit_anchor_health(),
    public.nazo_security_audit_privilege_preflight(BOOLEAN, BOOLEAN, BOOLEAN)
FROM PUBLIC;

COMMENT ON TABLE public.security_audit_chain_state IS
    'Immutable audit chain head; owned by the dedicated migration owner; runtime roles use SECURITY DEFINER APIs.';
COMMENT ON TABLE public.security_audit_events IS
    'Append-only security audit evidence; runtime roles must not receive table privileges.';
COMMENT ON TABLE public.security_audit_event_outbox IS
    'Exporter delivery state; runtime roles use SECURITY DEFINER claim/ack APIs only.';
