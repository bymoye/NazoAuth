ALTER TABLE public.security_audit_chain_state
    ADD COLUMN anchor_deployment_id VARCHAR(255),
    ADD COLUMN anchor_sequence BIGINT,
    ADD COLUMN anchor_hash BYTEA,
    ADD COLUMN anchor_occurred_at TIMESTAMPTZ,
    ADD COLUMN anchor_accepted_at TIMESTAMPTZ,
    ADD COLUMN anchor_observed_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_security_audit_anchor_checkpoint_complete CHECK (
        (anchor_deployment_id IS NULL AND anchor_sequence IS NULL AND anchor_hash IS NULL
         AND anchor_occurred_at IS NULL AND anchor_accepted_at IS NULL)
        OR
        ((anchor_deployment_id IS NULL OR char_length(anchor_deployment_id) BETWEEN 1 AND 255)
         AND anchor_sequence IS NOT NULL AND anchor_sequence >= 0
         AND anchor_hash IS NOT NULL AND octet_length(anchor_hash) = 32
         AND anchor_occurred_at IS NOT NULL AND anchor_accepted_at IS NOT NULL
         AND anchor_accepted_at >= anchor_occurred_at)
    );

-- Preserve the durable checkpoint already represented by exported outbox rows.
-- The first worker observation atomically binds it to the configured deployment.
WITH latest_export AS (
    SELECT events.sequence, events.event_hash, events.occurred_at, outbox.exported_at
    FROM public.security_audit_event_outbox AS outbox
    JOIN public.security_audit_events AS events ON events.event_id = outbox.event_id
    WHERE outbox.exported_at IS NOT NULL
    ORDER BY events.sequence DESC
    LIMIT 1
)
UPDATE public.security_audit_chain_state AS state
SET anchor_sequence = latest_export.sequence,
    anchor_hash = latest_export.event_hash,
    anchor_occurred_at = latest_export.occurred_at,
    anchor_accepted_at = latest_export.exported_at
FROM latest_export
WHERE state.singleton IS TRUE;

CREATE FUNCTION public.nazo_observe_security_audit_anchor(p_deployment_id TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_updated INTEGER;
BEGIN
    IF p_deployment_id IS NULL OR char_length(p_deployment_id) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'audit anchor deployment identity is invalid';
    END IF;
    UPDATE public.security_audit_chain_state
    SET anchor_deployment_id = COALESCE(anchor_deployment_id, p_deployment_id),
        anchor_observed_at = CURRENT_TIMESTAMP
    WHERE singleton IS TRUE
      AND (anchor_deployment_id IS NULL OR anchor_deployment_id = p_deployment_id);
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

CREATE FUNCTION public.nazo_record_security_audit_genesis(p_deployment_id TEXT, p_head_hash BYTEA)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_updated INTEGER;
BEGIN
    IF p_deployment_id IS NULL OR char_length(p_deployment_id) NOT BETWEEN 1 AND 255
       OR p_head_hash IS NULL OR octet_length(p_head_hash) <> 32 THEN
        RAISE EXCEPTION 'audit anchor genesis is invalid';
    END IF;
    UPDATE public.security_audit_chain_state
    SET anchor_deployment_id = p_deployment_id,
        anchor_sequence = 0,
        anchor_hash = p_head_hash,
        anchor_occurred_at = 'epoch'::TIMESTAMPTZ,
        anchor_accepted_at = CURRENT_TIMESTAMP,
        anchor_observed_at = CURRENT_TIMESTAMP
    WHERE singleton IS TRUE AND last_sequence = 0 AND last_hash = p_head_hash
      AND (anchor_deployment_id IS NULL OR anchor_deployment_id = p_deployment_id);
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

CREATE FUNCTION public.nazo_ack_security_audit_event(
    p_event_id UUID, p_expected_attempts INTEGER, p_deployment_id TEXT
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_exported_at TIMESTAMPTZ;
    v_sequence BIGINT;
    v_hash BYTEA;
    v_occurred_at TIMESTAMPTZ;
BEGIN
    IF p_deployment_id IS NULL OR char_length(p_deployment_id) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'audit anchor deployment identity is invalid';
    END IF;
    PERFORM 1 FROM public.security_audit_chain_state AS state
    WHERE state.singleton IS TRUE
      AND (state.anchor_deployment_id IS NULL OR state.anchor_deployment_id = p_deployment_id)
    FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;

    UPDATE public.security_audit_event_outbox AS outbox
    SET exported_at = CURRENT_TIMESTAMP, locked_at = NULL, updated_at = CURRENT_TIMESTAMP
    WHERE outbox.event_id = p_event_id
      AND outbox.attempts = p_expected_attempts
      AND outbox.locked_at IS NOT NULL AND outbox.exported_at IS NULL
    RETURNING outbox.exported_at INTO v_exported_at;
    IF NOT FOUND THEN RETURN FALSE; END IF;

    SELECT events.sequence, events.event_hash, events.occurred_at
    INTO STRICT v_sequence, v_hash, v_occurred_at
    FROM public.security_audit_events AS events WHERE events.event_id = p_event_id;

    UPDATE public.security_audit_chain_state AS state
    SET anchor_deployment_id = p_deployment_id,
        anchor_sequence = CASE WHEN v_sequence > COALESCE(state.anchor_sequence, -1) THEN v_sequence ELSE state.anchor_sequence END,
        anchor_hash = CASE WHEN v_sequence > COALESCE(state.anchor_sequence, -1) THEN v_hash ELSE state.anchor_hash END,
        anchor_occurred_at = CASE WHEN v_sequence > COALESCE(state.anchor_sequence, -1) THEN v_occurred_at ELSE state.anchor_occurred_at END,
        anchor_accepted_at = CASE WHEN v_sequence > COALESCE(state.anchor_sequence, -1) THEN v_exported_at ELSE state.anchor_accepted_at END,
        anchor_observed_at = v_exported_at
    WHERE state.singleton IS TRUE;
    RETURN TRUE;
END;
$$;

CREATE FUNCTION public.nazo_security_audit_shared_anchor_health()
RETURNS TABLE(
    last_sequence BIGINT, last_hash BYTEA, chain_valid BOOLEAN,
    pending_count BIGINT, oldest_pending_occurred_at TIMESTAMPTZ,
    anchor_deployment_id TEXT, anchor_sequence BIGINT, anchor_hash BYTEA,
    anchor_occurred_at TIMESTAMPTZ, anchor_accepted_at TIMESTAMPTZ,
    anchor_observed_at TIMESTAMPTZ
) LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH head AS (
        SELECT events.sequence, events.event_hash FROM public.security_audit_events AS events
        ORDER BY events.sequence DESC LIMIT 1
    ), backlog AS (
        SELECT COUNT(*)::BIGINT AS pending_count, MIN(events.occurred_at) AS oldest_pending_occurred_at
        FROM public.security_audit_event_outbox AS outbox
        JOIN public.security_audit_events AS events ON events.event_id = outbox.event_id
        WHERE outbox.exported_at IS NULL
    )
    SELECT state.last_sequence, state.last_hash,
           state.last_sequence >= 0 AND octet_length(state.last_hash) = 32 AND
           ((head.sequence IS NULL AND state.last_sequence = 0 AND state.last_hash = decode(repeat('00',32),'hex'))
            OR (head.sequence = state.last_sequence AND head.event_hash = state.last_hash)),
           backlog.pending_count, backlog.oldest_pending_occurred_at,
           state.anchor_deployment_id::TEXT, state.anchor_sequence, state.anchor_hash,
           state.anchor_occurred_at, state.anchor_accepted_at, state.anchor_observed_at
    FROM public.security_audit_chain_state AS state
    LEFT JOIN head ON TRUE CROSS JOIN backlog WHERE state.singleton IS TRUE
$$;

CREATE FUNCTION public.nazo_security_audit_shared_privilege_preflight(
    p_require_least_privilege BOOLEAN,
    p_require_append BOOLEAN,
    p_require_exporter BOOLEAN
) RETURNS TABLE(policy_satisfied BOOLEAN)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT base.policy_satisfied
       AND (NOT COALESCE(p_require_append, FALSE) OR (
            has_function_privilege(session_user,
                'public.nazo_security_audit_chain_head_for_update()'::REGPROCEDURE, 'EXECUTE')
            AND has_function_privilege(session_user,
                'public.nazo_append_security_audit_event(uuid,text,text,jsonb,timestamptz,bytea,bytea)'::REGPROCEDURE, 'EXECUTE')
            AND has_function_privilege(session_user,
                'public.nazo_security_audit_shared_anchor_health()'::REGPROCEDURE, 'EXECUTE')
       ))
       AND (NOT COALESCE(p_require_exporter, FALSE) OR (
            has_function_privilege(session_user,
                'public.nazo_claim_security_audit_events(bigint,integer)'::REGPROCEDURE, 'EXECUTE')
            AND has_function_privilege(session_user,
                'public.nazo_ack_security_audit_event(uuid,integer,text)'::REGPROCEDURE, 'EXECUTE')
            AND has_function_privilege(session_user,
                'public.nazo_observe_security_audit_anchor(text)'::REGPROCEDURE, 'EXECUTE')
            AND has_function_privilege(session_user,
                'public.nazo_record_security_audit_genesis(text,bytea)'::REGPROCEDURE, 'EXECUTE')
            AND has_function_privilege(session_user,
                'public.nazo_reschedule_security_audit_event(uuid,integer,timestamptz,text)'::REGPROCEDURE, 'EXECUTE')
            AND has_function_privilege(session_user,
                'public.nazo_security_audit_shared_anchor_health()'::REGPROCEDURE, 'EXECUTE')
       )) AS policy_satisfied
    FROM public.nazo_security_audit_privilege_preflight(
        p_require_least_privilege, FALSE, FALSE
    ) AS base
$$;

REVOKE ALL ON FUNCTION public.nazo_observe_security_audit_anchor(TEXT),
 public.nazo_record_security_audit_genesis(TEXT, BYTEA),
 public.nazo_ack_security_audit_event(UUID, INTEGER, TEXT),
 public.nazo_security_audit_shared_anchor_health(),
 public.nazo_security_audit_shared_privilege_preflight(BOOLEAN, BOOLEAN, BOOLEAN)
FROM PUBLIC;
