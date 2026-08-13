DROP TRIGGER IF EXISTS security_audit_events_append_only ON public.security_audit_events;
DROP TRIGGER IF EXISTS security_audit_events_no_truncate ON public.security_audit_events;

DROP FUNCTION IF EXISTS public.nazo_security_audit_privilege_preflight(BOOLEAN, BOOLEAN, BOOLEAN);
DROP FUNCTION IF EXISTS public.nazo_security_audit_anchor_health();
DROP FUNCTION IF EXISTS public.nazo_security_audit_anchor_freshness();
DROP FUNCTION IF EXISTS public.nazo_reschedule_security_audit_event(UUID, INTEGER, TIMESTAMPTZ, TEXT);
DROP FUNCTION IF EXISTS public.nazo_ack_security_audit_event(UUID, INTEGER);
DROP FUNCTION IF EXISTS public.nazo_claim_security_audit_events(BIGINT, INTEGER);
DROP FUNCTION IF EXISTS public.nazo_append_security_audit_event(
    UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ, BYTEA, BYTEA
);
DROP FUNCTION IF EXISTS public.nazo_security_audit_chain_head_for_update();
DROP FUNCTION IF EXISTS public.nazo_reject_security_audit_event_mutation();

DROP TABLE IF EXISTS public.security_audit_event_outbox;
DROP TABLE IF EXISTS public.security_audit_events;
DROP TABLE IF EXISTS public.security_audit_chain_state;
