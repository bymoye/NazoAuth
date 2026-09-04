DROP FUNCTION IF EXISTS public.nazo_security_audit_shared_privilege_preflight(BOOLEAN, BOOLEAN, BOOLEAN);
DROP FUNCTION IF EXISTS public.nazo_security_audit_shared_anchor_health();
DROP FUNCTION IF EXISTS public.nazo_ack_security_audit_event(UUID, INTEGER, TEXT);
DROP FUNCTION IF EXISTS public.nazo_record_security_audit_genesis(TEXT, BYTEA);
DROP FUNCTION IF EXISTS public.nazo_observe_security_audit_anchor(TEXT);
ALTER TABLE public.security_audit_chain_state
    DROP CONSTRAINT IF EXISTS ck_security_audit_anchor_checkpoint_complete,
    DROP COLUMN IF EXISTS anchor_observed_at,
    DROP COLUMN IF EXISTS anchor_accepted_at,
    DROP COLUMN IF EXISTS anchor_occurred_at,
    DROP COLUMN IF EXISTS anchor_hash,
    DROP COLUMN IF EXISTS anchor_sequence,
    DROP COLUMN IF EXISTS anchor_deployment_id;
