# Security audit ledger roles

The `20260805000100_security_audit_ledger` migration does not create or drop
cluster-global roles. A database administrator must provision separate roles
and run the migration as a dedicated, non-superuser migration owner. Runtime
roles are granted `EXECUTE` on narrowly scoped `SECURITY DEFINER` functions;
they are never granted table privileges.

## Provisioning boundary

Use deployment-specific role names. The following names are illustrative only:

```sql
CREATE ROLE nazoauth_migration_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
CREATE ROLE nazoauth_audit_writer LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
CREATE ROLE nazoauth_audit_exporter LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
```

The migration URL must execute the migration as `nazoauth_migration_owner` (or
as a short-lived migration runner that can `SET ROLE` to it). Do not use the
long-running application role as the owner. The owner must remain the owner of
the three ledger tables, their indexes/triggers, and all functions below; only
the owner can alter or disable the append-only trigger.

Before granting runtime access, remove the default schema creation path and
the table privileges inherited by application roles:

```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON TABLE
    public.security_audit_chain_state,
    public.security_audit_events,
    public.security_audit_event_outbox
FROM nazoauth_audit_writer, nazoauth_audit_exporter;
GRANT USAGE ON SCHEMA public TO nazoauth_audit_writer, nazoauth_audit_exporter;
```

The migration itself also revokes table and function privileges from `PUBLIC`.
The explicit role revocation above is still required when a deployment role
inherits privileges from another application role. `has_table_privilege` in
the strict preflight reports effective privileges, not just direct grants.

## Function grants

Grant only the capability required by each process. The writer can append and
observe a fresh chain head; it cannot claim or acknowledge exporter rows:

```sql
GRANT EXECUTE ON FUNCTION
    public.nazo_security_audit_privilege_preflight(boolean, boolean, boolean),
    public.nazo_security_audit_chain_head_for_update(),
    public.nazo_append_security_audit_event(
        uuid, text, text, jsonb, timestamptz, bytea, bytea
    ),
    public.nazo_security_audit_anchor_freshness()
TO nazoauth_audit_writer;
```

The exporter can claim and acknowledge outbox rows and refresh the checkpoint
without receiving append or chain-head-lock access:

```sql
GRANT EXECUTE ON FUNCTION
    public.nazo_security_audit_privilege_preflight(boolean, boolean, boolean),
    public.nazo_claim_security_audit_events(bigint, integer),
    public.nazo_ack_security_audit_event(uuid, integer),
    public.nazo_reschedule_security_audit_event(uuid, integer, timestamptz, text),
    public.nazo_security_audit_anchor_health()
TO nazoauth_audit_exporter;
```

If one process intentionally performs both jobs, grant both function sets to
one pre-created role and record that exception in the deployment inventory.
Never grant `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, or
`TRIGGER` on any of the three tables to that combined role. Runtime login roles
must not be members of the migration owner, a superuser role, or any role that
can acquire those privileges through `SET ROLE`.

## Fail-closed preflight

The repository calls the policy-driven preflight as the runtime role. A writer
uses `(require_least_privilege, require_append, require_exporter) =
 (true, true, false)`; an exporter uses `(true, false, true)`. Strict mode
requires a valid chain, the requested function `EXECUTE` grants, and all of
the following to be false for `session_user` or any role it can assume:
superuser, ledger table owner, or any effective ledger table privilege.
Therefore a writer cannot rewrite or
truncate the ledger and an exporter cannot bypass the claim/ack state machine.

The authorization-server setting `SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE`
should remain enabled in production. A test fixture may explicitly pass
`false` to the repository policy method, but non-strict mode still requires the
function API and a valid chain. A failed preflight is a startup/high-impact
operation failure; do not silently fall back to direct table writes.

Verify each role after grants, using the same connection identity as the
process:

```sql
SELECT *
FROM public.nazo_security_audit_privilege_preflight(true, true, false);
-- writer: policy_satisfied = true; claim_execute/ack_execute = false

SELECT *
FROM public.nazo_security_audit_privilege_preflight(true, false, true);
-- exporter: policy_satisfied = true; append_execute/head_execute = false
```

Run these checks after every role or grant change and after restoring a backup.
The migration owner and any superuser deliberately fail strict preflight and
must never be used as a long-running application or exporter identity.
