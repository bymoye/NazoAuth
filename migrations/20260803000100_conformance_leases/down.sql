DROP FUNCTION IF EXISTS nazo_oauth_cleanup_expired_conformance_leases();
DROP FUNCTION IF EXISTS nazo_oauth_conformance_lease_is_active(UUID, UUID);

DROP TRIGGER IF EXISTS trg_oauth_clients_conformance_lease ON oauth_clients;
DROP FUNCTION IF EXISTS nazo_oauth_validate_conformance_lease_binding();

DROP INDEX IF EXISTS ix_oauth_clients_conformance_lease;
ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS fk_oauth_clients_conformance_lease,
    DROP COLUMN IF EXISTS conformance_lease_id;

DROP TABLE IF EXISTS conformance_leases;
