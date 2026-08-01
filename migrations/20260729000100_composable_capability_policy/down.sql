ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_security_policy_object;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS security_policy;

DROP TABLE IF EXISTS runtime_module_default_policy;
