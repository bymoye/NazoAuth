DROP TRIGGER trg_tenant_resource_operations_append_only
ON tenant_resource_operations;
DROP FUNCTION nazo_tenant_resource_operations_append_only();
DROP TABLE tenant_resource_operations;

CREATE TABLE tenant_resource_control_operations (
    operation_id UUID PRIMARY KEY,
    request_hash VARCHAR(64) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    operation VARCHAR(32) NOT NULL,
    outcome JSONB NOT NULL,
    CONSTRAINT ck_tenant_resource_control_request_hash CHECK (
        request_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_tenant_resource_control_operation CHECK (
        operation IN ('apply', 'enumerate', 'revoke')
    ),
    CONSTRAINT ck_tenant_resource_control_outcome CHECK (
        jsonb_typeof(outcome) = 'object'
        AND octet_length(convert_to(outcome::text, 'UTF8')) <= 1048576
    )
);

CREATE FUNCTION nazo_tenant_resource_control_operations_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'tenant resource control outcomes are append-only'
        USING ERRCODE = '55006';
END;
$$;

CREATE TRIGGER trg_tenant_resource_control_operations_append_only
BEFORE UPDATE OR DELETE ON tenant_resource_control_operations
FOR EACH ROW
EXECUTE FUNCTION nazo_tenant_resource_control_operations_append_only();
