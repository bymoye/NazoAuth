ALTER TABLE conformance_leases
    ADD COLUMN public_material JSONB,
    ADD CONSTRAINT ck_conformance_public_material_object CHECK (
        public_material IS NULL OR jsonb_typeof(public_material) = 'object'
    ),
    ADD CONSTRAINT ck_conformance_public_material_size CHECK (
        public_material IS NULL OR octet_length(public_material::text) <= 32768
    );

COMMENT ON COLUMN conformance_leases.public_material IS
    'Public, time-bounded conformance trust only. Cleared on revoke or expiry; private JWK members are rejected before persistence.';
