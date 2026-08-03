ALTER TABLE conformance_leases
    DROP CONSTRAINT IF EXISTS ck_conformance_public_material_size,
    DROP CONSTRAINT IF EXISTS ck_conformance_public_material_object,
    DROP COLUMN IF EXISTS public_material;
