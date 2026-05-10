ALTER TABLE authkit_provisioning_rules
    ADD COLUMN IF NOT EXISTS condition text;

UPDATE authkit_provisioning_rules
SET condition = 'hasAny(claims'
    || COALESCE((
        SELECT string_agg('[' || to_jsonb(segment)::text || ']', '' ORDER BY ord)
        FROM jsonb_array_elements_text(claim_path) WITH ORDINALITY AS path(segment, ord)
    ), '')
    || ', ['
    || COALESCE((
        SELECT string_agg(to_jsonb(value)::text, ', ' ORDER BY ord)
        FROM unnest(match_values) WITH ORDINALITY AS vals(value, ord)
    ), '')
    || '])'
WHERE condition IS NULL;

ALTER TABLE authkit_provisioning_rules
    ALTER COLUMN condition SET NOT NULL,
    ALTER COLUMN claim_path DROP NOT NULL,
    ALTER COLUMN match_values DROP NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'authkit_provisioning_rules_condition_not_empty'
    ) THEN
        ALTER TABLE authkit_provisioning_rules
            ADD CONSTRAINT authkit_provisioning_rules_condition_not_empty CHECK (condition <> '');
    END IF;
END $$;

INSERT INTO authkit_schema_migrations (version, name)
VALUES (5, '000005_cel_provisioning_conditions')
ON CONFLICT (version) DO NOTHING;
