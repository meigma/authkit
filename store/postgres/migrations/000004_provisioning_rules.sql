ALTER TABLE authkit_oidc_providers
    ADD COLUMN IF NOT EXISTS forwarded_claims jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE TABLE IF NOT EXISTS authkit_provisioning_rules (
    id text PRIMARY KEY CHECK (id <> ''),
    display_name text NOT NULL,
    provider text NOT NULL REFERENCES authkit_oidc_providers(issuer) ON DELETE RESTRICT,
    claim_path jsonb NOT NULL,
    match_values text[] NOT NULL CHECK (cardinality(match_values) > 0),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authkit_provisioning_rule_roles (
    rule_id text NOT NULL REFERENCES authkit_provisioning_rules(id) ON DELETE CASCADE,
    role_id text NOT NULL REFERENCES authkit_roles(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, role_id)
);

CREATE INDEX IF NOT EXISTS authkit_provisioning_rules_provider_idx
    ON authkit_provisioning_rules (provider);

CREATE INDEX IF NOT EXISTS authkit_provisioning_rule_roles_role_id_idx
    ON authkit_provisioning_rule_roles (role_id);

INSERT INTO authkit_schema_migrations (version, name)
VALUES (4, '000004_provisioning_rules')
ON CONFLICT (version) DO NOTHING;
