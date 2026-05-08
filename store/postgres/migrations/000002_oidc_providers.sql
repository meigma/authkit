CREATE TABLE IF NOT EXISTS authkit_oidc_providers (
    issuer text PRIMARY KEY CHECK (issuer <> ''),
    jwks_url text NOT NULL CHECK (jwks_url <> ''),
    audiences text[] NOT NULL CHECK (cardinality(audiences) > 0),
    supported_signing_algorithms text[] NOT NULL DEFAULT '{}'::text[],
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO authkit_schema_migrations (version, name)
VALUES (2, '000002_oidc_providers')
ON CONFLICT (version) DO NOTHING;
