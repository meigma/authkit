CREATE TABLE IF NOT EXISTS authkit_schema_migrations (
    version integer PRIMARY KEY,
    name text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authkit_principals (
    id text PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('user', 'service')),
    display_name text NOT NULL,
    attributes jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authkit_external_identities (
    provider text NOT NULL,
    subject text NOT NULL,
    principal_id text NOT NULL REFERENCES authkit_principals(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject)
);

CREATE INDEX IF NOT EXISTS authkit_external_identities_principal_id_idx
    ON authkit_external_identities (principal_id);

CREATE TABLE IF NOT EXISTS authkit_api_tokens (
    id text PRIMARY KEY,
    principal_id text NOT NULL REFERENCES authkit_principals(id) ON DELETE RESTRICT,
    name text NOT NULL,
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS authkit_api_tokens_principal_id_idx
    ON authkit_api_tokens (principal_id);

INSERT INTO authkit_schema_migrations (version, name)
VALUES (1, '000001_initial')
ON CONFLICT (version) DO NOTHING;
