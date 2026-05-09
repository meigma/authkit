CREATE TABLE IF NOT EXISTS authkit_roles (
    id text PRIMARY KEY CHECK (id <> ''),
    display_name text NOT NULL,
    description text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authkit_role_actions (
    role_id text NOT NULL REFERENCES authkit_roles(id) ON DELETE RESTRICT,
    action text NOT NULL CHECK (action <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, action)
);

CREATE TABLE IF NOT EXISTS authkit_principal_roles (
    principal_id text NOT NULL REFERENCES authkit_principals(id) ON DELETE RESTRICT,
    role_id text NOT NULL REFERENCES authkit_roles(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, role_id)
);

CREATE INDEX IF NOT EXISTS authkit_principal_roles_role_id_idx
    ON authkit_principal_roles (role_id);

INSERT INTO authkit_schema_migrations (version, name)
VALUES (3, '000003_roles')
ON CONFLICT (version) DO NOTHING;
