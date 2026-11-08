-- pg_has_role names PostgreSQL roles rather than anything in a row. A request acts as one
-- of the deployment's roles, so the call is decided by the schema's memberships before any
-- row is read, here the acting role app_user being a member of editor.

CREATE ROLE editor NOLOGIN;
GRANT editor TO app_user;

CREATE TABLE docs (
    id TEXT PRIMARY KEY,
    title TEXT
);

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_select ON docs
    FOR SELECT TO PUBLIC
    USING (pg_has_role(current_user, 'editor', 'MEMBER'));
