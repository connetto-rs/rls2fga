-- The furniture a real schema carries around its policies.
--
-- Every other fixture is a policy pattern on two or three bare tables. A dump of a
-- live database also carries roles, grants, sequences, indexes, views, enums, domains,
-- generated columns, comments, an owner and a composite key, and the translator has to
-- walk past all of it without tripping. Nothing in the corpus exercised that.

CREATE ROLE auditor;

CREATE TABLE users (
    id UUID PRIMARY KEY,
    login TEXT NOT NULL UNIQUE
);

CREATE SEQUENCE docs_seq INCREMENT BY 1 START WITH 1;

CREATE TYPE mood AS ENUM ('calm', 'busy');

CREATE DOMAIN positive AS INT CHECK (VALUE > 0);

CREATE TABLE docs (
    id UUID PRIMARY KEY,
    owner_login TEXT NOT NULL REFERENCES users (login),
    tenant TEXT,
    weight INT,
    doubled INT GENERATED ALWAYS AS (weight * 2) STORED,
    state mood,
    rank positive
);

CREATE INDEX docs_tenant_idx ON docs (tenant);
CREATE UNIQUE INDEX docs_owner_login_uidx ON docs (owner_login);

-- A key over two columns, which leaves no single-column object identifier.
CREATE TABLE doc_links (
    parent_id UUID NOT NULL REFERENCES docs (id),
    child_id UUID NOT NULL REFERENCES docs (id),
    PRIMARY KEY (parent_id, child_id)
);

CREATE VIEW docs_titles AS
    SELECT id, owner_login FROM docs;

COMMENT ON TABLE docs IS 'documents, one row per document';

GRANT SELECT ON docs TO auditor;

ALTER TABLE docs OWNER TO auditor;

-- A function that identifies its caller through a session setting, and one returning the
-- acting role while running as its owner, where the value is the owner's for everybody.
CREATE FUNCTION caller_id() RETURNS UUID LANGUAGE sql STABLE SECURITY INVOKER
    AS 'SELECT current_setting(''app.user_id'')::uuid';

CREATE FUNCTION owner_id() RETURNS UUID LANGUAGE sql STABLE SECURITY DEFINER
    AS 'SELECT current_user::uuid';

CREATE FUNCTION doc_ids() RETURNS SETOF UUID LANGUAGE sql STABLE
    AS 'SELECT id FROM docs';

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_links ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_login = current_setting('app.user_id'));

CREATE POLICY docs_auditor ON docs FOR SELECT TO auditor USING (true);

CREATE POLICY doc_links_visible ON doc_links FOR SELECT
    USING (parent_id IN (SELECT id FROM docs WHERE owner_login = current_setting('app.user_id')));

-- A trigger and its function. Every real schema has these, and no fixture carried one
-- until the normalizer stopped panicking on `RETURNS TRIGGER`.
CREATE FUNCTION touch_docs() RETURNS TRIGGER LANGUAGE plpgsql
    AS 'BEGIN RETURN NEW; END';

CREATE TRIGGER docs_touch BEFORE UPDATE ON docs
    FOR EACH ROW EXECUTE FUNCTION touch_docs();

-- A composite type in a schema, named in full by a function on both sides.
CREATE SCHEMA app;

CREATE TYPE app.doc_ref AS (doc_id UUID, label TEXT);

CREATE FUNCTION describe_doc(ref app.doc_ref) RETURNS app.doc_ref LANGUAGE sql STABLE
    AS 'SELECT ref';

-- A set-returning declaration written as a table, which is a third spelling of a return.
CREATE FUNCTION doc_rows() RETURNS TABLE(id UUID, owner TEXT) LANGUAGE sql STABLE
    AS 'SELECT id, owner_login FROM docs';
